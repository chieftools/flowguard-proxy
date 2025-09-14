package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"flowguard/cache"
)

// Config represents the complete application configuration
type Config struct {
	Host           *HostConfig            `json:"host"`
	Rules          map[string]*Rule       `json:"rules"`
	Actions        map[string]*RuleAction `json:"actions"`
	Logging        *LoggingConfig         `json:"logging"`
	IPDatabase     *IPDatabaseConfig      `json:"ip_database"`
	TrustedProxies *TrustedProxiesConfig  `json:"trusted_proxies"`
	CacheDir       string                 `json:"cache_dir,omitempty"`
	CertPath       string                 `json:"cert_path,omitempty"`
}

type HostConfig struct {
	ID              string `json:"id,omitempty"`
	Key             string `json:"key,omitempty"`
	Name            string `json:"name"`
	Team            string `json:"team,omitempty"`
	DefaultHostname string `json:"default_hostname,omitempty"`
}

type LoggingConfig struct {
	FilePath     string `json:"file_path,omitempty"`
	AxiomToken   string `json:"axiom_token,omitempty"`
	AxiomDataset string `json:"axiom_dataset,omitempty"`
}

type IPDatabaseConfig struct {
	URL                    string `json:"url"`
	RefreshIntervalSeconds int    `json:"refresh_interval_seconds"`
}

type TrustedProxiesConfig struct {
	IPNets                 []string `json:"ipnets"`
	RefreshIntervalSeconds int      `json:"refresh_interval_seconds"`
}

type Rule struct {
	ID         string          // Rule ID from the map key
	Action     string          `json:"action"`
	Conditions *RuleConditions `json:"conditions"`
}

type RuleAction struct {
	Action  string `json:"action"`  // "block"
	Status  int    `json:"status"`  // HTTP status code
	Message string `json:"message"` // Response message
}

type RuleConditions struct {
	Operator string           `json:"operator,omitempty"` // AND, OR, NOT
	Groups   []RuleConditions `json:"groups,omitempty"`
	Matches  []MatchCondition `json:"matches,omitempty"`
	Comment  string           `json:"comment,omitempty"`
}

type MatchCondition struct {
	Type            string   `json:"type"`  // path, domain, ip, agent, header, asn, ipset
	Match           string   `json:"match"` // equals, contains, regex, in, not-in, etc.
	Value           string   `json:"value,omitempty"`
	Values          []string `json:"values,omitempty"`
	CaseInsensitive bool     `json:"case_insensitive,omitempty"`
	Family          int      `json:"family,omitempty"`    // For ipset matches (4 or 6)
	RawMatch        bool     `json:"raw_match,omitempty"` // Skip normalization for path matching
	compiledRegex   *regexp.Regexp
}

// Manager manages the configuration with hot-reload support
type Manager struct {
	configPath      string
	config          *Config
	trustedProxyIPs []net.IPNet
	lastModified    time.Time
	stopWatcher     chan struct{}
	callbacks       []func(*Config)
	cache           *cache.Cache
	mu              sync.RWMutex
}

// NewManager creates a new configuration manager
func NewManager(configPath string, userAgent string, cacheDir string) (*Manager, error) {
	// Create cache if cache directory is provided
	var c *cache.Cache
	if cacheDir != "" {
		var err error
		c, err = cache.NewCache(cacheDir, userAgent)
		if err != nil {
			log.Printf("[config] Failed to create cache: %v", err)
			os.Exit(1)
		}
	}

	m := &Manager{
		cache:       c,
		configPath:  configPath,
		stopWatcher: make(chan struct{}),
	}

	// Load initial configuration
	if err := m.Load(); err != nil {
		return nil, err
	}

	return m, nil
}

// Load loads or reloads the configuration from disk
func (m *Manager) Load() error {
	// Check file info
	info, err := os.Stat(m.configPath)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %w", err)
	}

	// Read file
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config JSON: %w", err)
	}

	// Parse trusted proxy IPs and fetch from URLs
	var trustedProxyIPs []net.IPNet
	if config.TrustedProxies != nil {
		trustedProxyIPs, err = m.parseTrustedProxies(config.TrustedProxies.IPNets)
		if err != nil {
			return fmt.Errorf("failed to parse trusted proxies: %w", err)
		}
	}

	// Update configuration atomically
	m.mu.Lock()
	oldConfig := m.config
	m.config = &config
	m.trustedProxyIPs = trustedProxyIPs
	m.lastModified = info.ModTime()
	m.mu.Unlock()

	// Notify all change listeners if config changed
	if oldConfig != nil {
		m.mu.RLock()
		callbacks := make([]func(*Config), len(m.callbacks))
		copy(callbacks, m.callbacks)
		m.mu.RUnlock()

		for _, callback := range callbacks {
			if callback != nil {
				callback(&config)
			}
		}
	}

	// Set rule IDs from map keys and compile regex patterns
	if config.Rules != nil {
		for id, rule := range config.Rules {
			rule.ID = id
			// Compile regex patterns in conditions
			if rule.Conditions != nil {
				m.compileConditionRegex(rule.Conditions)
			}
		}
	}

	log.Printf("[config] Loaded configuration from %s (rules: %d, actions: %d, trusted proxies: %d networks)",
		m.configPath, len(config.Rules), len(config.Actions), len(trustedProxyIPs))

	return nil
}

// parseTrustedProxies parses trusted proxy configuration
func (m *Manager) parseTrustedProxies(proxies []string) ([]net.IPNet, error) {
	var result []net.IPNet
	seenNetworks := make(map[string]bool)

	for _, proxy := range proxies {
		if strings.HasPrefix(proxy, "http://") || strings.HasPrefix(proxy, "https://") {
			// Fetch IP ranges from URL
			ranges, err := m.fetchIPRangesFromURL(proxy)
			if err != nil {
				log.Printf("[config] Failed to fetch trusted proxies from %s: %v", proxy, err)
				continue
			}
			for _, r := range ranges {
				key := r.String()
				if !seenNetworks[key] {
					result = append(result, r)
					seenNetworks[key] = true
				}
			}
		} else {
			// Parse as IP or CIDR
			var ipNet net.IPNet
			if strings.Contains(proxy, "/") {
				// Parse as CIDR
				_, network, err := net.ParseCIDR(proxy)
				if err != nil {
					return nil, fmt.Errorf("invalid CIDR %s: %w", proxy, err)
				}
				ipNet = *network
			} else {
				// Parse as single IP
				ip := net.ParseIP(proxy)
				if ip == nil {
					return nil, fmt.Errorf("invalid IP address: %s", proxy)
				}
				// Create a /32 or /128 network for single IP
				if ip.To4() != nil {
					ipNet = net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				} else {
					ipNet = net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				}
			}

			key := ipNet.String()
			if !seenNetworks[key] {
				result = append(result, ipNet)
				seenNetworks[key] = true
			}
		}
	}

	return result, nil
}

// fetchIPRangesFromURL fetches IP ranges from a URL with caching
func (m *Manager) fetchIPRangesFromURL(url string) ([]net.IPNet, error) {
	var data []byte
	var err error

	// Get cache TTL from config
	cacheTTL := 24 * time.Hour // default
	m.mu.RLock()
	if m.config != nil && m.config.TrustedProxies != nil && m.config.TrustedProxies.RefreshIntervalSeconds > 0 {
		cacheTTL = time.Duration(m.config.TrustedProxies.RefreshIntervalSeconds) * time.Second
	}
	m.mu.RUnlock()

	// Use cache if available
	data, err = m.cache.FetchWithCache(url, cacheTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", url, err)
	}

	// Parse the data (one CIDR per line)
	return m.parseIPRanges(data, url)
}

// parseIPRanges parses IP ranges from raw data
func (m *Manager) parseIPRanges(data []byte, source string) ([]net.IPNet, error) {
	var result []net.IPNet
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		_, network, err := net.ParseCIDR(line)
		if err != nil {
			log.Printf("[config] Invalid CIDR from %s: %s", source, line)
			continue
		}
		result = append(result, *network)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// GetConfig returns a copy of the current configuration
func (m *Manager) GetConfig() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// GetRules returns the current rules configuration
func (m *Manager) GetRules() map[string]*Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.config == nil {
		return nil
	}
	return m.config.Rules
}

// GetActions returns the current actions configuration
func (m *Manager) GetActions() map[string]*RuleAction {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.config == nil {
		return nil
	}
	return m.config.Actions
}

// GetRefreshInterval returns the configured refresh interval for trusted proxies
func (m *Manager) GetRefreshInterval() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.config == nil || m.config.TrustedProxies == nil || m.config.TrustedProxies.RefreshIntervalSeconds <= 0 {
		return 30 * time.Minute // default
	}

	return time.Duration(m.config.TrustedProxies.RefreshIntervalSeconds) * time.Second
}

// IsTrustedProxy checks if an IP is from a trusted proxy
func (m *Manager) IsTrustedProxy(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, network := range m.trustedProxyIPs {
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// OnChange adds a callback to be called when configuration changes
func (m *Manager) OnChange(callback func(*Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = append(m.callbacks, callback)
}

// RemoveOnChange removes a specific callback (by comparing function pointers)
// Note: This is not commonly needed but provided for completeness
func (m *Manager) RemoveOnChange(callback func(*Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, cb := range m.callbacks {
		// This comparison works for function pointers but may not be reliable
		// in all cases. A better approach would be to return an ID from OnChange.
		if &cb == &callback {
			// Remove callback by replacing with last element and truncating
			m.callbacks[i] = m.callbacks[len(m.callbacks)-1]
			m.callbacks = m.callbacks[:len(m.callbacks)-1]
			break
		}
	}
}

// StartWatcher starts watching the configuration file for changes
func (m *Manager) StartWatcher(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.checkAndReload()
			case <-m.stopWatcher:
				return
			}
		}
	}()
}

// checkAndReload checks if the config file has changed and reloads if necessary
func (m *Manager) checkAndReload() {
	info, err := os.Stat(m.configPath)
	if err != nil {
		log.Printf("[config] Failed to stat config file: %v", err)
		return
	}

	m.mu.RLock()
	lastMod := m.lastModified
	m.mu.RUnlock()

	if info.ModTime().After(lastMod) {
		log.Printf("[config] Configuration file changed, reloading...")
		if err := m.Load(); err != nil {
			log.Printf("[config] Failed to reload configuration: %v", err)
		} else {
			log.Printf("[config] Configuration reloaded successfully")
		}
	}
}

// StopWatcher stops the configuration file watcher
func (m *Manager) StopWatcher() {
	close(m.stopWatcher)
}

// RefreshTrustedProxies refreshes trusted proxy lists from URLs
func (m *Manager) RefreshTrustedProxies() error {
	m.mu.RLock()
	config := m.config
	m.mu.RUnlock()

	if config == nil || config.TrustedProxies == nil {
		return nil
	}

	// Get cache TTL from config
	cacheTTL := 24 * time.Hour // default
	if config.TrustedProxies.RefreshIntervalSeconds > 0 {
		cacheTTL = time.Duration(config.TrustedProxies.RefreshIntervalSeconds) * time.Second
	}

	// Force cache refresh by clearing old entries for URLs
	for _, proxy := range config.TrustedProxies.IPNets {
		if strings.HasPrefix(proxy, "http://") || strings.HasPrefix(proxy, "https://") {
			// Clear stale cache entries older than the configured TTL
			if _, timestamp, err := m.cache.LoadFromCache(proxy); err == nil {
				if time.Since(timestamp) > cacheTTL {
					m.cache.ClearCacheEntry(proxy)
					log.Printf("[config] Cleared stale cache entry for %s", proxy)
				} else {
					log.Printf("[config] Cache still fresh for %s (age: %v, TTL: %v)",
						proxy, time.Since(timestamp), cacheTTL)
				}
			}
		}
	}

	trustedProxyIPs, err := m.parseTrustedProxies(config.TrustedProxies.IPNets)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.trustedProxyIPs = trustedProxyIPs
	m.mu.Unlock()

	log.Printf("[config] Refreshed trusted proxy lists (%d networks)", len(trustedProxyIPs))
	return nil
}

// GetIPDatabaseRefreshInterval returns the configured refresh interval for the IP database
func (m *Manager) GetIPDatabaseRefreshInterval() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.config != nil && m.config.IPDatabase != nil && m.config.IPDatabase.RefreshIntervalSeconds > 0 {
		return time.Duration(m.config.IPDatabase.RefreshIntervalSeconds) * time.Second
	}

	// Default to 24 hours if not configured
	return 24 * time.Hour
}

// compileConditionRegex recursively compiles regex patterns in conditions
func (m *Manager) compileConditionRegex(cond *RuleConditions) {
	// Compile regex in matches
	for i := range cond.Matches {
		if cond.Matches[i].Match == "regex" {
			pattern := cond.Matches[i].Value
			if cond.Matches[i].CaseInsensitive {
				pattern = "(?i)" + pattern
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				log.Printf("[config] Warning: Invalid regex pattern '%s': %v", cond.Matches[i].Value, err)
			} else {
				cond.Matches[i].compiledRegex = re
			}
		}
	}

	// Recursively compile in groups
	for i := range cond.Groups {
		m.compileConditionRegex(&cond.Groups[i])
	}
}

// GetCompiledRegex returns the compiled regex for a MatchCondition
func (m *MatchCondition) GetCompiledRegex() *regexp.Regexp {
	return m.compiledRegex
}

// SetCompiledRegexInternal sets the compiled regex (for testing)
func (m *MatchCondition) SetCompiledRegexInternal(re *regexp.Regexp) {
	m.compiledRegex = re
}

// GetIPDatabasePath downloads the IP database if configured and returns the local path
func (m *Manager) GetIPDatabasePath() (string, error) {
	m.mu.RLock()
	var dbURL string
	var refreshInterval time.Duration
	if m.config != nil && m.config.IPDatabase != nil {
		dbURL = m.config.IPDatabase.URL
		if m.config.IPDatabase.RefreshIntervalSeconds > 0 {
			refreshInterval = time.Duration(m.config.IPDatabase.RefreshIntervalSeconds) * time.Second
		}
	}
	m.mu.RUnlock()

	if dbURL == "" {
		// No database URL configured, use local file if exists
		if _, err := os.Stat("ipinfo_lite.mmdb"); err == nil {
			return "ipinfo_lite.mmdb", nil
		}
		return "", fmt.Errorf("no IP database configured or found")
	}

	// Use cache to download and store the database file
	if m.cache == nil {
		return "", fmt.Errorf("cache not initialized")
	}

	// Use configured TTL or default to 24 hours
	cacheTTL := 24 * time.Hour
	if refreshInterval > 0 {
		cacheTTL = refreshInterval
	}

	// Download/retrieve from cache
	cachedPath, err := m.cache.FetchFileWithCache(dbURL, cacheTTL)
	if err != nil {
		// Fallback to local file if download fails
		if _, err := os.Stat("ipinfo_lite.mmdb"); err == nil {
			log.Printf("[config] Failed to download IP database, using local file: %v", err)
			return "ipinfo_lite.mmdb", nil
		}
		return "", fmt.Errorf("failed to download IP database: %w", err)
	}

	return cachedPath, nil
}
