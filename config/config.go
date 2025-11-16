package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"flowguard/api"
	"flowguard/cache"
	"flowguard/pusher"

	"github.com/fsnotify/fsnotify"
)

// Config represents the complete application configuration
type Config struct {
	ID             string                 `json:"id,omitempty"`
	Host           *HostConfig            `json:"host"`
	Rules          map[string]*Rule       `json:"rules"`
	Actions        map[string]*RuleAction `json:"actions"`
	Logging        *LoggingConfig         `json:"logging"`
	IPDatabase     *IPDatabaseConfig      `json:"ip_database"`
	TrustedProxies *TrustedProxiesConfig  `json:"trusted_proxies"`
	IPLists        *IPListsConfig         `json:"ip_lists,omitempty"`
	Realtime       *pusher.Config         `json:"realtime,omitempty"`
	CacheDir       string                 `json:"cache_dir,omitempty"`
}

type HostConfig struct {
	ID              string `json:"id,omitempty"`
	Key             string `json:"key,omitempty"`
	Name            string `json:"name"`
	Team            string `json:"team,omitempty"`
	CertPath        string `json:"cert_path,omitempty"`
	NginxConfigPath string `json:"nginx_config_path,omitempty"`
	DefaultHostname string `json:"default_hostname,omitempty"`
}

type LoggingConfig struct {
	FilePath        string   `json:"file_path,omitempty"`
	AxiomToken      string   `json:"axiom_token,omitempty"`
	AxiomDataset    string   `json:"axiom_dataset,omitempty"`
	HeaderWhitelist []string `json:"header_whitelist,omitempty"`
}

type IPDatabaseConfig struct {
	URL                    string `json:"url"`
	RefreshIntervalSeconds int    `json:"refresh_interval_seconds"`
}

type TrustedProxiesConfig struct {
	IPNets                 []string `json:"ipnets"`
	RefreshIntervalSeconds int      `json:"refresh_interval_seconds"`
}

type IPListsConfig map[string]*IPListConfig

type IPListConfig struct {
	URL                    string `json:"url,omitempty"`
	Path                   string `json:"path,omitempty"`
	RefreshIntervalSeconds int    `json:"refresh_interval_seconds,omitempty"`
}

type Rule struct {
	ID         string          // Rule ID from the map key
	Name       string          `json:"name"`
	Action     string          `json:"action"`
	SortOrder  int             `json:"sort_order,omitempty"` // Optional: explicit ordering (lower = processed first)
	Conditions *RuleConditions `json:"conditions"`
}

type RuleAction struct {
	ID                string // Action ID from the map key
	Name              string `json:"name"`
	Action            string `json:"action"`                        // "block" or "rate_limit"
	Status            int    `json:"status,omitempty"`              // HTTP status code (for block actions)
	Message           string `json:"message,omitempty"`             // Response message (for block actions)
	WindowSeconds     int    `json:"window_seconds,omitempty"`      // Time window in seconds (for rate_limit actions)
	RequestsPerWindow int    `json:"requests_per_window,omitempty"` // Max requests in time window (for rate_limit actions)
}

type RuleConditions struct {
	Operator string           `json:"operator,omitempty"` // AND, OR, NOT
	Groups   []RuleConditions `json:"groups,omitempty"`
	Matches  []MatchCondition `json:"matches,omitempty"`
	Comment  string           `json:"comment,omitempty"`
}

type MatchCondition struct {
	Type            string   `json:"type"`          // path, domain, ip, agent, header, asn, ipset, iplist
	Match           string   `json:"match"`         // equals, contains, regex, in, not-in, etc.
	Key             string   `json:"key,omitempty"` // For header matches: the header name
	Value           string   `json:"value,omitempty"`
	Values          []string `json:"values,omitempty"`
	CaseInsensitive bool     `json:"case_insensitive,omitempty"`
	Family          uint     `json:"family,omitempty"`    // For ipset matches (4 or 6)
	RawMatch        bool     `json:"raw_match,omitempty"` // Skip normalization for path matching
	compiledRegex   *regexp.Regexp
}

// Manager manages the configuration with hot-reload support
type Manager struct {
	configPath      string
	userAgent       string
	version         string
	verbose         bool
	config          *Config
	sortedRules     []*Rule // Pre-sorted rules for efficient iteration
	cache           *cache.Cache
	lastModified    time.Time
	currentConfigID string
	apiClient       *api.Client
	realtimeClient  *pusher.Client
	trustedProxyIPs []net.IPNet
	callbacks       []func(*Config)
	watcher         *fsnotify.Watcher
	stopWatcher     chan struct{}
	stopAPIRefresh  chan struct{}
	mu              sync.RWMutex
}

// NewManager creates a new configuration manager
func NewManager(configPath string, userAgent string, version string, cacheDir string, verbose bool) (*Manager, error) {
	// Create cache if cache directory is provided
	var c *cache.Cache
	if cacheDir != "" {
		var err error
		c, err = cache.NewCache(cacheDir, userAgent, verbose)
		if err != nil {
			log.Printf("[config] Failed to create cache: %v", err)
			os.Exit(1)
		}
	}

	// Create fsnotify watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("[config] Warning: Failed to create file watcher: %v. Configuration updates will not be automatic.", err)
	}

	m := &Manager{
		cache:          c,
		version:        version,
		verbose:        verbose,
		watcher:        watcher,
		userAgent:      userAgent,
		configPath:     configPath,
		stopWatcher:    make(chan struct{}),
		stopAPIRefresh: make(chan struct{}),
		apiClient:      api.NewClient("", userAgent),
		callbacks:      make([]func(*Config), 0),
	}

	// Load initial configuration
	if err := m.Load(); err != nil {
		return nil, err
	}

	// Setup file watcher if available
	if watcher != nil {
		// Watch the directory containing the config file for changes
		configDir := filepath.Dir(configPath)
		err = watcher.Add(configDir)
		if err != nil {
			log.Printf("[config] Warning: Failed to watch configuration directory %s: %v", configDir, err)
			watcher.Close()
			m.watcher = nil
		} else if verbose {
			log.Printf("[config] Watching configuration directory %s for changes", configDir)
		}
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

	if config.Rules != nil {
		for id, rule := range config.Rules {
			rule.ID = id

			if rule.Conditions != nil {
				m.compileConditionRegex(rule.Conditions)
			}
		}
	}

	if config.Actions != nil {
		for id, action := range config.Actions {
			action.ID = id
		}
	}

	// Pre-compute sorted rules for efficient iteration during request processing
	sortedRules := m.computeSortedRules(config.Rules)

	// Update configuration atomically
	m.mu.Lock()

	oldConfig := m.config
	m.config = &config
	m.sortedRules = sortedRules
	m.trustedProxyIPs = trustedProxyIPs
	m.lastModified = info.ModTime()
	m.currentConfigID = config.ID

	// Update API client with host key if available
	if config.Host != nil && config.Host.Key != "" {
		m.apiClient.SetHostKey(config.Host.Key)
	}

	// Update cache with API credentials
	if m.cache != nil && config.Host != nil && config.Host.Key != "" {
		apiBase := m.apiClient.GetBaseURL()
		m.cache.SetAPICredentials(apiBase, config.Host.Key)
	}

	m.mu.Unlock()

	// Update Realtime client configuration
	m.updatePusherClient(&config)

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

	log.Printf("[config] Loaded configuration from %s (rules: %d, actions: %d, trusted proxies: %d networks)", m.configPath, len(config.Rules), len(config.Actions), len(trustedProxyIPs))

	return nil
}

// GetConfig returns a copy of the current configuration
func (m *Manager) GetConfig() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// GetCache returns the HTTP cache instance
func (m *Manager) GetCache() *cache.Cache {
	return m.cache
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

// GetSortedRules returns the pre-sorted rules for efficient iteration
func (m *Manager) GetSortedRules() []*Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sortedRules
}

// computeSortedRules sorts rules by sort_order (if specified), then by ID
func (m *Manager) computeSortedRules(rules map[string]*Rule) []*Rule {
	if rules == nil || len(rules) == 0 {
		return nil
	}

	// Convert map to slice
	ruleList := make([]*Rule, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}

	// Sort by sort_order (primary), then by ID (secondary)
	sort.Slice(ruleList, func(i, j int) bool {
		// If both rules have sort_order, compare by sort_order
		if ruleList[i].SortOrder != 0 || ruleList[j].SortOrder != 0 {
			if ruleList[i].SortOrder != ruleList[j].SortOrder {
				return ruleList[i].SortOrder < ruleList[j].SortOrder
			}
		}
		// Fall back to ID comparison for deterministic ordering
		return ruleList[i].ID < ruleList[j].ID
	})

	return ruleList
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

// GetVersion returns the application version
func (m *Manager) GetVersion() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version
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

// StartWatcher starts watching the configuration file for changes using fsnotify
func (m *Manager) StartWatcher() {
	if m.watcher == nil {
		// Fall back to polling if fsnotify is not available
		log.Printf("[config] fsnotify not available, falling back to polling every 10 seconds")
		go func() {
			ticker := time.NewTicker(10 * time.Second)
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
		return
	}

	go m.watchConfigFile()
}

// watchConfigFile implements the fsnotify-based file watching with debouncing
func (m *Manager) watchConfigFile() {
	if m.watcher == nil {
		return
	}

	debounce := time.NewTimer(0)
	<-debounce.C // Drain the initial timer
	var pendingReload bool

	configFileName := filepath.Base(m.configPath)

	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			// Check if event is for our config file
			eventFileName := filepath.Base(event.Name)
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0 && eventFileName == configFileName {
				// Ignore temporary files
				if strings.HasPrefix(eventFileName, ".") || strings.HasSuffix(eventFileName, "~") || strings.HasSuffix(eventFileName, ".tmp") {
					continue
				}

				if m.verbose {
					log.Printf("[config] Detected change in configuration file: %s (%v)", configFileName, event.Op)
				}

				// Use debouncing to avoid multiple reloads for rapid changes
				if !pendingReload {
					pendingReload = true
					debounce.Reset(100 * time.Millisecond)
				}
			}

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[config] File watcher error: %v", err)

		case <-debounce.C:
			if pendingReload {
				pendingReload = false
				m.checkAndReload()
			}

		case <-m.stopWatcher:
			return
		}
	}
}

// checkAndReload checks if the config file has changed and reloads if necessary
func (m *Manager) checkAndReload() {
	shouldReload, reason := m.shouldReloadConfig()
	if shouldReload {
		log.Printf("[config] Configuration %s, reloading...", reason)
		if err := m.Load(); err != nil {
			log.Printf("[config] Failed to reload configuration: %v", err)
		} else {
			log.Printf("[config] Configuration reloaded successfully")
		}
	}
}

// shouldReloadConfig determines if the configuration should be reloaded
// Returns true and reason if reload is needed, false otherwise
func (m *Manager) shouldReloadConfig() (bool, string) {
	// First check if file exists and get info
	info, err := os.Stat(m.configPath)
	if err != nil {
		log.Printf("[config] Failed to stat config file: %v", err)
		return false, ""
	}

	// Read the file to check for ID changes
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		log.Printf("[config] Failed to read config file for ID check: %v", err)
		// Fall back to modification time check
		m.mu.RLock()
		lastMod := m.lastModified
		m.mu.RUnlock()

		if info.ModTime().After(lastMod) {
			return true, "file modification time changed"
		}
		return false, ""
	}

	// Parse just enough to get the ID
	var tempConfig struct {
		ID string `json:"id,omitempty"`
	}
	if err := json.Unmarshal(data, &tempConfig); err != nil {
		log.Printf("[config] Failed to parse config for ID check: %v", err)
		// Fall back to modification time check
		m.mu.RLock()
		lastMod := m.lastModified
		m.mu.RUnlock()

		if info.ModTime().After(lastMod) {
			return true, "file modification time changed (JSON parse failed)"
		}
		return false, ""
	}

	m.mu.RLock()
	currentID := m.currentConfigID
	lastMod := m.lastModified
	m.mu.RUnlock()

	// If we have an ID in the new config, use ID comparison
	if tempConfig.ID != "" {
		if tempConfig.ID != currentID {
			return true, fmt.Sprintf("ID changed from '%s' to '%s'", currentID, tempConfig.ID)
		}
		// IDs match, no reload needed
		return false, ""
	}

	// No ID in new config, fall back to modification time
	if info.ModTime().After(lastMod) {
		return true, "file modification time changed (no ID in config)"
	}

	return false, ""
}

// Stop stops the configuration file watcher
func (m *Manager) Stop() {
	close(m.stopAPIRefresh)
	close(m.stopWatcher)

	// Close fsnotify watcher
	if m.watcher != nil {
		m.watcher.Close()
	}

	// Disconnect Realtime client
	m.mu.Lock()
	if m.realtimeClient != nil {
		m.realtimeClient.Disconnect()
		m.realtimeClient = nil
	}
	m.mu.Unlock()
}

// RefreshFromAPI fetches the latest configuration from the API and updates the config file
func (m *Manager) RefreshFromAPI() error {
	m.mu.RLock()
	hasHostKey := m.config != nil && m.config.Host != nil && m.config.Host.Key != ""
	currentConfigID := m.currentConfigID
	m.mu.RUnlock()

	// Only refresh if we have a host key
	if !hasHostKey {
		return nil
	}

	// Fetch configuration from API using the client
	body, err := m.apiClient.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to fetch configuration from API: %w", err)
	}

	// Parse the new configuration to check ID
	var newConfig struct {
		ID string `json:"id,omitempty"`
	}
	if err := json.Unmarshal(body, &newConfig); err != nil {
		return fmt.Errorf("failed to parse API configuration: %w", err)
	}

	// If we have an ID in the new config, check if it's different from current
	if newConfig.ID != "" && newConfig.ID == currentConfigID {
		if m.verbose {
			log.Printf("[config] API configuration ID (%s) matches current, skipping update", newConfig.ID)
		}
		return nil
	}

	// Write to temporary file first for atomic update
	tmpFile := m.configPath + ".tmp"
	if err := os.WriteFile(tmpFile, body, 0644); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}

	// Atomically rename to final location
	if err := os.Rename(tmpFile, m.configPath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	if newConfig.ID != "" {
		log.Printf("[config] Configuration refreshed from API successfully (ID: %s -> %s)", currentConfigID, newConfig.ID)
	} else {
		log.Printf("[config] Configuration refreshed from API successfully (no ID)")
	}

	// The file watcher will detect the change and reload automatically
	return nil
}

// StartAPIRefresh starts a goroutine that periodically refreshes the configuration from the API
func (m *Manager) StartAPIRefresh(interval time.Duration) {
	log.Printf("[config] Started API configuration refresher")

	go func() {
		// Initial refresh on startup
		if err := m.RefreshFromAPI(); err != nil {
			log.Printf("[config] Initial API refresh failed: %v", err)
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := m.RefreshFromAPI(); err != nil {
					log.Printf("[config] API refresh failed: %v", err)
				}
			case <-m.stopAPIRefresh:
				return
			}
		}
	}()
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
		return "", fmt.Errorf("no IP database configured")
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

	// Download/retrieve from cache (API key will be applied automatically if URL starts with API base)
	cachedPath, _, err := m.cache.FetchFileWithCache(dbURL, cacheTTL)
	if err != nil {
		// Fallback to local file if download fails
		if _, err := os.Stat("ipinfo_lite.mmdb"); err == nil {
			log.Printf("[config] Failed to download IP database, using local file: %v", err)
			return "ipinfo_lite.mmdb", nil
		}
		return "", fmt.Errorf("failed to download IP database: %w", err)
	}

	// Note: Cache already logs the status (cache hit, 304, fresh file)
	return cachedPath, nil
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
	// Get cache TTL from config
	cacheTTL := 24 * time.Hour // default
	m.mu.RLock()
	if m.config != nil && m.config.TrustedProxies != nil && m.config.TrustedProxies.RefreshIntervalSeconds > 0 {
		cacheTTL = time.Duration(m.config.TrustedProxies.RefreshIntervalSeconds) * time.Second
	}
	m.mu.RUnlock()

	// Use cache if available
	data, _, err := m.cache.FetchWithCache(url, cacheTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", url, err)
	}

	// Note: Cache already logs the status (cache hit, 304, fresh data)
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

// updatePusherClient updates or creates the Realtime client based on configuration
func (m *Manager) updatePusherClient(config *Config) {
	// If no pusher config, disconnect any existing client
	if config.Realtime == nil {
		if m.realtimeClient != nil {
			m.realtimeClient.Disconnect()
			m.realtimeClient = nil
			log.Printf("[config] Realtime client disconnected (no configuration)")
		}
		return
	}

	// If no existing client, create new one
	if m.realtimeClient == nil {
		m.realtimeClient = pusher.NewClient(config.Realtime, m.userAgent, config.Host.Key, m.verbose)

		if m.realtimeClient != nil {
			// Set up event handler for config updates
			m.realtimeClient.OnEvent("config.updated", func(message pusher.Message) {
				log.Printf("[config] Received config update event from realtime event")

				if err := m.RefreshFromAPI(); err != nil {
					log.Printf("[config] Failed to refresh config from API after realtime event: %v", err)
				}
			})

			// Start connection in background
			go func() {
				if err := m.realtimeClient.Connect(); err != nil {
					log.Printf("[config] Failed to connect to realtime server: %v", err)
				}
			}()

			log.Printf("[config] Realtime client initialized")
		}
	} else {
		// Update existing client configuration
		if err := m.realtimeClient.UpdateConfig(config.Realtime); err != nil {
			log.Printf("[config] Failed to update realtime client configuration: %v", err)
		}
	}
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
