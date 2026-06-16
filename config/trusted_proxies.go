package config

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

const DefaultTrustedProxyHeaderAuthHeader = "FG-Trusted-Proxy-Secret"

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

// GetTrustedProxyHeaderAuth returns the configured trusted proxy header auth values.
func (m *Manager) GetTrustedProxyHeaderAuth() (header string, values []string, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.config == nil || m.config.TrustedProxies == nil || m.config.TrustedProxies.HeaderAuth == nil {
		return "", nil, false
	}

	auth := m.config.TrustedProxies.HeaderAuth
	values = make([]string, len(auth.Values))
	copy(values, auth.Values)
	return trustedProxyHeaderAuthHeader(auth), values, true
}

// RefreshTrustedProxies refreshes trusted proxy lists from URLs
func (m *Manager) RefreshTrustedProxies() error {
	m.mu.RLock()
	config := m.config
	m.mu.RUnlock()

	if config == nil || config.TrustedProxies == nil {
		return nil
	}

	if err := validateTrustedProxiesConfig(config.TrustedProxies); err != nil {
		return err
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
					log.Printf("[config] Cache still fresh for %s (age: %v, TTL: %v)", proxy, time.Since(timestamp), cacheTTL)
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

// parseIPOrCIDR parses a string as either a CIDR or plain IP address.
// Plain IPs are converted to /32 (IPv4) or /128 (IPv6) networks.
func parseIPOrCIDR(s string) (net.IPNet, error) {
	if strings.Contains(s, "/") {
		_, network, err := net.ParseCIDR(s)
		if err != nil {
			return net.IPNet{}, fmt.Errorf("invalid CIDR %s: %w", s, err)
		}
		return *network, nil
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return net.IPNet{}, fmt.Errorf("invalid IP address: %s", s)
	}

	if ip.To4() != nil {
		return net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
	}
	return net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
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
			ipNet, err := parseIPOrCIDR(proxy)
			if err != nil {
				return nil, err
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

func validateTrustedProxiesConfig(config *TrustedProxiesConfig) error {
	if config == nil {
		return nil
	}

	if len(config.IPNets) == 0 && config.HeaderAuth == nil {
		return fmt.Errorf("trusted_proxies must configure ipnets or header_auth")
	}

	if config.HeaderAuth == nil {
		return nil
	}

	if config.HeaderAuth.Header != nil && *config.HeaderAuth.Header == "" {
		return fmt.Errorf("trusted_proxies.header_auth.header must not be empty")
	}
	if config.HeaderAuth.Header != nil && !isHTTPHeaderFieldName(*config.HeaderAuth.Header) {
		return fmt.Errorf("trusted_proxies.header_auth.header must be a valid HTTP header field name")
	}

	if len(config.HeaderAuth.Values) == 0 {
		return fmt.Errorf("trusted_proxies.header_auth.values must contain at least one value")
	}
	for i, value := range config.HeaderAuth.Values {
		if value == "" {
			return fmt.Errorf("trusted_proxies.header_auth.values[%d] must not be empty", i)
		}
	}

	return nil
}

func trustedProxyHeaderAuthHeader(config *TrustedProxyHeaderAuthConfig) string {
	if config == nil || config.Header == nil {
		return DefaultTrustedProxyHeaderAuthHeader
	}

	return *config.Header
}

func isHTTPHeaderFieldName(name string) bool {
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'':
		case c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_':
		case c == '`' || c == '|' || c == '~':
		default:
			return false
		}
	}

	return name != ""
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

// parseIPRanges parses IP ranges from raw data (supports plain IPs and CIDR notation)
func (m *Manager) parseIPRanges(data []byte, source string) ([]net.IPNet, error) {
	var result []net.IPNet
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ipNet, err := parseIPOrCIDR(line)
		if err != nil {
			log.Printf("[config] %v from %s", err, source)
			continue
		}
		result = append(result, ipNet)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
