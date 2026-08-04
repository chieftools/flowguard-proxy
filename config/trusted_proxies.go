package config

import (
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"flowguard/iplist"
)

const (
	DefaultTrustedProxyHeaderAuthHeader = "FG-Trusted-Proxy-Secret"
	defaultTrustedProxyRefreshInterval  = 30 * time.Minute
)

// GetRefreshInterval returns the configured refresh interval for trusted proxies.
func (m *Manager) GetRefreshInterval() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return trustedProxyRefreshInterval(m.config)
}

func trustedProxyRefreshInterval(config *Config) time.Duration {
	if config == nil || config.TrustedProxies == nil || config.TrustedProxies.RefreshIntervalSeconds <= 0 {
		return defaultTrustedProxyRefreshInterval
	}
	return time.Duration(config.TrustedProxies.RefreshIntervalSeconds) * time.Second
}

// IsTrustedProxy checks if an IP is from a trusted proxy.
func (m *Manager) IsTrustedProxy(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

	m.mu.RLock()
	set := m.trustedProxySet
	m.mu.RUnlock()
	return set.Contains(addr)
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

// StartTrustedProxyRefresh starts periodic URL refreshes for the running proxy.
func (m *Manager) StartTrustedProxyRefresh() {
	m.trustedProxyRefreshOnce.Do(func() {
		m.trustedProxyRefreshWG.Add(1)
		go m.runTrustedProxyRefresh()
	})
}

func (m *Manager) runTrustedProxyRefresh() {
	defer m.trustedProxyRefreshWG.Done()

	for {
		interval, enabled := m.trustedProxySchedule()
		var timer *time.Timer
		var timerC <-chan time.Time
		if enabled {
			timer = time.NewTimer(interval)
			timerC = timer.C
		}

		select {
		case <-m.stopTrustedProxyRefresh:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-m.wakeTrustedProxyRefresh:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timerC:
			if err := m.RefreshTrustedProxies(); err != nil {
				log.Printf("[trusted_proxy] Failed to refresh trusted proxy sources: %v", err)
			}
		}
	}
}

func (m *Manager) trustedProxySchedule() (time.Duration, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.config == nil || m.config.TrustedProxies == nil {
		return 0, false
	}
	for _, source := range m.config.TrustedProxies.IPNets {
		if isHTTPSource(source) {
			return trustedProxyRefreshInterval(m.config), true
		}
	}
	return 0, false
}

func (m *Manager) wakeTrustedProxyRefreshLoop() {
	select {
	case m.wakeTrustedProxyRefresh <- struct{}{}:
	default:
	}
}

// RefreshTrustedProxies refreshes URL-backed trusted proxy sources and swaps
// the effective set atomically. A failed source retains its last valid set.
func (m *Manager) RefreshTrustedProxies() error {
	m.trustedProxyUpdateMu.Lock()
	defer m.trustedProxyUpdateMu.Unlock()

	m.mu.RLock()
	config := m.config
	previousSet := m.trustedProxySet
	m.mu.RUnlock()

	if config == nil || config.TrustedProxies == nil {
		return nil
	}
	set, sources, err := m.buildTrustedProxySet(config.TrustedProxies, true)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.trustedProxySet = set
	m.trustedProxySources = sources
	m.mu.Unlock()

	if !previousSet.Equal(set) {
		log.Printf("[trusted_proxy] Refreshed trusted proxy sources (%d networks)", set.Size())
	} else if m.verbose {
		log.Printf("[trusted_proxy] Trusted proxy sources unchanged (%d networks)", set.Size())
	}
	return nil
}

func (m *Manager) buildTrustedProxySet(config *TrustedProxiesConfig, force bool) (*iplist.Set, map[string]*iplist.Set, error) {
	if err := validateTrustedProxiesConfig(config); err != nil {
		return nil, nil, err
	}

	m.mu.RLock()
	previousSources := make(map[string]*iplist.Set, len(m.trustedProxySources))
	for source, set := range m.trustedProxySources {
		previousSources[source] = set
	}
	m.mu.RUnlock()

	directPrefixes := make([]netip.Prefix, 0, len(config.IPNets))
	urlSources := make(map[string]*iplist.Set)
	for _, source := range config.IPNets {
		if !isHTTPSource(source) {
			prefix, err := iplist.ParsePrefix(source)
			if err != nil {
				return nil, nil, err
			}
			directPrefixes = append(directPrefixes, prefix)
			continue
		}

		set, err := m.fetchTrustedProxySet(source, config.RefreshIntervalSeconds, force)
		if err != nil {
			if previous := previousSources[source]; previous != nil {
				urlSources[source] = previous
				log.Printf("[trusted_proxy] Failed to refresh %s; retaining %d last-known-good networks: %v", source, previous.Size(), err)
			} else {
				log.Printf("[trusted_proxy] Failed to load %s; source contributes no trusted networks: %v", source, err)
			}
			continue
		}
		urlSources[source] = set
	}

	sets := make([]*iplist.Set, 0, len(urlSources)+1)
	sets = append(sets, iplist.NewSet(directPrefixes))
	for _, set := range urlSources {
		sets = append(sets, set)
	}
	return iplist.UnionSets(sets...), urlSources, nil
}

func (m *Manager) fetchTrustedProxySet(source string, refreshIntervalSeconds int, force bool) (*iplist.Set, error) {
	if m.cache == nil {
		return nil, fmt.Errorf("cache is not initialized")
	}

	var data []byte
	var err error
	if force {
		data, _, err = m.cache.FetchWithCacheForced(source)
	} else {
		interval := defaultTrustedProxyRefreshInterval
		if refreshIntervalSeconds > 0 {
			interval = time.Duration(refreshIntervalSeconds) * time.Second
		}
		data, _, err = m.cache.FetchWithCache(source, interval)
	}
	if err != nil {
		return nil, err
	}

	set, issues, err := iplist.ParseSet(data)
	if err != nil {
		return nil, err
	}
	for _, issue := range issues {
		log.Printf("[trusted_proxy] %v at line %d in %s", issue.Err, issue.Line, source)
	}
	return set, nil
}

func isHTTPSource(source string) bool {
	return strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
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
