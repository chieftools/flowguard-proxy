package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"sort"

	"go.chief.tools/flowguard-proxy/iplist"
)

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
		if errors.Is(err, fs.ErrPermission) {
			return fmt.Errorf("failed to read config file: %w; it holds the host key and only root can read it, so run flowguard as root, for example with sudo", err)
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config JSON: %w", err)
	}

	if config.TrustedProxies != nil {
		if err := validateTrustedProxiesConfig(config.TrustedProxies); err != nil {
			return err
		}
	}

	if config.Rules != nil {
		for id, rule := range config.Rules {
			rule.ID = id

			if rule.Conditions != nil {
				if err := validateConditionOperators(rule.ID, rule.Conditions, "conditions"); err != nil {
					return err
				}
				normalizeHostMatchValues(rule.Conditions)
				m.compileConditionRegex(rule.Conditions)
			}
		}
	}

	if config.Actions != nil {
		for id, action := range config.Actions {
			action.ID = id
		}
	}

	if err := validateChallengesConfig(&config); err != nil {
		return err
	}
	if err := validateUpstreamConfig(&config); err != nil {
		return err
	}
	if err := validateBindAddresses(&config); err != nil {
		return err
	}

	if !config.ProtocolSettings().AnyEnabled() {
		return fmt.Errorf("server.protocols must enable at least one protocol")
	}

	hostKey := ""
	if config.Host != nil {
		hostKey = config.Host.Key
	}

	userAgent := config.UserAgent(m.userAgent)
	m.apiClient.SetIdentity(hostKey, userAgent)
	if m.cache != nil {
		m.cache.SetAPIIdentity(m.apiClient.GetBaseURL(), hostKey, userAgent)
	}

	// Pre-compute sorted rules for efficient iteration during request processing
	sortedRules := m.computeSortedRules(config.Rules)

	// Serialize trusted proxy source updates with periodic refreshes. Building
	// may reuse the last-known-good value for a URL that is temporarily down.
	m.trustedProxyUpdateMu.Lock()

	trustedProxySet := iplist.NewSet(nil)
	trustedProxySources := make(map[string]*iplist.Set)
	proxyProtocolSet := iplist.NewSet(nil)
	if config.TrustedProxies != nil {
		trustedProxySet, trustedProxySources, err = m.buildTrustedProxySet(config.TrustedProxies, false)
		if err != nil {
			m.trustedProxyUpdateMu.Unlock()
			return fmt.Errorf("failed to parse trusted proxies: %w", err)
		}
		proxyProtocolSet, err = buildProxyProtocolSet(config.TrustedProxies.ProxyProtocol)
		if err != nil {
			m.trustedProxyUpdateMu.Unlock()
			return fmt.Errorf("failed to parse trusted proxies: %w", err)
		}
	}

	// Update configuration atomically
	m.mu.Lock()

	oldConfig := m.config
	m.config = &config
	m.sortedRules = sortedRules
	m.trustedProxySet = trustedProxySet
	m.trustedProxySources = trustedProxySources
	m.proxyProtocolSet = proxyProtocolSet
	m.lastModified = info.ModTime()
	m.currentConfigID = config.ID

	m.mu.Unlock()
	m.trustedProxyUpdateMu.Unlock()
	m.wakeTrustedProxyRefreshLoop()

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

	log.Printf("[config] Loaded configuration from %s (rules: %d, actions: %d, trusted proxies: %d networks)", m.configPath, len(config.Rules), len(config.Actions), trustedProxySet.Size())

	return nil
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
		iHasOrder := ruleList[i].SortOrder != nil
		jHasOrder := ruleList[j].SortOrder != nil

		switch {
		case iHasOrder && !jHasOrder:
			return true
		case !iHasOrder && jHasOrder:
			return false
		case iHasOrder && jHasOrder && *ruleList[i].SortOrder != *ruleList[j].SortOrder:
			return *ruleList[i].SortOrder < *ruleList[j].SortOrder
		}

		// Fall back to ID comparison for deterministic ordering
		return ruleList[i].ID < ruleList[j].ID
	})

	return ruleList
}
