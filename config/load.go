package config

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
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
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config JSON: %w", err)
	}

	// Set host key in API client and cache if available
	if config.Host != nil && config.Host.Key != "" {
		m.apiClient.SetHostKey(config.Host.Key)

		if m.cache != nil {
			m.cache.SetAPICredentials(m.apiClient.GetBaseURL(), config.Host.Key)
		}
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
				if err := validateConditionOperators(rule.ID, rule.Conditions, "conditions"); err != nil {
					return err
				}
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
		iHasOrder := ruleList[i].SortOrder != 0
		jHasOrder := ruleList[j].SortOrder != 0

		switch {
		case iHasOrder && !jHasOrder:
			return true
		case !iHasOrder && jHasOrder:
			return false
		case iHasOrder && jHasOrder && ruleList[i].SortOrder != ruleList[j].SortOrder:
			return ruleList[i].SortOrder < ruleList[j].SortOrder
		}

		// Fall back to ID comparison for deterministic ordering
		return ruleList[i].ID < ruleList[j].ID
	})

	return ruleList
}
