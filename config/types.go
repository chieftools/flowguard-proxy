package config

import (
	"regexp"

	"flowguard/pusher"
)

// Config represents the complete application configuration
type Config struct {
	ID             string                 `json:"id,omitempty"`
	Host           *HostConfig            `json:"host,omitempty"`
	Rules          map[string]*Rule       `json:"rules"`
	Actions        map[string]*RuleAction `json:"actions"`
	Logging        *LoggingConfig         `json:"logging,omitempty"`
	IPLists        *IPListsConfig         `json:"ip_lists,omitempty"`
	Updates        *UpdatesConfig         `json:"updates,omitempty"`
	Firewall       *FirewallConfig        `json:"firewall,omitempty"`
	Realtime       *pusher.Config         `json:"realtime,omitempty"`
	Heartbeat      *HeartbeatConfig       `json:"heartbeat,omitempty"`
	IPDatabase     *IPDatabaseConfig      `json:"ip_database,omitempty"`
	TrustedProxies *TrustedProxiesConfig  `json:"trusted_proxies,omitempty"`
}

type HostConfig struct {
	ID              string `json:"id,omitempty"`
	Key             string `json:"key,omitempty"`
	Name            string `json:"name,omitempty"`
	Team            string `json:"team,omitempty"`
	CacheDir        string `json:"cache_dir,omitempty"`
	CertPath        string `json:"cert_path,omitempty"`
	NginxConfigPath string `json:"nginx_config_path,omitempty"`
	DefaultHostname string `json:"default_hostname,omitempty"`
}

type LoggingConfig struct {
	Sinks           map[string]map[string]interface{} `json:"sinks,omitempty"`
	HeaderWhitelist []string                          `json:"header_whitelist,omitempty"`
}

type UpdatesConfig struct {
	AllowUnattended bool `json:"allow_unattended"`
}

type FirewallConfig struct {
	MonitorEnabled       *bool `json:"monitor_enabled,omitempty"`
	AutoRepair           *bool `json:"auto_repair,omitempty"`
	CheckIntervalSeconds int   `json:"check_interval_seconds,omitempty"`
}

type HeartbeatConfig struct {
	Enabled         *bool `json:"enabled,omitempty"`
	JitterSeconds   int   `json:"jitter_seconds,omitempty"`
	IntervalSeconds int   `json:"interval_seconds,omitempty"`
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
	Name                   string `json:"name,omitempty"`
	Path                   string `json:"path,omitempty"`
	Confidence             int    `json:"confidence,omitempty"`
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
	Operator string           `json:"operator,omitempty"` // AND, OR, NAND, NOR
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
	Confidence      int      `json:"confidence,omitempty"` // Minimum confidence level (0-100) for IP list matches
	Family          uint     `json:"family,omitempty"`     // For ipset matches (4 or 6)
	RawMatch        bool     `json:"raw_match,omitempty"`  // Skip normalization for path matching
	compiledRegex   *regexp.Regexp
}

// GetCompiledRegex returns the compiled regex for a MatchCondition
func (m *MatchCondition) GetCompiledRegex() *regexp.Regexp {
	return m.compiledRegex
}

// SetCompiledRegexInternal sets the compiled regex (for testing)
func (m *MatchCondition) SetCompiledRegexInternal(re *regexp.Regexp) {
	m.compiledRegex = re
}
