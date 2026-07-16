package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"flowguard/config"
)

func TestProxyIPMatcher(t *testing.T) {
	rm := &RulesMiddleware{}

	tests := []struct {
		name     string
		proxyIP  string
		match    config.MatchCondition
		expected bool
	}{
		{
			name:    "equals exact IP",
			proxyIP: "203.0.113.10",
			match: config.MatchCondition{
				Type:  "proxy-ip",
				Match: "equals",
				Value: "203.0.113.10",
			},
			expected: true,
		},
		{
			name:    "equals exact IPv6 address",
			proxyIP: "2001:db8::10",
			match: config.MatchCondition{
				Type:  "proxy-ip",
				Match: "equals",
				Value: "2001:db8::10",
			},
			expected: true,
		},
		{
			name:    "equals CIDR",
			proxyIP: "203.0.113.10",
			match: config.MatchCondition{
				Type:  "proxy-ip",
				Match: "equals",
				Value: "203.0.113.0/24",
			},
			expected: true,
		},
		{
			name:    "in IPv6 CIDR",
			proxyIP: "2001:db8::10",
			match: config.MatchCondition{
				Type:   "proxy-ip",
				Match:  "in",
				Values: []string{"198.51.100.0/24", "2001:db8::/32"},
			},
			expected: true,
		},
		{
			name:    "not in CIDR fails when contained",
			proxyIP: "198.51.100.50",
			match: config.MatchCondition{
				Type:   "proxy-ip",
				Match:  "not-in",
				Values: []string{"198.51.100.0/24"},
			},
			expected: false,
		},
		{
			name:    "exists with proxy IP",
			proxyIP: "203.0.113.10",
			match: config.MatchCondition{
				Type:  "proxy-ip",
				Match: "exists",
			},
			expected: true,
		},
		{
			name: "missing without proxy IP",
			match: config.MatchCondition{
				Type:  "proxy-ip",
				Match: "missing",
			},
			expected: true,
		},
		{
			name: "negative comparison does not match missing proxy IP",
			match: config.MatchCondition{
				Type:  "proxy-ip",
				Match: "not-equals",
				Value: "203.0.113.10",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := requestWithProxyInfo(tt.proxyIP, nil)
			if result := rm.evaluateMatch(req, &tt.match); result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestProxyASNMatcher(t *testing.T) {
	rm := &RulesMiddleware{}
	cloudflareASN := &ASNInfo{ASN: "AS13335"}
	invalidASN := &ASNInfo{ASN: "13335"}

	tests := []struct {
		name     string
		proxyASN *ASNInfo
		match    config.MatchCondition
		expected bool
	}{
		{
			name:     "equals ASN number",
			proxyASN: cloudflareASN,
			match: config.MatchCondition{
				Type:  "proxy-asn",
				Match: "equals",
				Value: "13335",
			},
			expected: true,
		},
		{
			name:     "ASN in list",
			proxyASN: cloudflareASN,
			match: config.MatchCondition{
				Type:   "proxy-asn",
				Match:  "in",
				Values: []string{"13335", "209242"},
			},
			expected: true,
		},
		{
			name:     "exists with usable ASN",
			proxyASN: cloudflareASN,
			match: config.MatchCondition{
				Type:  "proxy-asn",
				Match: "exists",
			},
			expected: true,
		},
		{
			name: "missing without ASN",
			match: config.MatchCondition{
				Type:  "proxy-asn",
				Match: "missing",
			},
			expected: true,
		},
		{
			name:     "invalid ASN is missing",
			proxyASN: invalidASN,
			match: config.MatchCondition{
				Type:  "proxy-asn",
				Match: "missing",
			},
			expected: true,
		},
		{
			name: "negative comparison does not match missing ASN",
			match: config.MatchCondition{
				Type:  "proxy-asn",
				Match: "not-equals",
				Value: "13335",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := requestWithProxyInfo("203.0.113.10", tt.proxyASN)
			if result := rm.evaluateMatch(req, &tt.match); result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestProxyIPListMatcher(t *testing.T) {
	listManager := &stubIPListManager{
		lists: map[string]map[string]bool{
			"proxy-allowlist": {
				"203.0.113.10": true,
			},
			"proxy-allowlist@80": {
				"203.0.113.11": true,
			},
		},
	}
	rm := &RulesMiddleware{ipListManager: listManager}

	tests := []struct {
		name        string
		proxyIP     string
		match       config.MatchCondition
		expected    bool
		queriedList string
	}{
		{
			name:    "proxy IP is in list",
			proxyIP: "203.0.113.10",
			match: config.MatchCondition{
				Type:  "proxy-iplist",
				Match: "in",
				Value: "proxy-allowlist",
			},
			expected:    true,
			queriedList: "proxy-allowlist",
		},
		{
			name:    "proxy IP in list does not match not-in",
			proxyIP: "203.0.113.10",
			match: config.MatchCondition{
				Type:  "proxy-iplist",
				Match: "not-in",
				Value: "proxy-allowlist",
			},
			expected:    false,
			queriedList: "proxy-allowlist",
		},
		{
			name:    "proxy IP outside list matches not-in",
			proxyIP: "198.51.100.10",
			match: config.MatchCondition{
				Type:  "proxy-iplist",
				Match: "not-in",
				Value: "proxy-allowlist",
			},
			expected:    true,
			queriedList: "proxy-allowlist",
		},
		{
			name: "missing proxy IP does not match negative comparison",
			match: config.MatchCondition{
				Type:  "proxy-iplist",
				Match: "not-in",
				Value: "proxy-allowlist",
			},
			expected: false,
		},
		{
			name:    "confidence-specific list is preferred",
			proxyIP: "203.0.113.11",
			match: config.MatchCondition{
				Type:       "proxy-iplist",
				Match:      "in",
				Value:      "proxy-allowlist",
				Confidence: 80,
			},
			expected:    true,
			queriedList: "proxy-allowlist@80",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listManager.lastContainsList = ""
			req := requestWithProxyInfo(tt.proxyIP, nil)
			if result := rm.evaluateMatch(req, &tt.match); result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
			if listManager.lastContainsList != tt.queriedList {
				t.Fatalf("expected list %q, got %q", tt.queriedList, listManager.lastContainsList)
			}
		})
	}
}

type stubIPListManager struct {
	lists            map[string]map[string]bool
	lastContainsList string
}

func (m *stubIPListManager) Contains(listName string, ip string) bool {
	m.lastContainsList = listName
	return m.lists[listName][ip]
}

func (m *stubIPListManager) HasList(listName string) bool {
	_, exists := m.lists[listName]
	return exists
}

func TestProxyIPAllowlistRuleBlocksDirectAndUnlistedTraffic(t *testing.T) {
	configProvider := &MockConfigProvider{
		rules: map[string]*config.Rule{
			"block-non-allowlisted-proxies": {
				ID:     "block-non-allowlisted-proxies",
				Action: "block",
				Conditions: &config.RuleConditions{
					Operator: "OR",
					Matches: []config.MatchCondition{
						{Type: "proxy-ip", Match: "missing"},
						{Type: "proxy-iplist", Match: "not-in", Value: "proxy-allowlist"},
					},
				},
			},
		},
		actions: map[string]*config.RuleAction{
			"block": {Action: "block", Status: http.StatusForbidden},
		},
	}
	rm := NewRulesMiddleware(configProvider)
	defer rm.Stop()
	rm.SetIPListManager(&stubIPListManager{
		lists: map[string]map[string]bool{
			"proxy-allowlist": {
				"203.0.113.10": true,
			},
		},
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	directResponse := httptest.NewRecorder()
	rm.Handle(directResponse, requestWithProxyInfo("", nil), next)
	if directResponse.Code != http.StatusForbidden {
		t.Fatalf("expected direct request to be blocked, got %d", directResponse.Code)
	}

	proxiedResponse := httptest.NewRecorder()
	rm.Handle(proxiedResponse, requestWithProxyInfo("203.0.113.10", nil), next)
	if proxiedResponse.Code != http.StatusNoContent {
		t.Fatalf("expected allowlisted proxy request to continue, got %d", proxiedResponse.Code)
	}

	unlistedResponse := httptest.NewRecorder()
	rm.Handle(unlistedResponse, requestWithProxyInfo("203.0.113.11", nil), next)
	if unlistedResponse.Code != http.StatusForbidden {
		t.Fatalf("expected unlisted proxy request to be blocked, got %d", unlistedResponse.Code)
	}
}

func TestRateLimitKeyGeneratorIncludesProxyMatchers(t *testing.T) {
	rule := &config.Rule{
		Conditions: &config.RuleConditions{
			Matches: []config.MatchCondition{
				{Type: "proxy-ip", Match: "exists"},
				{Type: "proxy-asn", Match: "exists"},
			},
		},
	}
	generator := &RateLimitKeyGenerator{}

	base := requestWithProxyInfo("203.0.113.10", &ASNInfo{ASN: "AS13335"})
	differentIP := requestWithProxyInfo("203.0.113.11", &ASNInfo{ASN: "AS13335"})
	differentASN := requestWithProxyInfo("203.0.113.10", &ASNInfo{ASN: "AS209242"})

	baseKey := generator.GenerateKey("rule", rule, base)
	if baseKey == generator.GenerateKey("rule", rule, differentIP) {
		t.Fatal("expected proxy IP changes to affect rate limit key")
	}
	if baseKey == generator.GenerateKey("rule", rule, differentASN) {
		t.Fatal("expected proxy ASN changes to affect rate limit key")
	}
}

func requestWithProxyInfo(proxyIP string, proxyASN *ASNInfo) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	ctx := req.Context()
	if proxyIP != "" {
		ctx = context.WithValue(ctx, ContextKeyProxyIP, proxyIP)
		ctx = context.WithValue(ctx, ContextKeyIsProxied, true)
	}
	if proxyASN != nil {
		ctx = context.WithValue(ctx, ContextKeyProxyASNInfo, proxyASN)
	}
	return req.WithContext(ctx)
}
