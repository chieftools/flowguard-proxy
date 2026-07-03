package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"flowguard/config"
)

func TestMethodMatcher(t *testing.T) {
	rm := &RulesMiddleware{}

	tests := []struct {
		name     string
		method   string
		match    config.MatchCondition
		expected bool
	}{
		{
			name:   "equals method",
			method: http.MethodPost,
			match: config.MatchCondition{
				Type:  "method",
				Match: "equals",
				Value: http.MethodPost,
			},
			expected: true,
		},
		{
			name:   "method in list",
			method: http.MethodPatch,
			match: config.MatchCondition{
				Type:   "method",
				Match:  "in",
				Values: []string{http.MethodPost, http.MethodPatch},
			},
			expected: true,
		},
		{
			name:   "method not equals",
			method: http.MethodGet,
			match: config.MatchCondition{
				Type:  "method",
				Match: "not-equals",
				Value: http.MethodPost,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "https://example.com/admin", nil)
			result := rm.evaluateMatch(req, &tt.match)
			if result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestQueryParamMatcher(t *testing.T) {
	rm := &RulesMiddleware{}
	regexMatch := config.MatchCondition{
		Type:  "query-param",
		Key:   "tag",
		Match: "regex",
		Value: "^alp",
	}
	regexMatch.SetCompiledRegexInternal(regexp.MustCompile(regexMatch.Value))

	tests := []struct {
		name     string
		target   string
		match    config.MatchCondition
		expected bool
	}{
		{
			name:   "exists with empty value",
			target: "https://example.com/search?empty=",
			match: config.MatchCondition{
				Type:  "query-param",
				Key:   "empty",
				Match: "exists",
			},
			expected: true,
		},
		{
			name:   "missing",
			target: "https://example.com/search?tag=alpha",
			match: config.MatchCondition{
				Type:  "query-param",
				Key:   "missing",
				Match: "missing",
			},
			expected: true,
		},
		{
			name:   "any repeated value equals",
			target: "https://example.com/search?tag=alpha&tag=beta",
			match: config.MatchCondition{
				Type:  "query-param",
				Key:   "tag",
				Match: "equals",
				Value: "beta",
			},
			expected: true,
		},
		{
			name:     "any repeated value matches regex",
			target:   "https://example.com/search?tag=alpha&tag=beta",
			match:    regexMatch,
			expected: true,
		},
		{
			name:   "absent key does not satisfy negative comparison",
			target: "https://example.com/search?tag=alpha",
			match: config.MatchCondition{
				Type:  "query-param",
				Key:   "missing",
				Match: "not-equals",
				Value: "blocked",
			},
			expected: false,
		},
		{
			name:   "missing key fails without key field",
			target: "https://example.com/search?tag=alpha",
			match: config.MatchCondition{
				Type:  "query-param",
				Match: "exists",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			result := rm.evaluateMatch(req, &tt.match)
			if result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCookieMatcher(t *testing.T) {
	rm := &RulesMiddleware{}

	tests := []struct {
		name     string
		cookie   string
		match    config.MatchCondition
		expected bool
	}{
		{
			name:   "exists with empty value",
			cookie: "empty=",
			match: config.MatchCondition{
				Type:  "cookie",
				Key:   "empty",
				Match: "exists",
			},
			expected: true,
		},
		{
			name:   "missing",
			cookie: "session=active",
			match: config.MatchCondition{
				Type:  "cookie",
				Key:   "missing",
				Match: "missing",
			},
			expected: true,
		},
		{
			name:   "any repeated cookie equals",
			cookie: "session=bad; session=good",
			match: config.MatchCondition{
				Type:  "cookie",
				Key:   "session",
				Match: "equals",
				Value: "good",
			},
			expected: true,
		},
		{
			name:   "cookie value in list",
			cookie: "tier=pro",
			match: config.MatchCondition{
				Type:   "cookie",
				Key:    "tier",
				Match:  "in",
				Values: []string{"pro", "enterprise"},
			},
			expected: true,
		},
		{
			name:   "absent key does not satisfy negative comparison",
			cookie: "session=active",
			match: config.MatchCondition{
				Type:  "cookie",
				Key:   "missing",
				Match: "not-in",
				Values: []string{
					"blocked",
				},
			},
			expected: false,
		},
		{
			name:   "missing key fails without key field",
			cookie: "session=active",
			match: config.MatchCondition{
				Type:  "cookie",
				Match: "exists",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
			req.Header.Set("Cookie", tt.cookie)
			result := rm.evaluateMatch(req, &tt.match)
			if result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIPMatcherSupportsCIDRTargets(t *testing.T) {
	rm := &RulesMiddleware{}

	tests := []struct {
		name     string
		clientIP string
		match    config.MatchCondition
		expected bool
	}{
		{
			name:     "equals exact IP",
			clientIP: "203.0.113.10",
			match: config.MatchCondition{
				Type:  "ip",
				Match: "equals",
				Value: "203.0.113.10",
			},
			expected: true,
		},
		{
			name:     "equals CIDR",
			clientIP: "203.0.113.10",
			match: config.MatchCondition{
				Type:  "ip",
				Match: "equals",
				Value: "203.0.113.0/24",
			},
			expected: true,
		},
		{
			name:     "not equals CIDR fails when contained",
			clientIP: "203.0.113.10",
			match: config.MatchCondition{
				Type:  "ip",
				Match: "not-equals",
				Value: "203.0.113.0/24",
			},
			expected: false,
		},
		{
			name:     "in IPv6 CIDR",
			clientIP: "2001:db8::10",
			match: config.MatchCondition{
				Type:   "ip",
				Match:  "in",
				Values: []string{"198.51.100.0/24", "2001:db8::/32"},
			},
			expected: true,
		},
		{
			name:     "not in CIDR fails when contained",
			clientIP: "198.51.100.50",
			match: config.MatchCondition{
				Type:   "ip",
				Match:  "not-in",
				Values: []string{"198.51.100.0/24"},
			},
			expected: false,
		},
		{
			name:     "not in CIDR matches outside range",
			clientIP: "192.0.2.50",
			match: config.MatchCondition{
				Type:   "ip",
				Match:  "not-in",
				Values: []string{"198.51.100.0/24"},
			},
			expected: true,
		},
		{
			name:     "string operator still uses string matching",
			clientIP: "203.0.113.10",
			match: config.MatchCondition{
				Type:  "ip",
				Match: "contains",
				Value: "203.0.113",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := requestWithClientIP(tt.clientIP)
			result := rm.evaluateMatch(req, &tt.match)
			if result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRateLimitKeyGeneratorIncludesRequestFieldMatchers(t *testing.T) {
	rule := &config.Rule{
		Conditions: &config.RuleConditions{
			Matches: []config.MatchCondition{
				{Type: "method", Match: "equals", Value: http.MethodPost},
				{Type: "query-param", Key: "token", Match: "exists"},
				{Type: "cookie", Key: "session", Match: "exists"},
			},
		},
	}

	generator := &RateLimitKeyGenerator{}
	base := httptest.NewRequest(http.MethodPost, "https://example.com/path?token=one", nil)
	base.Header.Set("Cookie", "session=one")

	differentMethod := httptest.NewRequest(http.MethodGet, "https://example.com/path?token=one", nil)
	differentMethod.Header.Set("Cookie", "session=one")

	differentQuery := httptest.NewRequest(http.MethodPost, "https://example.com/path?token=two", nil)
	differentQuery.Header.Set("Cookie", "session=one")

	differentCookie := httptest.NewRequest(http.MethodPost, "https://example.com/path?token=one", nil)
	differentCookie.Header.Set("Cookie", "session=two")

	baseKey := generator.GenerateKey("rule", rule, base)
	if baseKey == generator.GenerateKey("rule", rule, differentMethod) {
		t.Fatal("expected method changes to affect rate limit key")
	}
	if baseKey == generator.GenerateKey("rule", rule, differentQuery) {
		t.Fatal("expected query parameter changes to affect rate limit key")
	}
	if baseKey == generator.GenerateKey("rule", rule, differentCookie) {
		t.Fatal("expected cookie changes to affect rate limit key")
	}
}

func requestWithClientIP(clientIP string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	ctx := context.WithValue(req.Context(), ContextKeyClientIP, clientIP)
	return req.WithContext(ctx)
}
