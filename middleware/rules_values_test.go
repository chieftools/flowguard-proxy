package middleware

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"flowguard/config"
)

func TestEvaluateMatch_QueryParamSeesPairsGoWouldDrop(t *testing.T) {
	rm := &RulesMiddleware{}
	match := &config.MatchCondition{Type: "query-param", Key: "q", Match: "contains", Value: "union select"}

	for _, rawQuery := range []string{
		"q=1+union+select",
		"q=1+union+select;",
		"q=%zz'+union+select",
		"x=%zz&q=1+union+select",
	} {
		t.Run(rawQuery, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.URL.RawQuery = rawQuery
			if !rm.evaluateMatch(req, match) {
				t.Errorf("expected query %q to match", rawQuery)
			}
		})
	}
}

func TestEvaluateMatch_HeaderChecksEveryValue(t *testing.T) {
	rm := &RulesMiddleware{}

	tests := []struct {
		name     string
		header   string
		values   []string
		match    config.MatchCondition
		expected bool
	}{
		{"later value equals", "X-Debug", []string{"0", "1"}, config.MatchCondition{Type: "header", Key: "X-Debug", Match: "equals", Value: "1"}, true},
		{"joined value equals", "X-Debug", []string{"0", "1"}, config.MatchCondition{Type: "header", Key: "X-Debug", Match: "equals", Value: "0, 1"}, true},
		{"later value fails not-equals", "X-Debug", []string{"0", "1"}, config.MatchCondition{Type: "header", Key: "X-Debug", Match: "not-equals", Value: "1"}, false},
		{"later user agent contains", "User-Agent", []string{"Mozilla/5.0", "sqlmap/1.7"}, config.MatchCondition{Type: "user-agent", Match: "contains", Value: "sqlmap"}, true},
		{"missing header matches not-equals", "", nil, config.MatchCondition{Type: "header", Key: "X-Token", Match: "not-equals", Value: "secret"}, true},
		{"missing user agent matches not-contains", "", nil, config.MatchCondition{Type: "user-agent", Match: "not-contains", Value: "Mozilla"}, true},
		{"empty header is missing", "X-Token", []string{""}, config.MatchCondition{Type: "header", Key: "X-Token", Match: "missing"}, true},
		{"later non-empty value exists", "X-Token", []string{"", "abc"}, config.MatchCondition{Type: "header", Key: "X-Token", Match: "exists"}, true},
		{"user agent exists", "User-Agent", []string{"curl/8.0"}, config.MatchCondition{Type: "user-agent", Match: "exists"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Del("User-Agent")
			for _, value := range tt.values {
				req.Header.Add(tt.header, value)
			}
			if got := rm.evaluateMatch(req, &tt.match); got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestEvaluateMatch_NegatedOperatorsRequireNoValueToMatch(t *testing.T) {
	rm := &RulesMiddleware{}

	tests := []struct {
		name     string
		rawQuery string
		cookie   string
		match    config.MatchCondition
		expected bool
	}{
		{"query not-contains with one bad value", "q=safe&q=<script>", "", config.MatchCondition{Type: "query-param", Key: "q", Match: "not-contains", Value: "<"}, false},
		{"query not-contains with only safe values", "q=safe&q=fine", "", config.MatchCondition{Type: "query-param", Key: "q", Match: "not-contains", Value: "<"}, true},
		{"query not-in with one listed value", "mode=read&mode=admin", "", config.MatchCondition{Type: "query-param", Key: "mode", Match: "not-in", Values: []string{"admin"}}, false},
		{"query not-regex with one matching value", "id=1&id=1+or+1=1", "", config.MatchCondition{Type: "query-param", Key: "id", Match: "not-regex", Value: `\s`}, false},
		{"query contains with one bad value", "q=safe&q=<script>", "", config.MatchCondition{Type: "query-param", Key: "q", Match: "contains", Value: "<"}, true},
		{"cookie not-equals with one bad value", "", "role=user; role=admin", config.MatchCondition{Type: "cookie", Key: "role", Match: "not-equals", Value: "admin"}, false},
		{"cookie not-equals with only good values", "", "role=user; role=guest", config.MatchCondition{Type: "cookie", Key: "role", Match: "not-equals", Value: "admin"}, true},
		{"missing query key matches not-equals", "other=1", "", config.MatchCondition{Type: "query-param", Key: "token", Match: "not-equals", Value: "secret"}, true},
		{"missing query key does not match contains", "other=1", "", config.MatchCondition{Type: "query-param", Key: "rest_route", Match: "contains", Value: "/batch/v1"}, false},
		{"missing query key is missing", "other=1", "", config.MatchCondition{Type: "query-param", Key: "author", Match: "missing"}, true},
		{"empty query key exists", "author=", "", config.MatchCondition{Type: "query-param", Key: "author", Match: "exists"}, true},
		{"missing cookie matches not-equals", "", "other=1", config.MatchCondition{Type: "cookie", Key: "role", Match: "not-equals", Value: "admin"}, true},
		{"missing cookie does not match equals", "", "", config.MatchCondition{Type: "cookie", Key: "role", Match: "equals", Value: "admin"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.match.Match == "not-regex" {
				tt.match.SetCompiledRegexInternal(regexp.MustCompile(tt.match.Value))
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.URL.RawQuery = tt.rawQuery
			if tt.cookie != "" {
				req.Header.Set("Cookie", tt.cookie)
			}
			if got := rm.evaluateMatch(req, &tt.match); got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestEvaluateMatch_DomainRegexSeesIPLiteralHosts(t *testing.T) {
	rm := &RulesMiddleware{}
	// A raw-IP / missing-Host rule as written in the control panel, accepting
	// both bracketed and bare IPv6. Domain regexes are compiled
	// case-insensitively at config load.
	match := &config.MatchCondition{Type: "domain", Match: "regex", Value: `^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[?[0-9a-fA-F]*:[0-9a-fA-F]*:[0-9a-fA-F:]*\]?)?(:\d{1,5})?$`}
	match.SetCompiledRegexInternal(regexp.MustCompile("(?i)" + match.Value))

	tests := map[string]bool{
		"":                      true,
		"192.0.2.10":            true,
		"192.0.2.10:443":        true,
		"[2001:db8::10]":        true,
		"[2001:DB8::10]:443":    true,
		"[::ffff:192.0.2.10]":   true,
		"example.com":           false,
		"example.com:443":       false,
		"www.example.com.:8443": false,
		"cafe:443":              false,
	}
	for host, expected := range tests {
		t.Run(host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = host
			if got := rm.evaluateMatch(req, match); got != expected {
				t.Errorf("host %q: expected %v, got %v", host, expected, got)
			}
		})
	}
}
