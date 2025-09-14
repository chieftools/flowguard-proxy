package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"flowguard/config"
)

func TestRulesMiddleware_RawMatch(t *testing.T) {
	// Create a mock config manager with rules for testing raw_match
	configMgr := &mockConfigManager{
		rules: map[string]*config.Rule{
			"block-double-slash-raw": {
				ID:     "block-double-slash-raw",
				Action: "block-action",
				Conditions: &config.RuleConditions{
					Operator: "OR",
					Matches: []config.MatchCondition{
						{
							Type:     "path",
							Match:    "contains",
							Value:    "//wp-login",
							RawMatch: true, // This rule should match double slashes
						},
					},
				},
			},
			"block-double-slash-normalized": {
				ID:     "block-double-slash-normalized",
				Action: "block-action",
				Conditions: &config.RuleConditions{
					Operator: "OR",
					Matches: []config.MatchCondition{
						{
							Type:     "path",
							Match:    "contains",
							Value:    "//admin",
							RawMatch: false, // This rule should NOT match double slashes (normalized)
						},
					},
				},
			},
			"block-exact-path-raw": {
				ID:     "block-exact-path-raw",
				Action: "block-action",
				Conditions: &config.RuleConditions{
					Operator: "OR",
					Matches: []config.MatchCondition{
						{
							Type:     "path",
							Match:    "equals",
							Value:    "/test/../secret",
							RawMatch: true, // Should match the exact malformed path
						},
					},
				},
			},
			"block-normalized-path": {
				ID:     "block-normalized-path",
				Action: "block-action",
				Conditions: &config.RuleConditions{
					Operator: "OR",
					Matches: []config.MatchCondition{
						{
							Type:     "path",
							Match:    "equals",
							Value:    "/secret",
							RawMatch: false, // Should match after normalization
						},
					},
				},
			},
		},
		actions: map[string]*config.RuleAction{
			"block-action": {
				Action:  "block",
				Status:  403,
				Message: "Forbidden",
			},
		},
	}

	rm := NewRulesMiddleware(configMgr)

	tests := []struct {
		name        string
		path        string
		shouldBlock bool
		description string
	}{
		// Test raw_match: true (preserves double slashes)
		{
			name:        "double slash with raw_match true",
			path:        "//wp-login.php",
			shouldBlock: true,
			description: "Should block double slash when raw_match is true",
		},
		{
			name:        "single slash with raw_match true",
			path:        "/wp-login.php",
			shouldBlock: false,
			description: "Should not block single slash when looking for double slash with raw_match",
		},

		// Test raw_match: false (normalizes double slashes)
		{
			name:        "double slash with raw_match false",
			path:        "//admin/panel",
			shouldBlock: false,
			description: "Should NOT block double slash when raw_match is false (gets normalized)",
		},

		// Test path traversal with raw_match
		{
			name:        "exact malformed path with raw_match true",
			path:        "/test/../secret",
			shouldBlock: true,
			description: "Should match exact malformed path when raw_match is true",
		},
		{
			name:        "normalized path matches",
			path:        "/test/../secret",
			shouldBlock: true,
			description: "Should match after normalization when raw_match is false",
		},
		{
			name:        "already normalized path",
			path:        "/secret",
			shouldBlock: true,
			description: "Should match already normalized path",
		},

		// Test backslashes with raw_match
		{
			name:        "backslash path not matching raw",
			path:        "\\wp-login.php",
			shouldBlock: false,
			description: "Backslash should not match double forward slash pattern with raw_match",
		},

		// Test percent encoding with raw_match
		{
			name:        "percent encoded slash with raw_match",
			path:        "%2F%2Fwp-login.php",
			shouldBlock: false,
			description: "Percent-encoded slashes should not match literal double slash with raw_match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test request
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.URL.Path = tt.path
			rec := httptest.NewRecorder()

			// Create a test handler
			var handlerCalled bool
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			// Execute the middleware
			rm.Handle(rec, req, nextHandler)

			// Check the result
			if tt.shouldBlock {
				if handlerCalled {
					t.Errorf("Expected request to be blocked but handler was called. %s", tt.description)
				}
				if rec.Code != 403 {
					t.Errorf("Expected status 403, got %d. %s", rec.Code, tt.description)
				}
			} else {
				if !handlerCalled {
					t.Errorf("Expected request to pass but handler was not called. %s", tt.description)
				}
				if rec.Code != http.StatusOK {
					t.Errorf("Expected status 200, got %d. %s", rec.Code, tt.description)
				}
			}
		})
	}
}

func TestRulesMiddleware_RawMatchCombinedWithCaseInsensitive(t *testing.T) {
	// Test that raw_match and case_insensitive can work together
	configMgr := &mockConfigManager{
		rules: map[string]*config.Rule{
			"block-case-insensitive-raw": {
				ID:     "block-case-insensitive-raw",
				Action: "block-action",
				Conditions: &config.RuleConditions{
					Operator: "OR",
					Matches: []config.MatchCondition{
						{
							Type:            "path",
							Match:           "contains",
							Value:           "//WP-LOGIN",
							RawMatch:        true,
							CaseInsensitive: true,
						},
					},
				},
			},
		},
		actions: map[string]*config.RuleAction{
			"block-action": {
				Action:  "block",
				Status:  403,
				Message: "Forbidden",
			},
		},
	}

	rm := NewRulesMiddleware(configMgr)

	tests := []struct {
		name        string
		path        string
		shouldBlock bool
	}{
		{
			name:        "lowercase double slash matches",
			path:        "//wp-login.php",
			shouldBlock: true,
		},
		{
			name:        "uppercase double slash matches",
			path:        "//WP-LOGIN.php",
			shouldBlock: true,
		},
		{
			name:        "mixed case double slash matches",
			path:        "//Wp-LoGiN.php",
			shouldBlock: true,
		},
		{
			name:        "single slash does not match",
			path:        "/wp-login.php",
			shouldBlock: false,
		},
		{
			name:        "normalized would not match",
			path:        "//wp-admin.php",
			shouldBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.URL.Path = tt.path
			rec := httptest.NewRecorder()

			var handlerCalled bool
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			rm.Handle(rec, req, nextHandler)

			if tt.shouldBlock {
				if handlerCalled {
					t.Errorf("Expected request to be blocked but handler was called for path: %s", tt.path)
				}
			} else {
				if !handlerCalled {
					t.Errorf("Expected request to pass but handler was not called for path: %s", tt.path)
				}
			}
		})
	}
}
