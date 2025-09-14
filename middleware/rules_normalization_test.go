package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"flowguard/config"
)

// mockConfigManager implements a simple mock for testing
type mockConfigManager struct {
	mu      sync.RWMutex
	rules   map[string]*config.Rule
	actions map[string]*config.RuleAction
}

func (m *mockConfigManager) GetRules() map[string]*config.Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rules
}

func (m *mockConfigManager) GetActions() map[string]*config.RuleAction {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.actions
}

func TestRulesMiddleware_PathNormalization(t *testing.T) {
	// Create a mock config manager with rules
	configMgr := &mockConfigManager{
		rules: map[string]*config.Rule{
			"block-admin": {
				ID:     "block-admin",
				Action: "block-action",
				Conditions: &config.RuleConditions{
					Operator: "OR",
					Matches: []config.MatchCondition{
						{
							Type:  "path",
							Match: "equals",
							Value: "/admin/panel",
						},
					},
				},
			},
			"block-api-v1": {
				ID:     "block-api-v1",
				Action: "block-action",
				Conditions: &config.RuleConditions{
					Operator: "OR",
					Matches: []config.MatchCondition{
						{
							Type:  "path",
							Match: "starts-with",
							Value: "/api/v1/",
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

	// Create the middleware
	rm := NewRulesMiddleware(configMgr)

	tests := []struct {
		name        string
		path        string
		shouldBlock bool
		description string
	}{
		// Test backslash conversion
		{
			name:        "backslashes converted to match",
			path:        "\\admin\\panel",
			shouldBlock: true,
			description: "Backslashes should be converted to forward slashes",
		},
		{
			name:        "mixed slashes normalized",
			path:        "/admin\\panel",
			shouldBlock: true,
			description: "Mixed slashes should be normalized",
		},

		// Test successive slash merging
		{
			name:        "double slashes merged",
			path:        "//admin//panel",
			shouldBlock: true,
			description: "Double slashes should be merged",
		},
		{
			name:        "triple slashes merged",
			path:        "///admin///panel",
			shouldBlock: true,
			description: "Multiple slashes should be merged",
		},

		// Test dot segment removal
		{
			name:        "dot segments removed",
			path:        "/test/../admin/panel",
			shouldBlock: true,
			description: "Dot segments should be removed",
		},
		{
			name:        "single dots removed",
			path:        "/admin/./panel",
			shouldBlock: true,
			description: "Single dot segments should be removed",
		},
		{
			name:        "complex path traversal",
			path:        "/test/foo/../../admin/panel",
			shouldBlock: true,
			description: "Complex path traversal should be normalized",
		},

		// Test percent decoding
		{
			name:        "percent encoded letters decoded",
			path:        "/%61%64%6D%69%6E/panel", // 'admin' encoded
			shouldBlock: true,
			description: "Percent-encoded unreserved characters should be decoded",
		},
		{
			name:        "mixed encoding",
			path:        "/ad%6Din/panel", // 'admin' partially encoded
			shouldBlock: true,
			description: "Mixed encoded/plain text should work",
		},

		// Test combined normalizations
		{
			name:        "all normalizations combined",
			path:        "\\\\test\\\\..//%61%64%6D%69%6E//panel",
			shouldBlock: true,
			description: "All normalizations should work together",
		},

		// Test starts-with matching with normalization
		{
			name:        "starts-with double slashes",
			path:        "//api//v1//users",
			shouldBlock: true,
			description: "Starts-with should work with normalized paths",
		},
		{
			name:        "starts-with backslashes",
			path:        "\\api\\v1\\users",
			shouldBlock: true,
			description: "Starts-with should work with backslash normalization",
		},
		{
			name:        "starts-with dot segments",
			path:        "/test/../api/v1/users",
			shouldBlock: true,
			description: "Starts-with should work with dot segment removal",
		},

		// Test non-matching paths
		{
			name:        "different path",
			path:        "/user/profile",
			shouldBlock: false,
			description: "Non-matching paths should not be blocked",
		},
		{
			name:        "similar but different",
			path:        "/adminpanel", // No slash separator
			shouldBlock: false,
			description: "Similar paths without exact match should not be blocked",
		},
		{
			name:        "api v2 not blocked",
			path:        "/api/v2/users",
			shouldBlock: false,
			description: "Different API version should not be blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test request - use a valid URL and then manually set the path
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.URL.Path = tt.path
			rec := httptest.NewRecorder()

			// Create a test handler that sets a success flag
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

func TestRulesMiddleware_NormalizationDoesNotAffectForwarding(t *testing.T) {
	// This test ensures that normalization is only used for matching,
	// not for the actual forwarded request

	// Create a mock config manager with a rule that would never match
	configMgr := &mockConfigManager{
		rules: map[string]*config.Rule{
			"never-match": {
				ID:     "never-match",
				Action: "block-action",
				Conditions: &config.RuleConditions{
					Operator: "OR",
					Matches: []config.MatchCondition{
						{
							Type:  "path",
							Match: "equals",
							Value: "/this-will-never-match-anything-12345",
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

	// Test various unnormalized paths
	testPaths := []string{
		"//api//v1//users",
		"\\api\\v1\\users",
		"/api/../v1/./users",
		"/api/%61%70%69/users",
	}

	for _, path := range testPaths {
		t.Run("path: "+path, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.URL.Path = path
			rec := httptest.NewRecorder()

			// Create a handler that captures the actual request path
			var capturedPath string
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			})

			// Execute the middleware
			rm.Handle(rec, req, nextHandler)

			// Verify the original path is preserved
			if capturedPath != path {
				t.Errorf("Expected forwarded path to be %q, got %q", path, capturedPath)
			}
		})
	}
}
