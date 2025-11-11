package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"flowguard/config"
)

// TestHeaderMatching tests the new header matching functionality with the Key field
func TestHeaderMatching(t *testing.T) {
	tests := []struct {
		name           string
		headerKey      string
		headerValue    string
		matchCondition config.MatchCondition
		requestHeaders map[string]string
		expected       bool
	}{
		{
			name:        "Header exists - should match",
			headerKey:   "X-API-Key",
			headerValue: "",
			matchCondition: config.MatchCondition{
				Type:  "header",
				Key:   "X-API-Key",
				Match: "exists",
			},
			requestHeaders: map[string]string{
				"X-API-Key": "secret-key",
			},
			expected: true,
		},
		{
			name:        "Header missing - should match",
			headerKey:   "X-API-Key",
			headerValue: "",
			matchCondition: config.MatchCondition{
				Type:  "header",
				Key:   "X-API-Key",
				Match: "missing",
			},
			requestHeaders: map[string]string{
				"Authorization": "Bearer token",
			},
			expected: true,
		},
		{
			name:        "Header equals - should match",
			headerKey:   "Authorization",
			headerValue: "Bearer secret",
			matchCondition: config.MatchCondition{
				Type:  "header",
				Key:   "Authorization",
				Match: "equals",
				Value: "Bearer secret",
			},
			requestHeaders: map[string]string{
				"Authorization": "Bearer secret",
			},
			expected: true,
		},
		{
			name:        "Header equals - should not match",
			headerKey:   "Authorization",
			headerValue: "Bearer wrong",
			matchCondition: config.MatchCondition{
				Type:  "header",
				Key:   "Authorization",
				Match: "equals",
				Value: "Bearer secret",
			},
			requestHeaders: map[string]string{
				"Authorization": "Bearer wrong",
			},
			expected: false,
		},
		{
			name:        "Header contains - should match",
			headerKey:   "User-Agent",
			headerValue: "bot",
			matchCondition: config.MatchCondition{
				Type:            "header",
				Key:             "User-Agent",
				Match:           "contains",
				Value:           "bot",
				CaseInsensitive: true,
			},
			requestHeaders: map[string]string{
				"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)",
			},
			expected: true,
		},
		{
			name:        "Header starts-with - should match",
			headerKey:   "Authorization",
			headerValue: "Bearer",
			matchCondition: config.MatchCondition{
				Type:  "header",
				Key:   "Authorization",
				Match: "starts-with",
				Value: "Bearer ",
			},
			requestHeaders: map[string]string{
				"Authorization": "Bearer token123",
			},
			expected: true,
		},
		{
			name:        "Header ends-with - should match",
			headerKey:   "Content-Type",
			headerValue: "json",
			matchCondition: config.MatchCondition{
				Type:  "header",
				Key:   "Content-Type",
				Match: "ends-with",
				Value: "json",
			},
			requestHeaders: map[string]string{
				"Content-Type": "application/json",
			},
			expected: true,
		},
		{
			name:        "Header in list - should match",
			headerKey:   "X-Custom",
			headerValue: "",
			matchCondition: config.MatchCondition{
				Type:   "header",
				Key:    "X-Custom",
				Match:  "in",
				Values: []string{"value1", "value2", "value3"},
			},
			requestHeaders: map[string]string{
				"X-Custom": "value2",
			},
			expected: true,
		},
		{
			name:        "Header not-in list - should match",
			headerKey:   "X-Custom",
			headerValue: "",
			matchCondition: config.MatchCondition{
				Type:   "header",
				Key:    "X-Custom",
				Match:  "not-in",
				Values: []string{"bad1", "bad2", "bad3"},
			},
			requestHeaders: map[string]string{
				"X-Custom": "good-value",
			},
			expected: true,
		},
		{
			name:        "Header case insensitive equals - should match",
			headerKey:   "X-Custom",
			headerValue: "TEST",
			matchCondition: config.MatchCondition{
				Type:            "header",
				Key:             "X-Custom",
				Match:           "equals",
				Value:           "test",
				CaseInsensitive: true,
			},
			requestHeaders: map[string]string{
				"X-Custom": "TEST",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RulesMiddleware{}

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			for k, v := range tt.requestHeaders {
				req.Header.Set(k, v)
			}

			// Evaluate the match
			result := rm.evaluateMatch(req, &tt.matchCondition)

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestHeaderMatchingWithoutKey tests that header matching fails gracefully when Key is missing
func TestHeaderMatchingWithoutKey(t *testing.T) {
	rm := &RulesMiddleware{}

	matchCondition := config.MatchCondition{
		Type:  "header",
		Match: "equals",
		Value: "some-value",
		// Key field is intentionally missing
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Some-Header", "some-value")

	// Should return false and log an error when Key is missing
	result := rm.evaluateMatch(req, &matchCondition)
	if result != false {
		t.Error("Expected false when header Key field is missing")
	}
}

// TestHeaderMatchingIntegration tests header matching in a full middleware flow
func TestHeaderMatchingIntegration(t *testing.T) {
	configProvider := &MockConfigProvider{
		rules: map[string]*config.Rule{
			"block_bad_auth": {
				ID:     "block_bad_auth",
				Action: "block_action",
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{
							Type:  "header",
							Key:   "Authorization",
							Match: "equals",
							Value: "bad-token",
						},
					},
				},
			},
			"require_api_key": {
				ID:     "require_api_key",
				Action: "block_no_key",
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{
							Type:  "header",
							Key:   "X-API-Key",
							Match: "missing",
						},
					},
				},
			},
		},
		actions: map[string]*config.RuleAction{
			"block_action": {
				Action:  "block",
				Status:  403,
				Message: "Forbidden",
			},
			"block_no_key": {
				Action:  "block",
				Status:  401,
				Message: "API key required",
			},
		},
	}

	rm := NewRulesMiddleware(configProvider)
	defer rm.Stop()

	handlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	// Test 1: Request with bad auth token should be blocked
	t.Run("Block bad auth token", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "bad-token")
		req.Header.Set("X-API-Key", "valid-key")
		w := httptest.NewRecorder()

		rm.Handle(w, req, nextHandler)

		if handlerCalled {
			t.Error("Handler should not be called for blocked request")
		}
		if w.Code != 403 {
			t.Errorf("Expected 403 Forbidden, got %d", w.Code)
		}
	})

	// Test 2: Request without API key should be blocked
	t.Run("Block missing API key", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer good-token")
		// X-API-Key header is intentionally missing
		w := httptest.NewRecorder()

		rm.Handle(w, req, nextHandler)

		if handlerCalled {
			t.Error("Handler should not be called for blocked request")
		}
		if w.Code != 401 {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
		if w.Body.String() != "API key required\n" {
			t.Errorf("Expected 'API key required' message, got: %s", w.Body.String())
		}
	})

	// Test 3: Request with valid headers should pass
	t.Run("Allow valid request", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer good-token")
		req.Header.Set("X-API-Key", "valid-key")
		w := httptest.NewRecorder()

		rm.Handle(w, req, nextHandler)

		if !handlerCalled {
			t.Error("Handler should be called for valid request")
		}
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", w.Code)
		}
	})
}
