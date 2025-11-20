package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"flowguard/config"
)

func TestRulesMiddleware_LogAction_Basic(t *testing.T) {
	// Create mock config provider with a simple log action
	configProvider := &MockConfigProvider{
		rules: map[string]*config.Rule{
			"log_rule": {
				ID:     "log_rule",
				Action: "log_action",
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{
							Type:  "path",
							Match: "starts-with",
							Value: "/api",
						},
					},
				},
			},
		},
		actions: map[string]*config.RuleAction{
			"log_action": {
				Action:  "log",
				Message: "API request logged",
			},
		},
	}

	rm := NewRulesMiddleware(configProvider)
	defer rm.Stop()

	handlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		// Verify that the rule was matched and marked as "log"
		matchedRule := GetRuleMatched(r)
		if matchedRule == nil {
			t.Error("Expected rule to be matched in context")
		} else if matchedRule.ID != "log_rule" {
			t.Errorf("Expected matched rule ID 'log_rule', got '%s'", matchedRule.ID)
		}

		// Verify the result is "log"
		result := GetRuleResult(r)
		if result != "log" {
			t.Errorf("Expected rule result 'log', got '%s'", result)
		}

		// Verify the action is set
		matchedAction := GetActionMatched(r)
		if matchedAction == nil {
			t.Error("Expected action to be matched in context")
		} else if matchedAction.Action != "log" {
			t.Errorf("Expected matched action type 'log', got '%s'", matchedAction.Action)
		}

		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/users", nil)
	w := httptest.NewRecorder()

	rm.Handle(w, req, nextHandler)

	if !handlerCalled {
		t.Error("Handler should be called for log action")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}

func TestRulesMiddleware_LogAction_ContinuesProcessing(t *testing.T) {
	// Test that log action continues to evaluate subsequent rules
	configProvider := &MockConfigProvider{
		rules: map[string]*config.Rule{
			"log_rule_1": {
				ID:     "log_rule_1",
				Action: "log_action_1",
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{
							Type:  "path",
							Match: "starts-with",
							Value: "/",
						},
					},
				},
			},
			"log_rule_2": {
				ID:     "log_rule_2",
				Action: "log_action_2",
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{
							Type:  "path",
							Match: "contains",
							Value: "api",
						},
					},
				},
			},
		},
		actions: map[string]*config.RuleAction{
			"log_action_1": {
				Action:  "log",
				Message: "First log",
			},
			"log_action_2": {
				Action:  "log",
				Message: "Second log",
			},
		},
	}

	rm := NewRulesMiddleware(configProvider)
	defer rm.Stop()

	handlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		// The second rule should have overwritten the context
		matchedRule := GetRuleMatched(r)
		if matchedRule == nil {
			t.Error("Expected rule to be matched in context")
		} else if matchedRule.ID != "log_rule_2" {
			t.Errorf("Expected matched rule ID 'log_rule_2' (last matching log rule), got '%s'", matchedRule.ID)
		}

		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/users", nil)
	w := httptest.NewRecorder()

	rm.Handle(w, req, nextHandler)

	if !handlerCalled {
		t.Error("Handler should be called when only log actions match")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}

func TestRulesMiddleware_LogAction_OverriddenByBlock(t *testing.T) {
	// Test that a block action overrides a previous log action
	configProvider := &MockConfigProvider{
		rules: map[string]*config.Rule{
			"log_rule": {
				ID:     "log_rule",
				Action: "log_action",
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{
							Type:  "path",
							Match: "starts-with",
							Value: "/",
						},
					},
				},
			},
			"block_rule": {
				ID:     "block_rule",
				Action: "block_action",
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{
							Type:  "path",
							Match: "contains",
							Value: "admin",
						},
					},
				},
			},
		},
		actions: map[string]*config.RuleAction{
			"log_action": {
				Action:  "log",
				Message: "Request logged",
			},
			"block_action": {
				Action:  "block",
				Status:  403,
				Message: "Access denied",
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

	req := httptest.NewRequest("GET", "/admin/users", nil)
	w := httptest.NewRecorder()

	rm.Handle(w, req, nextHandler)

	if handlerCalled {
		t.Error("Handler should not be called when block action matches")
	}
	if w.Code != 403 {
		t.Errorf("Expected 403 Forbidden, got %d", w.Code)
	}

	body := w.Body.String()
	if body != "Access denied\n" {
		t.Errorf("Expected block message, got: %s", body)
	}
}

func TestRulesMiddleware_LogAction_OverriddenByAllow(t *testing.T) {
	// Test that an allow action overrides a previous log action
	configProvider := &MockConfigProvider{
		rules: map[string]*config.Rule{
			"log_rule": {
				ID:     "log_rule",
				Action: "log_action",
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{
							Type:  "path",
							Match: "starts-with",
							Value: "/",
						},
					},
				},
			},
			"allow_rule": {
				ID:     "allow_rule",
				Action: "allow_action",
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{
							Type:  "path",
							Match: "equals",
							Value: "/api/health",
						},
					},
				},
			},
			"block_rule": {
				ID:     "block_rule",
				Action: "block_action",
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{
							Type:  "path",
							Match: "starts-with",
							Value: "/api",
						},
					},
				},
			},
		},
		actions: map[string]*config.RuleAction{
			"log_action": {
				Action:  "log",
				Message: "Request logged",
			},
			"allow_action": {
				Action:  "allow",
				Message: "Explicitly allowed",
			},
			"block_action": {
				Action:  "block",
				Status:  403,
				Message: "API blocked",
			},
		},
	}

	rm := NewRulesMiddleware(configProvider)
	defer rm.Stop()

	handlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		// Verify that allow action overrode the log action
		matchedRule := GetRuleMatched(r)
		if matchedRule == nil {
			t.Error("Expected rule to be matched in context")
		} else if matchedRule.ID != "allow_rule" {
			t.Errorf("Expected matched rule ID 'allow_rule', got '%s'", matchedRule.ID)
		}

		// Verify the result is "proxy" (from allow action)
		result := GetRuleResult(r)
		if result != "proxy" {
			t.Errorf("Expected rule result 'proxy', got '%s'", result)
		}

		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()

	rm.Handle(w, req, nextHandler)

	if !handlerCalled {
		t.Error("Handler should be called when allow action matches")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}

func TestRulesMiddleware_LogAction_NoMatch(t *testing.T) {
	// Test that requests not matching log rules pass through normally
	configProvider := &MockConfigProvider{
		rules: map[string]*config.Rule{
			"log_rule": {
				ID:     "log_rule",
				Action: "log_action",
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{
							Type:  "path",
							Match: "starts-with",
							Value: "/api",
						},
					},
				},
			},
		},
		actions: map[string]*config.RuleAction{
			"log_action": {
				Action:  "log",
				Message: "API request logged",
			},
		},
	}

	rm := NewRulesMiddleware(configProvider)
	defer rm.Stop()

	handlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		// Verify no rule was matched
		matchedRule := GetRuleMatched(r)
		if matchedRule != nil {
			t.Errorf("Expected no matched rule, but got '%s'", matchedRule.ID)
		}

		// Result should default to "proxy"
		result := GetRuleResult(r)
		if result != "proxy" {
			t.Errorf("Expected default result 'proxy', got '%s'", result)
		}

		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/static/style.css", nil)
	w := httptest.NewRecorder()

	rm.Handle(w, req, nextHandler)

	if !handlerCalled {
		t.Error("Handler should be called for non-matching request")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}
