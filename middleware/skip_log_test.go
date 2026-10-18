package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.chief.tools/flowguard-proxy/config"
	"go.chief.tools/flowguard-proxy/logger"
)

func skipLogTestRule(id, action string, sortOrder int, path string) *config.Rule {
	return &config.Rule{
		ID:        id,
		Action:    action,
		SortOrder: testIntPtr(sortOrder),
		Conditions: &config.RuleConditions{
			Matches: []config.MatchCondition{{Type: "path", Match: "equals", Value: path}},
		},
	}
}

// countLoggedRequests sends one request through the logging and rules
// middleware and returns how many log entries it produced.
func countLoggedRequests(t *testing.T, rules map[string]*config.Rule, path string, upstream http.HandlerFunc) int {
	t.Helper()

	logPath := filepath.Join(t.TempDir(), "requests.log")
	loggerManager := logger.NewManager("FlowGuard/test")
	if err := loggerManager.UpdateSinks(map[string]map[string]interface{}{
		"skip_log_test": {"type": "file", "path": logPath},
	}); err != nil {
		t.Fatalf("configure test logger: %v", err)
	}
	lm := &LoggingMiddleware{loggerManager: loggerManager, enabled: true, version: "test"}

	rm := NewRulesMiddleware(&MockConfigProvider{
		rules: rules,
		actions: map[string]*config.RuleAction{
			"skip":  {ID: "skip", Action: "skip_log"},
			"log":   {ID: "log", Action: "log"},
			"allow": {ID: "allow", Action: "allow"},
			"block": {ID: "block", Action: "block", Status: http.StatusForbidden},
		},
	})
	defer rm.Stop()

	req := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
	func() {
		defer func() {
			if recovered := recover(); recovered != nil && recovered != http.ErrAbortHandler {
				panic(recovered)
			}
		}()
		lm.Handle(httptest.NewRecorder(), req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rm.Handle(w, r, upstream)
		}))
	}()
	if err := loggerManager.Close(); err != nil {
		t.Fatalf("close test logger: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("read request log: %v", err)
	}
	if trimmed := strings.TrimSpace(string(data)); trimmed != "" {
		return len(strings.Split(trimmed, "\n"))
	}
	return 0
}

func TestSkipLogAction(t *testing.T) {
	respond := func(status int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }
	}

	tests := []struct {
		name     string
		rules    map[string]*config.Rule
		path     string
		upstream http.HandlerFunc
		wantLogs int
	}{
		{
			name:     "successful request is not logged",
			rules:    map[string]*config.Rule{"healthz": skipLogTestRule("healthz", "skip", 0, "/healthz")},
			path:     "/healthz",
			upstream: respond(http.StatusOK),
			wantLogs: 0,
		},
		{
			name:     "redirect is not logged",
			rules:    map[string]*config.Rule{"healthz": skipLogTestRule("healthz", "skip", 0, "/healthz")},
			path:     "/healthz",
			upstream: respond(http.StatusFound),
			wantLogs: 0,
		},
		{
			name:     "other paths are logged",
			rules:    map[string]*config.Rule{"healthz": skipLogTestRule("healthz", "skip", 0, "/healthz")},
			path:     "/login",
			upstream: respond(http.StatusOK),
			wantLogs: 1,
		},
		{
			name:     "upstream error is logged",
			rules:    map[string]*config.Rule{"healthz": skipLogTestRule("healthz", "skip", 0, "/healthz")},
			path:     "/healthz",
			upstream: respond(http.StatusBadGateway),
			wantLogs: 1,
		},
		{
			name:     "client error is logged",
			rules:    map[string]*config.Rule{"healthz": skipLogTestRule("healthz", "skip", 0, "/healthz")},
			path:     "/healthz",
			upstream: respond(http.StatusNotFound),
			wantLogs: 1,
		},
		{
			name:  "aborted request is logged",
			rules: map[string]*config.Rule{"healthz": skipLogTestRule("healthz", "skip", 0, "/healthz")},
			path:  "/healthz",
			upstream: func(_ http.ResponseWriter, r *http.Request) {
				RecordResponseStatus(r, 444)
				panic(http.ErrAbortHandler)
			},
			wantLogs: 1,
		},
		{
			name: "later block rule still applies and is logged",
			rules: map[string]*config.Rule{
				"healthz": skipLogTestRule("healthz", "skip", 0, "/healthz"),
				"deny":    skipLogTestRule("deny", "block", 1, "/healthz"),
			},
			path:     "/healthz",
			upstream: respond(http.StatusOK),
			wantLogs: 1,
		},
		{
			name: "later log rule is logged",
			rules: map[string]*config.Rule{
				"healthz": skipLogTestRule("healthz", "skip", 0, "/healthz"),
				"audit":   skipLogTestRule("audit", "log", 1, "/healthz"),
			},
			path:     "/healthz",
			upstream: respond(http.StatusOK),
			wantLogs: 1,
		},
		{
			name: "earlier log rule is logged",
			rules: map[string]*config.Rule{
				"audit":   skipLogTestRule("audit", "log", 0, "/healthz"),
				"healthz": skipLogTestRule("healthz", "skip", 1, "/healthz"),
			},
			path:     "/healthz",
			upstream: respond(http.StatusOK),
			wantLogs: 1,
		},
		{
			name: "later allow rule is not logged",
			rules: map[string]*config.Rule{
				"healthz": skipLogTestRule("healthz", "skip", 0, "/healthz"),
				"trusted": skipLogTestRule("trusted", "allow", 1, "/healthz"),
			},
			path:     "/healthz",
			upstream: respond(http.StatusOK),
			wantLogs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := countLoggedRequests(t, tt.rules, tt.path, tt.upstream); got != tt.wantLogs {
				t.Fatalf("got %d log entries, want %d", got, tt.wantLogs)
			}
		})
	}
}
