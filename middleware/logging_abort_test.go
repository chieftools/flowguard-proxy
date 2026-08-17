package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"flowguard/logger"
)

func TestLoggingMiddlewareRecordsDeliberatelyAbortedRequest(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "requests.log")
	loggerManager := logger.NewManager("FlowGuard/test")
	if err := loggerManager.UpdateSinks(map[string]map[string]interface{}{
		"abort_test": {
			"type": "file",
			"path": logPath,
		},
	}); err != nil {
		t.Fatalf("configure test logger: %v", err)
	}

	lm := &LoggingMiddleware{
		loggerManager: loggerManager,
		enabled:       true,
		version:       "test",
	}
	req := httptest.NewRequest(http.MethodGet, "https://example.test/restricted", nil)
	w := httptest.NewRecorder()

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		lm.Handle(w, req, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			// ReverseProxy reports transport failures on a cloned outbound
			// request, so exercise the shared context recorder through a clone.
			RecordResponseStatus(r.Clone(r.Context()), 444)
			panic(http.ErrAbortHandler)
		}))
	}()
	if recovered != http.ErrAbortHandler {
		t.Fatalf("recovered panic = %v, want http.ErrAbortHandler", recovered)
	}
	if err := loggerManager.Close(); err != nil {
		t.Fatalf("close test logger: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read request log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("log lines = %d, want 1", len(lines))
	}
	var entry struct {
		Response struct {
			Status int `json:"status"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("decode request log: %v", err)
	}
	if entry.Response.Status != 444 {
		t.Fatalf("logged response status = %d, want 444", entry.Response.Status)
	}
	if w.Body.Len() != 0 || len(w.Header()) != 0 {
		t.Fatalf("unexpected HTTP response: headers=%v body=%q", w.Header(), w.Body.String())
	}
}
