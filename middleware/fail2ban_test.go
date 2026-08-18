package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"flowguard/logger"
)

type staticFail2BanMatcher map[string][]string

func (m staticFail2BanMatcher) MatchingJails(ip string) []string {
	return m[ip]
}

func TestFail2BanMiddlewareReturnsStandardBlockResponseAndLogsJails(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "requests.log")
	loggerManager := logger.NewManager("FlowGuard/test")
	if err := loggerManager.UpdateSinks(map[string]map[string]interface{}{
		"file": {"type": "file", "path": logPath},
	}); err != nil {
		t.Fatalf("configure logger: %v", err)
	}
	loggingMiddleware := &LoggingMiddleware{loggerManager: loggerManager, enabled: true, version: "test"}
	blockingMiddleware := NewFail2BanMiddleware(staticFail2BanMatcher{
		"192.0.2.81": {"repeat-offender", "web-scan"},
	})
	req := httptest.NewRequest(http.MethodGet, "https://example.test/private", nil)
	req.Header.Set("Accept", "text/html")
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyClientIP, "192.0.2.81"))
	w := httptest.NewRecorder()
	nextCalled := false

	timingMiddleware := NewTimingMiddleware()
	timingMiddleware.Handle(w, req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loggingMiddleware.Handle(w, r, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			blockingMiddleware.Handle(w, r, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			}))
		}))
	}))
	if nextCalled {
		t.Fatal("blocked request reached the next handler")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("response status = %d, want %d", w.Code, http.StatusForbidden)
	}
	streamID := w.Header().Get("FG-Stream")
	if streamID == "" {
		t.Fatal("blocked response did not include an FG-Stream header")
	}
	if !strings.Contains(w.Body.String(), streamID) {
		t.Fatalf("blocked response did not contain stream ID %q", streamID)
	}
	if got := w.Header().Get("Via"); got != "1.1 flowguard" {
		t.Fatalf("Via header = %q", got)
	}
	if err := loggerManager.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var entry struct {
		StreamID string `json:"stream_id"`
		Rule     struct {
			Result string `json:"result"`
		} `json:"rule"`
		Response struct {
			Status int `json:"status"`
		} `json:"response"`
		Fail2Ban RequestLogEntryFail2BanInfo `json:"fail2ban"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatalf("decode log: %v", err)
	}
	if entry.Rule.Result != "block" || entry.Response.Status != http.StatusForbidden {
		t.Fatalf("unexpected block result: rule=%q status=%d", entry.Rule.Result, entry.Response.Status)
	}
	if entry.StreamID != streamID {
		t.Fatalf("logged stream ID = %q, response stream ID = %q", entry.StreamID, streamID)
	}
	if !reflect.DeepEqual(entry.Fail2Ban.Jails, []string{"repeat-offender", "web-scan"}) {
		t.Fatalf("logged jails = %#v", entry.Fail2Ban.Jails)
	}
}

func TestFail2BanMiddlewarePassesUnlistedClient(t *testing.T) {
	middleware := NewFail2BanMiddleware(staticFail2BanMatcher{})
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyClientIP, "203.0.113.92"))
	called := false
	middleware.Handle(httptest.NewRecorder(), req, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	if !called {
		t.Fatal("unlisted request did not reach the next handler")
	}
}
