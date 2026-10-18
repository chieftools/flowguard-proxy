package flowguardcaddy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"go.chief.tools/flowguard-proxy/config"
	"go.chief.tools/flowguard-proxy/engine"
)

// writeTestConfig writes a configuration that blocks /blocked and logs every
// request to a file, and returns the config and log paths.
func writeTestConfig(t *testing.T) (string, string) {
	t.Helper()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "requests.log")
	cfg := map[string]any{
		"rules": map[string]any{
			"rule_block": map[string]any{
				"name":   "Block path",
				"action": "action_block",
				"conditions": map[string]any{
					"operator": "AND",
					"matches": []map[string]any{
						{"type": "path", "match": "equals", "value": "/blocked"},
					},
				},
			},
		},
		"actions": map[string]any{
			"action_block": map[string]any{"name": "Block", "action": "block"},
		},
		"logging": map[string]any{
			"sinks": map[string]any{
				"file": map[string]any{"type": "file", "path": logPath},
			},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return configPath, logPath
}

func newTestHandler(t *testing.T) (*Handler, func() []map[string]any) {
	t.Helper()

	configPath, logPath := writeTestConfig(t)
	configMgr, err := config.NewManager(configPath, "FlowGuard/test", "test", "", false)
	if err != nil {
		t.Fatalf("new config manager: %v", err)
	}
	e := engine.New(configMgr, engine.Options{})

	var stopped atomic.Bool
	stop := func() {
		if stopped.CompareAndSwap(false, true) {
			e.Stop()
		}
	}
	t.Cleanup(stop)

	readLog := func() []map[string]any {
		t.Helper()
		// Stopping the engine closes the sinks, which flushes the log.
		stop()
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("read request log: %v", err)
		}
		var entries []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var entry map[string]any
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatalf("decode request log line %q: %v", line, err)
			}
			entries = append(entries, entry)
		}
		return entries
	}

	return &Handler{engine: e, activeUpstream: new(atomic.Int64)}, readLog
}

func loggedStatus(t *testing.T, entry map[string]any) int {
	t.Helper()
	response, _ := entry["response"].(map[string]any)
	status, _ := response["status"].(float64)
	return int(status)
}

func TestHandlerPassesAllowedRequestsToNext(t *testing.T) {
	h, readLog := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "https://example.test/allowed", nil)
	req.Header.Set("FG-IPCountry", "NL")
	w := httptest.NewRecorder()

	var nextCalled bool
	var upstreamCountry, upstreamStream string
	err := h.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		upstreamCountry = r.Header.Get("FG-IPCountry")
		upstreamStream = r.Header.Get("FG-Stream")
		w.WriteHeader(http.StatusCreated)
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !nextCalled {
		t.Fatal("expected the allowed request to reach the next handler")
	}
	if upstreamCountry != "XX" {
		t.Fatalf("FG-IPCountry = %q, want the client's spoofed value replaced with XX", upstreamCountry)
	}
	if upstreamStream == "" || w.Header().Get("FG-Stream") != upstreamStream {
		t.Fatalf("FG-Stream request=%q response=%q, want the same stream ID", upstreamStream, w.Header().Get("FG-Stream"))
	}

	entries := readLog()
	if len(entries) != 1 || loggedStatus(t, entries[0]) != http.StatusCreated {
		t.Fatalf("unexpected log entries: %v", entries)
	}
	if _, ok := entries[0]["upstream"]; ok {
		t.Fatalf("expected no upstream telemetry without an upstream round trip: %v", entries[0]["upstream"])
	}
}

func TestHandlerBlocksMatchingRequests(t *testing.T) {
	h, readLog := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "https://example.test/blocked", nil)
	w := httptest.NewRecorder()

	err := h.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		t.Fatal("blocked request reached the next handler")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}

	entries := readLog()
	if len(entries) != 1 || loggedStatus(t, entries[0]) != http.StatusForbidden {
		t.Fatalf("unexpected log entries: %v", entries)
	}
}

func TestHandlerLogsCaddyErrorStatus(t *testing.T) {
	h, readLog := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "https://example.test/allowed", nil)
	upstreamErr := caddyhttp.Error(http.StatusBadGateway, errors.New("dial tcp: connection refused"))
	err := h.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return upstreamErr
	}))
	if !errors.Is(err, upstreamErr.Err) {
		t.Fatalf("ServeHTTP error = %v, want the next handler's error", err)
	}

	entries := readLog()
	if len(entries) != 1 || loggedStatus(t, entries[0]) != http.StatusBadGateway {
		t.Fatalf("unexpected log entries: %v", entries)
	}
}

func TestHandlerRecordsUpstreamTelemetry(t *testing.T) {
	h, readLog := newTestHandler(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	req := httptest.NewRequest(http.MethodGet, "https://example.test/allowed", nil)
	err := h.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// Caddy's reverse_proxy sends upstream requests with the incoming
		// request's context, which carries the trace.
		outbound, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstream.URL, nil)
		if err != nil {
			return err
		}
		resp, err := upstream.Client().Do(outbound)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	entries := readLog()
	if len(entries) != 1 {
		t.Fatalf("unexpected log entries: %v", entries)
	}
	upstreamInfo, _ := entries[0]["upstream"].(map[string]any)
	if upstreamInfo["attempts"] != float64(1) || upstreamInfo["outcome"] != "success" {
		t.Fatalf("unexpected upstream telemetry: %v", entries[0]["upstream"])
	}
}

func TestHandlerAttachesConnectionInfo(t *testing.T) {
	h, readLog := newTestHandler(t)

	ctx := connContext(context.Background(), nil)
	// A second flowguard handler on the same server registers the hook again.
	ctx = connContext(ctx, nil)
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "https://example.test/allowed", nil).WithContext(ctx)
		if err := h.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			return nil
		})); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
	}

	entries := readLog()
	if len(entries) != 2 {
		t.Fatalf("unexpected log entries: %v", entries)
	}
	first, _ := entries[0]["connection"].(map[string]any)
	second, _ := entries[1]["connection"].(map[string]any)
	if first["id"] == nil || first["id"] != second["id"] || second["requests"] != float64(2) {
		t.Fatalf("expected both requests on one connection: first=%v second=%v", first, second)
	}
}

func TestErrorStatus(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{caddyhttp.Error(http.StatusBadGateway, errors.New("down")), http.StatusBadGateway},
		{caddyhttp.HandlerError{Err: errors.New("no status")}, http.StatusInternalServerError},
		{errors.New("plain"), http.StatusInternalServerError},
	} {
		if got := errorStatus(tc.err); got != tc.want {
			t.Errorf("errorStatus(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}
