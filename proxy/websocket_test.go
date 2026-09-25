package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"flowguard/config"
	"flowguard/middleware"

	"github.com/gorilla/websocket"
)

type telemetryUpgradeBody struct {
	reader     *bytes.Reader
	written    bytes.Buffer
	closes     atomic.Int32
	halfCloses atomic.Int32
}

func (b *telemetryUpgradeBody) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

func (b *telemetryUpgradeBody) Write(p []byte) (int, error) {
	return b.written.Write(p)
}

func (b *telemetryUpgradeBody) Close() error {
	b.closes.Add(1)
	return nil
}

func (b *telemetryUpgradeBody) CloseWrite() error {
	b.halfCloses.Add(1)
	return nil
}

func TestUpstreamTelemetryPreservesUpgradeBody(t *testing.T) {
	server := NewServer(&ServerConfig{scheme: "http", bindAddr: "192.0.2.45", bindPort: "11443"})
	underlying := &telemetryUpgradeBody{reader: bytes.NewReader([]byte("server-data"))}
	transport := &upstreamRetryTransport{
		server: server,
		next: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusSwitchingProtocols,
				Header:     http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}},
				Body:       underlying,
				Request:    req,
			}, nil
		}),
	}
	req := mustNewRequest(t, http.MethodGet, "http://app.example.test/socket", nil)
	req = req.WithContext(middleware.ContextWithUpstreamTelemetry(req.Context()))

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	connection, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("upgrade body %T is not writable", resp.Body)
	}
	if _, err := connection.Write([]byte("client-data")); err != nil {
		t.Fatalf("write upgrade body: %v", err)
	}
	data, err := io.ReadAll(connection)
	if err != nil || string(data) != "server-data" {
		t.Fatalf("read upgrade body = %q, %v", data, err)
	}
	closeWriter, ok := connection.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("upgrade body %T lost CloseWrite", connection)
	}
	if err := closeWriter.CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close upgrade body: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close upgrade body again: %v", err)
	}

	if got := underlying.written.String(); got != "client-data" {
		t.Fatalf("written data = %q", got)
	}
	if underlying.closes.Load() != 1 || underlying.halfCloses.Load() != 1 {
		t.Fatalf("close calls = %d, half-close calls = %d", underlying.closes.Load(), underlying.halfCloses.Load())
	}
	if server.activeUpstream.Load() != 0 {
		t.Fatalf("active upstream requests = %d", server.activeUpstream.Load())
	}
	snapshot := middleware.GetUpstreamSnapshot(req)
	if snapshot == nil || snapshot.Attempts != 1 || snapshot.Outcome != "success" {
		t.Fatalf("upstream snapshot = %+v", snapshot)
	}
}

type websocketLogEntry struct {
	ID        string `json:"_id"`
	StreamID  string `json:"stream_id"`
	WebSocket struct {
		Phase string `json:"phase"`
	} `json:"websocket"`
	Response struct {
		Status      int      `json:"status"`
		TimeMS      int64    `json:"time_ms"`
		HeaderNames []string `json:"header_names"`
	} `json:"response"`
	Upstream struct {
		Attempts int    `json:"attempts"`
		Outcome  string `json:"outcome"`
		TotalMS  int64  `json:"total_ms"`
	} `json:"upstream"`
}

func readWebSocketLogEntries(path string) ([]websocketLogEntry, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	entries := make([]websocketLogEntry, 0, len(lines))
	for _, line := range lines {
		var entry websocketLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func waitForWebSocketLogEntries(t *testing.T, path string, want int) []websocketLogEntry {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, err := readWebSocketLogEntries(path)
		if err == nil && len(entries) >= want {
			return entries
		}
		if time.Now().After(deadline) {
			t.Fatalf("log entries: got %d, want %d, last error: %v", len(entries), want, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWebSocketProxyLogsOpenAndCloseWithFinalTelemetry(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/plain" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade backend connection: %v", err)
			return
		}
		defer conn.Close()
		for {
			messageType, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(messageType, data); err != nil {
				return
			}
		}
	}))
	defer backend.Close()

	logPath := filepath.Join(t.TempDir(), "requests.log")
	configMgr := newProxyTestConfigManager(t, config.Config{
		Logging: &config.LoggingConfig{Sinks: map[string]map[string]interface{}{
			"websocket_test": {"type": "file", "path": logPath},
		}},
	})
	t.Cleanup(configMgr.Stop)
	logging := middleware.NewLoggingMiddleware(configMgr)
	t.Cleanup(logging.Stop)
	chain := middleware.NewChain()
	chain.Add(middleware.NewTimingMiddleware())
	chain.Add(logging)

	server := NewServer(&ServerConfig{scheme: "http", bindAddr: "127.0.0.1", bindPort: "0", middleware: chain})
	backendTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, backend.Listener.Addr().String())
		},
	}
	defer backendTransport.CloseIdleConnections()
	server.upstreamTransport = &upstreamRetryTransport{
		server: server,
		next: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/broken-socket" {
				return &http.Response{
					StatusCode: http.StatusSwitchingProtocols,
					Header:     http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}},
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    req,
				}, nil
			}
			return backendTransport.RoundTrip(req)
		}),
	}
	front := httptest.NewServer(http.HandlerFunc(server.handleRequest))
	defer front.Close()

	dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	websocketURL := "ws" + strings.TrimPrefix(front.URL, "http")
	conn, response, err := dialer.Dial(websocketURL+"/socket", nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("websocket status = %d", response.StatusCode)
	}

	entries := waitForWebSocketLogEntries(t, logPath, 1)
	if len(entries) != 1 || entries[0].WebSocket.Phase != "open" || entries[0].Response.Status != http.StatusSwitchingProtocols {
		t.Fatalf("open log entries = %+v", entries)
	}
	if !slices.Contains(entries[0].Response.HeaderNames, "upgrade") {
		t.Fatalf("open log lacks upgrade response header: %+v", entries[0].Response.HeaderNames)
	}
	if entries[0].Upstream.Attempts != 1 || entries[0].Upstream.Outcome != "" {
		t.Fatalf("open upstream telemetry = %+v", entries[0].Upstream)
	}
	if server.activeUpstream.Load() != 1 {
		t.Fatalf("active upstream requests while open = %d", server.activeUpstream.Load())
	}

	if err := conn.WriteMessage(websocket.TextMessage, []byte("synthetic websocket payload")); err != nil {
		t.Fatalf("write websocket message: %v", err)
	}
	_, echoed, err := conn.ReadMessage()
	if err != nil || string(echoed) != "synthetic websocket payload" {
		t.Fatalf("echoed message = %q, %v", echoed, err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second)); err != nil {
		t.Fatalf("close websocket: %v", err)
	}
	_, _, _ = conn.ReadMessage()
	_ = conn.Close()

	entries = waitForWebSocketLogEntries(t, logPath, 2)
	if len(entries) != 2 || entries[1].WebSocket.Phase != "close" || entries[1].Response.Status != http.StatusSwitchingProtocols {
		t.Fatalf("closed websocket logs = %+v", entries)
	}
	if entries[0].StreamID == "" || entries[0].StreamID != entries[1].StreamID || entries[0].ID == entries[1].ID {
		t.Fatalf("websocket log identity mismatch: open=%+v close=%+v", entries[0], entries[1])
	}
	if entries[1].Response.TimeMS < entries[0].Response.TimeMS || entries[1].Upstream.Outcome != "success" || entries[1].Upstream.TotalMS == 0 {
		t.Fatalf("close timing and telemetry = %+v", entries[1])
	}
	if server.activeUpstream.Load() != 0 {
		t.Fatalf("active upstream requests after close = %d", server.activeUpstream.Load())
	}

	_, failedResponse, err := dialer.Dial(websocketURL+"/broken-socket", nil)
	if err == nil {
		t.Fatal("broken upgrade unexpectedly succeeded")
	}
	if failedResponse == nil || failedResponse.StatusCode != http.StatusBadGateway {
		t.Fatalf("broken upgrade response = %+v, error = %v", failedResponse, err)
	}
	failedResponse.Body.Close()
	plainResponse, err := http.Get(front.URL + "/plain")
	if err != nil {
		t.Fatalf("plain request: %v", err)
	}
	plainResponse.Body.Close()
	if plainResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("plain response status = %d", plainResponse.StatusCode)
	}
	entries = waitForWebSocketLogEntries(t, logPath, 4)
	if len(entries) != 4 || entries[2].WebSocket.Phase != "" || entries[2].Response.Status != http.StatusBadGateway || entries[3].WebSocket.Phase != "" || entries[3].Response.Status != http.StatusNoContent {
		t.Fatalf("failed upgrade and ordinary request logs = %+v", entries)
	}
	if server.activeUpstream.Load() != 0 {
		t.Fatalf("active upstream requests after all requests = %d", server.activeUpstream.Load())
	}
}
