package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.chief.tools/flowguard-proxy/middleware"

	"github.com/gorilla/websocket"
)

func startShutdownTestServer(t *testing.T, backend *httptest.Server) *Server {
	t.Helper()

	server := NewServer(&ServerConfig{scheme: "http", bindAddr: "127.0.0.1", bindPort: "0", middleware: middleware.NewChain()})
	backendTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, backend.Listener.Addr().String())
		},
	}
	t.Cleanup(backendTransport.CloseIdleConnections)
	server.upstreamTransport = &upstreamRetryTransport{server: server, next: backendTransport}

	if err := server.Start(nil, make(chan error, 1)); err != nil {
		t.Fatalf("start server: %v", err)
	}

	return server
}

func TestServerShutdownClosesProxiedWebSockets(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade backend connection: %v", err)
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer backend.Close()

	server := startShutdownTestServer(t, backend)
	addr := server.listener.Addr().String()

	dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	conn, _, err := dialer.Dial("ws://"+addr+"/socket", nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	started := time.Now()
	server.Shutdown(ctx)
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("shutdown took %s with an open WebSocket", elapsed)
	}

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("expected WebSocket to be closed after shutdown")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("WebSocket was still open after shutdown")
	}
	if got := server.activeRequests.Load(); got != 0 {
		t.Fatalf("active requests after shutdown = %d", got)
	}
}

func TestServerShutdownClosesStreamingRequestsAfterDrainTimeout(t *testing.T) {
	streaming := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(streaming)
		<-r.Context().Done()
	}))
	defer backend.Close()

	server := startShutdownTestServer(t, backend)
	addr := server.listener.Addr().String()

	resp, err := http.Get("http://" + addr + "/events")
	if err != nil {
		t.Fatalf("start streaming request: %v", err)
	}
	defer resp.Body.Close()
	<-streaming

	drainTimeout := 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()

	started := time.Now()
	server.Shutdown(ctx)
	elapsed := time.Since(started)
	if elapsed < drainTimeout {
		t.Fatalf("shutdown returned after %s, before the %s drain timeout", elapsed, drainTimeout)
	}
	if elapsed > drainTimeout+activeRequestCloseTimeout {
		t.Fatalf("shutdown took %s, expected streaming request to be closed after the drain timeout", elapsed)
	}

	readDone := make(chan error, 1)
	go func() {
		_, err := resp.Body.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("expected streaming response to end after shutdown")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("streaming response was still open after shutdown")
	}
	if got := server.activeRequests.Load(); got != 0 {
		t.Fatalf("active requests after shutdown = %d", got)
	}
}

func TestManagerShutdownTimeoutDefaults(t *testing.T) {
	manager := &Manager{config: &Config{}}
	if got := manager.shutdownTimeout(); got != DefaultShutdownTimeout {
		t.Fatalf("default shutdown timeout = %s, want %s", got, DefaultShutdownTimeout)
	}

	manager.config.ShutdownTimeout = 3 * time.Second
	if got := manager.shutdownTimeout(); got != 3*time.Second {
		t.Fatalf("configured shutdown timeout = %s, want 3s", got)
	}
}

func TestServerShutdownWithoutActiveRequests(t *testing.T) {
	backend := httptest.NewServer(http.NotFoundHandler())
	defer backend.Close()

	server := startShutdownTestServer(t, backend)
	addr := server.listener.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)

	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("expected listener to be closed after shutdown, dial err = %v", err)
	}
}
