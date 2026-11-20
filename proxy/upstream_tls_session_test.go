package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestUpstreamTransportsResumeBackendTLSSessions(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer backend.Close()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, backend.Listener.Addr().String())
	}
	request := func(t *testing.T, transport *http.Transport) bool {
		t.Helper()
		resp, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "https://site.test/", nil))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		transport.CloseIdleConnections()
		return resp.TLS.DidResume
	}

	t.Run("transparent transports of different clients", func(t *testing.T) {
		pool := newTransparentTransportPool(10, time.Minute, 1)
		first := transparentTestKey("192.0.2.1")
		first.scheme = "https"
		second := transparentTestKey("192.0.2.2")
		second.scheme = "https"

		if request(t, pool.transportWithDialer(first, dial, false)) {
			t.Fatal("expected the first client to do a full handshake")
		}
		if !request(t, pool.transportWithDialer(second, dial, false)) {
			t.Fatal("expected a new client to resume the backend TLS session")
		}
	})

	t.Run("header mode transport", func(t *testing.T) {
		server := NewServer(&ServerConfig{scheme: "https", bindAddr: "127.0.0.1", bindPort: "0"})
		transport := server.newOrdinaryUpstreamTransport(false)
		transport.DialContext = dial

		if request(t, transport) {
			t.Fatal("expected the first connection to do a full handshake")
		}
		if !request(t, transport) {
			t.Fatal("expected a new connection to resume the backend TLS session")
		}
	})
}
