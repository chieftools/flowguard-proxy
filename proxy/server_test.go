package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"flowguard/middleware"
)

func TestServerStartReturnsBindErrorsSynchronously(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer occupied.Close()

	_, port, err := net.SplitHostPort(occupied.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	server := NewServer(&ServerConfig{
		scheme:     "http",
		bindAddr:   "127.0.0.1",
		bindPort:   port,
		middleware: middleware.NewChain(),
	})

	if err := server.Start(nil, make(chan error, 1)); err == nil {
		t.Fatal("expected bind error, got nil")
	}
}

func TestServerStartHTTPSStartsHTTP3AndShutsDown(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:     "https",
		bindAddr:   "127.0.0.1",
		bindPort:   "0",
		middleware: middleware.NewChain(),
	})

	errChan := make(chan error, 1)
	if err := server.Start(&tls.Config{}, errChan); err != nil {
		t.Fatalf("start: %v", err)
	}
	if server.http3Server == nil {
		t.Fatal("expected HTTP/3 server to be started for HTTPS")
	}
	if server.udpConn == nil {
		t.Fatal("expected UDP listener to be started for HTTP/3")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server.Shutdown(ctx)

	select {
	case err := <-errChan:
		t.Fatalf("unexpected serve error: %v", err)
	default:
	}
}

func TestHTTPSReverseProxyTransportAttemptsHTTP2(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:   "https",
		bindAddr: "127.0.0.1",
		bindPort: "443",
	})
	target, err := url.Parse("https://127.0.0.1")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	proxy := server.createReverseProxyWithHost(target, "example.com")
	transport, ok := proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", proxy.Transport)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatal("expected HTTPS upstream transport to attempt HTTP/2")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.ServerName != "example.com" {
		t.Fatalf("unexpected TLS server name: %#v", transport.TLSClientConfig)
	}
}

func TestReverseProxyPreservesOriginAltSvc(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:   "https",
		bindAddr: "127.0.0.1",
		bindPort: "443",
	})
	target, err := url.Parse("https://127.0.0.1")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	proxy := server.createReverseProxyWithHost(target, "example.com")
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp := &http.Response{
		Header: http.Header{
			"Alt-Svc": []string{`h3=":443"; ma=86400`},
		},
		ProtoMajor: 3,
		ProtoMinor: 0,
		Request:    req,
	}

	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("modify response: %v", err)
	}
	if got := resp.Header.Get("Alt-Svc"); got != `h3=":443"; ma=86400` {
		t.Fatalf("expected Alt-Svc to be preserved, got %q", got)
	}
}

func TestServerStartServesAndShutsDown(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:     "http",
		bindAddr:   "127.0.0.1",
		bindPort:   "0",
		middleware: middleware.NewChain(),
	})

	errChan := make(chan error, 1)
	if err := server.Start(nil, errChan); err != nil {
		t.Fatalf("start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server.Shutdown(ctx)

	select {
	case err := <-errChan:
		t.Fatalf("unexpected serve error: %v", err)
	default:
	}
}
