package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"flowguard/config"
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

func TestServerStartHTTPSSkipsHTTP3WhenDisabled(t *testing.T) {
	protocols := config.ProtocolSettings{HTTP1: true, HTTP2: true, HTTP3: false}
	server := NewServer(&ServerConfig{
		scheme:     "https",
		bindAddr:   "127.0.0.1",
		bindPort:   "0",
		middleware: middleware.NewChain(),
		protocols:  &protocols,
	})

	errChan := make(chan error, 1)
	if err := server.Start(&tls.Config{}, errChan); err != nil {
		t.Fatalf("start: %v", err)
	}
	if server.http3Server != nil {
		t.Fatal("expected HTTP/3 server not to be started")
	}
	if server.udpConn != nil {
		t.Fatal("expected UDP listener not to be started")
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

func TestServerRecordsAndAttachesTCPJA4Fingerprint(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:     "https",
		bindAddr:   "127.0.0.1",
		bindPort:   "443",
		middleware: middleware.NewChain(),
	})

	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 51515}
	conn := &ja4Conn{Conn: fakeConn{localAddr: localAddr, remoteAddr: remoteAddr}}

	tlsConfig := server.tlsConfigWithJA4(&tls.Config{}, "t")
	_, err := tlsConfig.GetConfigForClient(&tls.ClientHelloInfo{
		Conn:              conn,
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
		Extensions:        []uint16{0x002b},
		SupportedVersions: []uint16{tls.VersionTLS13},
		ServerName:        "example.com",
		SupportedProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com/test", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.RemoteAddr = remoteAddr.String()
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, localAddr))
	req = req.WithContext(server.tcpConnContext(req.Context(), conn))

	req = server.withJA4Fingerprint(req)
	if got := middleware.GetJA4Fingerprint(req); got != "t13d0101h2_0f2cb44170f4_b9a491fefe05" {
		t.Fatalf("unexpected JA4 fingerprint: %q", got)
	}
}

func TestServerRecordsQUICJA4Fingerprint(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:     "https",
		bindAddr:   "127.0.0.1",
		bindPort:   "443",
		middleware: middleware.NewChain(),
	})

	localAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 51515}

	tlsConfig := server.tlsConfigWithJA4(&tls.Config{}, "q")
	_, err := tlsConfig.GetConfigForClient(&tls.ClientHelloInfo{
		Conn:              fakeConn{localAddr: localAddr, remoteAddr: remoteAddr},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
		Extensions:        []uint16{0x002b},
		SupportedVersions: []uint16{tls.VersionTLS13},
		SupportedProtos:   []string{"h3"},
	})
	if err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}

	if got := server.fingerprints.Get(localAddr.String(), remoteAddr.String()); got != "q13i0101h3_0f2cb44170f4_b9a491fefe05" {
		t.Fatalf("unexpected JA4 fingerprint: %q", got)
	}
}

type fakeConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c fakeConn) Read([]byte) (int, error)         { return 0, nil }
func (c fakeConn) Write([]byte) (int, error)        { return 0, nil }
func (c fakeConn) Close() error                     { return nil }
func (c fakeConn) LocalAddr() net.Addr              { return c.localAddr }
func (c fakeConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c fakeConn) SetDeadline(time.Time) error      { return nil }
func (c fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c fakeConn) SetWriteDeadline(time.Time) error { return nil }

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

func TestReverseProxyAddsHTTP3AltSvcWhenEnabled(t *testing.T) {
	protocols := config.ProtocolSettings{HTTP1: true, HTTP2: true, HTTP3: true}
	server := NewServer(&ServerConfig{
		scheme:    "https",
		bindAddr:  "127.0.0.1",
		bindPort:  "11443",
		redirPort: "443",
		protocols: &protocols,
		altSvc:    true,
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
		Header:     http.Header{},
		ProtoMajor: 2,
		ProtoMinor: 0,
		Request:    req,
	}

	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("modify response: %v", err)
	}
	if got := resp.Header.Get("Alt-Svc"); got != `h3=":443"; ma=86400` {
		t.Fatalf("expected HTTP/3 Alt-Svc to be added, got %q", got)
	}
}

func TestReverseProxyDoesNotDuplicateHTTP3AltSvc(t *testing.T) {
	protocols := config.ProtocolSettings{HTTP1: true, HTTP2: true, HTTP3: true}
	server := NewServer(&ServerConfig{
		scheme:    "https",
		bindAddr:  "127.0.0.1",
		bindPort:  "11443",
		redirPort: "443",
		protocols: &protocols,
		altSvc:    true,
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
			"Alt-Svc": []string{`h3=":443"; ma=3600`},
		},
		ProtoMajor: 2,
		ProtoMinor: 0,
		Request:    req,
	}

	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("modify response: %v", err)
	}
	values := resp.Header.Values("Alt-Svc")
	if len(values) != 1 || values[0] != `h3=":443"; ma=3600` {
		t.Fatalf("expected existing HTTP/3 Alt-Svc to be preserved without duplicate, got %v", values)
	}
}

func TestReverseProxyDoesNotAddHTTP3AltSvcWhenHTTP3Disabled(t *testing.T) {
	protocols := config.ProtocolSettings{HTTP1: true, HTTP2: true, HTTP3: false}
	server := NewServer(&ServerConfig{
		scheme:    "https",
		bindAddr:  "127.0.0.1",
		bindPort:  "11443",
		redirPort: "443",
		protocols: &protocols,
		altSvc:    true,
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
		Header:     http.Header{},
		ProtoMajor: 2,
		ProtoMinor: 0,
		Request:    req,
	}

	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatalf("modify response: %v", err)
	}
	if got := resp.Header.Get("Alt-Svc"); got != "" {
		t.Fatalf("expected no Alt-Svc when HTTP/3 is disabled, got %q", got)
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
