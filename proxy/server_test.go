package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
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

func TestHTTPSReverseProxyTransportUsesHTTP1UpstreamByDefault(t *testing.T) {
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
	retryTransport, ok := proxy.Transport.(*upstreamRetryTransport)
	if !ok {
		t.Fatalf("expected *upstreamRetryTransport, got %T", proxy.Transport)
	}
	transport, ok := retryTransport.next.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", retryTransport.next)
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatal("expected HTTPS upstream transport to stay on HTTP/1.1 by default")
	}
	if transport.TLSNextProto == nil {
		t.Fatal("expected TLSNextProto to be set so upstream HTTP/2 stays disabled")
	}
	if len(transport.TLSNextProto) != 0 {
		t.Fatalf("expected no alternate upstream TLS protocols, got %d", len(transport.TLSNextProto))
	}
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("unexpected TLS server name: %#v", transport.TLSClientConfig)
	}
	if transport.TLSClientConfig.ServerName != "" {
		t.Fatalf("expected upstream SNI to come from request URL host, got %q", transport.TLSClientConfig.ServerName)
	}
}

func TestReverseProxyUsesRequestedHostAndDialsBindAddress(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:   "https",
		bindAddr: "185.208.210.7",
		bindPort: "11443",
	})
	target, err := url.Parse("https://185.208.210.7")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	proxy := server.createReverseProxyWithHost(target, "example.com")
	req, err := http.NewRequest(http.MethodGet, "https://example.com/test", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	outReq := req.Clone(req.Context())
	proxy.Rewrite(&httputil.ProxyRequest{In: req, Out: outReq})

	if outReq.URL.Host != "example.com" {
		t.Fatalf("expected upstream URL host to stay on requested host for SNI/pooling, got %q", outReq.URL.Host)
	}
	if outReq.Host != "example.com" {
		t.Fatalf("expected Host header to be preserved, got %q", outReq.Host)
	}
	if got := server.upstreamAddress(); got != "185.208.210.7:443" {
		t.Fatalf("expected dial address to target bind IP on default HTTPS port, got %q", got)
	}
}

func TestReverseProxyReplacesSpoofableForwardingHeaders(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:   "https",
		bindAddr: "192.0.2.10",
		bindPort: "11443",
	})
	target, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	proxy := server.createReverseProxyWithHost(target, "example.com")
	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req.RemoteAddr = "198.51.100.25:43210"
	req.Header.Set("Forwarded", "for=attacker")
	req.Header.Set("X-Forwarded-For", "attacker")
	req.Header.Set("X-Forwarded-Host", "attacker.example")
	req.Header.Set("X-Forwarded-Port", "1234")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Real-IP", "203.0.113.99")
	req.Header.Set("CF-Connecting-IP", "203.0.113.98")
	req.Header.Set("True-Client-IP", "203.0.113.97")
	req = req.WithContext(context.WithValue(req.Context(), middleware.ContextKeyClientIP, "203.0.113.20"))

	outReq := req.Clone(req.Context())
	proxy.Rewrite(&httputil.ProxyRequest{In: req, Out: outReq})

	if got := outReq.Header.Get("X-Forwarded-For"); got != "203.0.113.20" {
		t.Fatalf("unexpected X-Forwarded-For: %q", got)
	}
	if got := outReq.Header.Get("X-Real-IP"); got != "203.0.113.20" {
		t.Fatalf("unexpected X-Real-IP: %q", got)
	}
	if got := outReq.Header.Get("X-Forwarded-Host"); got != "example.com" {
		t.Fatalf("unexpected X-Forwarded-Host: %q", got)
	}
	if got := outReq.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("unexpected X-Forwarded-Proto: %q", got)
	}
	for _, name := range []string{"Forwarded", "X-Forwarded-Port", "CF-Connecting-IP", "True-Client-IP"} {
		if got := outReq.Header.Get(name); got != "" {
			t.Fatalf("expected %s to be stripped, got %q", name, got)
		}
	}
}

func TestReverseProxyPreservesRawQuery(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:   "https",
		bindAddr: "192.0.2.10",
		bindPort: "11443",
	})
	target, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	proxy := server.createReverseProxyWithHost(target, "example.com")
	var upstreamRawQuery string
	proxy.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamRawQuery = req.URL.RawQuery
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "https://example.com/test?legacy=one;two&valid=value", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("unexpected response status: %d", w.Code)
	}
	if upstreamRawQuery != req.URL.RawQuery {
		t.Fatalf("upstream raw query = %q, want %q", upstreamRawQuery, req.URL.RawQuery)
	}
}

func TestReverseProxyClientAbortRecords499InsteadOfSynthetic502(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:   "https",
		bindAddr: "127.0.0.1",
		bindPort: "11443",
	})
	target, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	proxy := server.createReverseProxyWithHost(target, "example.com")
	req := httptest.NewRequest(http.MethodGet, "https://example.com/static/app.js", nil)
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	proxy.ErrorHandler(w, req, context.Canceled)

	if w.Code != statusClientClosedRequest {
		t.Fatalf("expected client abort to record 499, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("expected no synthetic error body for client abort, got %q", w.Body.String())
	}
}

func TestReverseProxyPolicyRejectionAbortsWithoutResponse(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:   "https",
		bindAddr: "192.0.2.60",
		bindPort: "11443",
	})
	proxy := server.createReverseProxyWithHost(&url.URL{Scheme: "https", Host: "example.test"}, "example.test")

	req := httptest.NewRequest(http.MethodGet, "https://example.test/private", nil)
	w := httptest.NewRecorder()

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		proxy.ErrorHandler(w, req, &upstreamPolicyRejectionError{cause: retryableDialError(syscall.ECONNREFUSED)})
	}()

	if recovered != http.ErrAbortHandler {
		t.Fatalf("recovered panic = %v, want http.ErrAbortHandler", recovered)
	}
	if w.Body.Len() != 0 || len(w.Header()) != 0 {
		t.Fatalf("unexpected HTTP response: headers=%v body=%q", w.Header(), w.Body.String())
	}
}

func TestPolicyRejectionKeepsHTTP2ConnectionAvailable(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:   "https",
		bindAddr: "192.0.2.61",
		bindPort: "11443",
	})
	proxy := server.createReverseProxyWithHost(&url.URL{Scheme: "https", Host: "example.test"}, "example.test")

	var connectionCount atomic.Int32
	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rejected" {
			proxy.ErrorHandler(w, r, &upstreamPolicyRejectionError{cause: retryableDialError(syscall.ECONNREFUSED)})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	testServer.EnableHTTP2 = true
	testServer.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		connectionCount.Add(1)
		return ctx
	}
	testServer.StartTLS()
	t.Cleanup(testServer.Close)

	client := testServer.Client()
	if resp, err := client.Get(testServer.URL + "/rejected"); err == nil {
		resp.Body.Close()
		t.Fatalf("policy-rejected HTTP/2 stream unexpectedly returned status %d", resp.StatusCode)
	}

	resp, err := client.Get(testServer.URL + "/healthy")
	if err != nil {
		t.Fatalf("healthy request after rejected stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || resp.ProtoMajor != 2 {
		t.Fatalf("healthy response status=%d protocol=%s", resp.StatusCode, resp.Proto)
	}
	if got := connectionCount.Load(); got != 1 {
		t.Fatalf("HTTP/2 connection count = %d, want rejected and healthy streams on one connection", got)
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

func TestFilteredLoggerSuppressesH3RequestCancelledOnlyWhenNotVerbose(t *testing.T) {
	var buf bytes.Buffer
	originalOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(originalOutput)

	newFilteredLogger(false).Print("suppressing panic for copyResponse error in test; copy error: H3_REQUEST_CANCELLED")
	if buf.Len() != 0 {
		t.Fatalf("expected H3_REQUEST_CANCELLED to be filtered when not verbose, got %q", buf.String())
	}

	newFilteredLogger(false).Print("suppressing panic for copyResponse error in test; copy error: H3 error (0x0)")
	if buf.Len() != 0 {
		t.Fatalf("expected H3 error (0x0) to be filtered when not verbose, got %q", buf.String())
	}

	newFilteredLogger(false).Print("suppressing panic for copyResponse error in test; copy error: NO_ERROR (remote): 85:Network blackhole detected")
	if buf.Len() != 0 {
		t.Fatalf("expected network blackhole copy error to be filtered when not verbose, got %q", buf.String())
	}

	newFilteredLogger(false).Print("suppressing panic for copyResponse error in test; copy error: unexpected backend read failure")
	if !strings.Contains(buf.String(), "unexpected backend read failure") {
		t.Fatalf("expected unrelated copy error to be logged, got %q", buf.String())
	}

	buf.Reset()
	newFilteredLogger(true).Print("suppressing panic for copyResponse error in test; copy error: H3_REQUEST_CANCELLED")
	if !strings.Contains(buf.String(), "H3_REQUEST_CANCELLED") {
		t.Fatalf("expected H3_REQUEST_CANCELLED to be logged when verbose, got %q", buf.String())
	}
}

func TestProxyErrorLogLimiterRateLimitsRecoveryLogs(t *testing.T) {
	var buf bytes.Buffer
	originalOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(originalOutput)

	limiter := newProxyErrorLogLimiter(time.Second)
	err := retryableDialError(syscall.ECONNREFUSED)

	limiter.logRecovery("127.0.0.1", "11443", "example.com", 2, err)
	limiter.logRecovery("127.0.0.1", "11443", "example.com", 1, err)

	got := buf.String()
	if strings.Count(got, "upstream recovered for example.com") != 1 {
		t.Fatalf("expected only first recovery log before flush, got %q", got)
	}

	limiter.flushRecovery("127.0.0.1|11443|example.com|recovered|connection-refused", "127.0.0.1", "11443", "example.com", err)
	if !strings.Contains(buf.String(), "suppressed 1 similar transient recovery logs") {
		t.Fatalf("expected suppressed recovery summary, got %q", buf.String())
	}
}

func TestUpstreamRetryTransportRetriesSafeBodylessRequests(t *testing.T) {
	attempts := 0
	var recoveredFailures int
	var recoveredErr error
	transport := &upstreamRetryTransport{
		next: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			if attempts == 1 {
				return nil, retryableDialError(syscall.ECONNREFUSED)
			}
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     http.Header{},
				Body:       http.NoBody,
				Request:    req,
			}, nil
		}),
		breaker:    newUpstreamCircuitBreaker(3, time.Second),
		retryDelay: func() time.Duration { return 0 },
		sleep:      func(context.Context, time.Duration) error { return nil },
		onRecovered: func(req *http.Request, failures int, err error) {
			recoveredFailures = failures
			recoveredErr = err
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected retry response status 204, got %d", resp.StatusCode)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
	if recoveredFailures != 1 {
		t.Fatalf("expected one recovered transient failure, got %d", recoveredFailures)
	}
	if !errors.Is(recoveredErr, syscall.ECONNREFUSED) {
		t.Fatalf("expected recovered error to be ECONNREFUSED, got %v", recoveredErr)
	}
}

func TestUpstreamRetryTransportDoesNotRetryUnsafeOrBodyRequests(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		err  error
	}{
		{
			name: "post connection reset",
			req:  mustNewRequest(t, http.MethodPost, "https://example.com/", nil),
			err:  retryableDialError(syscall.ECONNRESET),
		},
		{
			name: "get with non-replayable body",
			req:  mustNewRequest(t, http.MethodGet, "https://example.com/", io.NopCloser(strings.NewReader("body"))),
			err:  retryableDialError(syscall.ECONNREFUSED),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attempts := 0
			transport := &upstreamRetryTransport{
				next: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					attempts++
					return nil, tt.err
				}),
				breaker:    newUpstreamCircuitBreaker(3, time.Second),
				retryDelay: func() time.Duration { return 0 },
				sleep:      func(context.Context, time.Duration) error { return nil },
			}

			_, err := transport.RoundTrip(tt.req)
			if !errors.Is(err, tt.err) {
				t.Fatalf("expected %v, got %v", tt.err, err)
			}
			if attempts != 1 {
				t.Fatalf("expected 1 attempt, got %d", attempts)
			}
		})
	}
}

func TestUpstreamRetryTransportDoesNotMutateBreakerForPolicyRejection(t *testing.T) {
	breaker := newUpstreamCircuitBreaker(2, time.Second)
	breaker.failures = 1
	attempts := 0
	transport := &upstreamRetryTransport{
		next: roundTripFunc(func(*http.Request) (*http.Response, error) {
			attempts++
			return nil, &upstreamPolicyRejectionError{cause: retryableDialError(syscall.ECONNREFUSED)}
		}),
		breaker:      breaker,
		recoveryWait: 5 * time.Second,
		retryDelay:   func() time.Duration { return 0 },
		sleep: func(context.Context, time.Duration) error {
			t.Fatal("policy rejection should not sleep or retry")
			return nil
		},
	}

	_, err := transport.RoundTrip(mustNewRequest(t, http.MethodGet, "https://example.test/", nil))
	if !isUpstreamPolicyRejection(err) {
		t.Fatalf("RoundTrip error = %v, want policy rejection", err)
	}
	if attempts != 1 {
		t.Fatalf("upstream attempts = %d, want 1", attempts)
	}
	if breaker.failures != 1 || !breaker.openUntil.IsZero() {
		t.Fatalf("breaker changed after policy rejection: failures=%d openUntil=%v", breaker.failures, breaker.openUntil)
	}
}

func TestUpstreamRetryTransportReleasesHalfOpenProbeAfterPolicyRejection(t *testing.T) {
	now := time.Unix(200, 0)
	breaker := newUpstreamCircuitBreaker(1, time.Second)
	breaker.now = func() time.Time { return now }
	breaker.recordFailure()
	openUntil := breaker.openUntil
	now = openUntil.Add(time.Nanosecond)

	attempts := 0
	transport := &upstreamRetryTransport{
		next: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			if attempts == 1 {
				return nil, &upstreamPolicyRejectionError{cause: retryableDialError(syscall.ECONNREFUSED)}
			}
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     http.Header{},
				Body:       http.NoBody,
				Request:    req,
			}, nil
		}),
		breaker:      breaker,
		recoveryWait: 5 * time.Second,
	}

	_, err := transport.RoundTrip(mustNewRequest(t, http.MethodGet, "https://example.test/blocked", nil))
	if !isUpstreamPolicyRejection(err) {
		t.Fatalf("first RoundTrip error = %v, want policy rejection", err)
	}
	if breaker.probing {
		t.Fatal("policy rejection left the half-open probe occupied")
	}
	if breaker.failures != 1 || !breaker.openUntil.Equal(openUntil) {
		t.Fatalf("neutral result changed breaker history: failures=%d openUntil=%v", breaker.failures, breaker.openUntil)
	}

	resp, err := transport.RoundTrip(mustNewRequest(t, http.MethodGet, "https://example.test/recovery", nil))
	if err != nil {
		t.Fatalf("second RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent || attempts != 2 {
		t.Fatalf("recovery response status=%d attempts=%d", resp.StatusCode, attempts)
	}
	if breaker.failures != 0 || breaker.probing || !breaker.openUntil.IsZero() {
		t.Fatalf("successful follow-up did not close breaker: failures=%d probing=%v openUntil=%v",
			breaker.failures, breaker.probing, breaker.openUntil)
	}
}

func TestUpstreamRetryTransportKeepsUnsafeBodylessRequestAliveAfterDialFailures(t *testing.T) {
	now := time.Unix(100, 0)
	breaker := newUpstreamCircuitBreaker(2, time.Second)
	breaker.now = func() time.Time { return now }

	attempts := 0
	var slept time.Duration
	transport := &upstreamRetryTransport{
		next: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			if attempts <= 2 {
				return nil, retryableDialError(syscall.ECONNREFUSED)
			}
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     http.Header{},
				Body:       http.NoBody,
				Request:    req,
			}, nil
		}),
		breaker:      breaker,
		recoveryWait: 5 * time.Second,
		retryDelay:   func() time.Duration { return 0 },
		sleep: func(ctx context.Context, delay time.Duration) error {
			slept += delay
			now = now.Add(delay)
			return nil
		},
	}

	resp, err := transport.RoundTrip(mustNewRequest(t, http.MethodPost, "https://example.com/", nil))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected recovery response status 204, got %d", resp.StatusCode)
	}
	if attempts != 3 {
		t.Fatalf("expected two failed dial attempts and one recovery attempt, got %d", attempts)
	}
	if slept != time.Second {
		t.Fatalf("expected to wait for breaker cooldown after failures, slept %v", slept)
	}
}

func TestUpstreamCircuitBreakerOpensAfterConsecutiveTransientFailures(t *testing.T) {
	now := time.Unix(100, 0)
	breaker := newUpstreamCircuitBreaker(3, time.Second)
	breaker.now = func() time.Time { return now }

	attempts := 0
	transport := &upstreamRetryTransport{
		next: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, retryableDialError(syscall.ECONNRESET)
		}),
		breaker:    breaker,
		retryDelay: func() time.Duration { return 0 },
		sleep:      func(context.Context, time.Duration) error { return nil },
	}

	for i := 0; i < 3; i++ {
		_, err := transport.RoundTrip(mustNewRequest(t, http.MethodPost, "https://example.com/", nil))
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("failure %d: expected ECONNRESET, got %v", i+1, err)
		}
	}
	if attempts != 3 {
		t.Fatalf("expected 3 upstream attempts before opening, got %d", attempts)
	}

	_, err := transport.RoundTrip(mustNewRequest(t, http.MethodPost, "https://example.com/", nil))
	if !errors.Is(err, errUpstreamCircuitOpen) {
		t.Fatalf("expected open circuit error, got %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected open circuit to avoid an upstream attempt, got %d attempts", attempts)
	}

	now = now.Add(time.Second + time.Nanosecond)
	_, err = transport.RoundTrip(mustNewRequest(t, http.MethodPost, "https://example.com/", nil))
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("expected half-open probe failure, got %v", err)
	}
	if attempts != 4 {
		t.Fatalf("expected one half-open upstream probe, got %d attempts", attempts)
	}

	_, err = transport.RoundTrip(mustNewRequest(t, http.MethodPost, "https://example.com/", nil))
	if !errors.Is(err, errUpstreamCircuitOpen) {
		t.Fatalf("expected reopened circuit error, got %v", err)
	}
	if attempts != 4 {
		t.Fatalf("expected reopened circuit to avoid an upstream attempt, got %d attempts", attempts)
	}
}

func TestUpstreamRetryTransportWaitsForOpenBreakerRecovery(t *testing.T) {
	now := time.Unix(100, 0)
	breaker := newUpstreamCircuitBreaker(1, time.Second)
	breaker.now = func() time.Time { return now }
	breaker.recordFailure()

	attempts := 0
	var slept time.Duration
	transport := &upstreamRetryTransport{
		next: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     http.Header{},
				Body:       http.NoBody,
				Request:    req,
			}, nil
		}),
		breaker:      breaker,
		recoveryWait: 5 * time.Second,
		sleep: func(ctx context.Context, delay time.Duration) error {
			slept += delay
			now = now.Add(delay)
			return nil
		},
	}

	resp, err := transport.RoundTrip(mustNewRequest(t, http.MethodGet, "https://example.com/", nil))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected recovery response status 204, got %d", resp.StatusCode)
	}
	if attempts != 1 {
		t.Fatalf("expected one half-open probe attempt, got %d", attempts)
	}
	if slept != time.Second {
		t.Fatalf("expected to wait for breaker cooldown, slept %v", slept)
	}
}

func TestUpstreamRetryTransportKeepsSafeRequestAliveUntilRecovery(t *testing.T) {
	now := time.Unix(100, 0)
	breaker := newUpstreamCircuitBreaker(2, time.Second)
	breaker.now = func() time.Time { return now }

	attempts := 0
	var slept time.Duration
	transport := &upstreamRetryTransport{
		next: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			if attempts <= 2 {
				return nil, retryableDialError(syscall.ECONNREFUSED)
			}
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     http.Header{},
				Body:       http.NoBody,
				Request:    req,
			}, nil
		}),
		breaker:      breaker,
		recoveryWait: 5 * time.Second,
		retryDelay:   func() time.Duration { return 0 },
		sleep: func(ctx context.Context, delay time.Duration) error {
			slept += delay
			now = now.Add(delay)
			return nil
		},
	}

	resp, err := transport.RoundTrip(mustNewRequest(t, http.MethodGet, "https://example.com/", nil))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected recovery response status 204, got %d", resp.StatusCode)
	}
	if attempts != 3 {
		t.Fatalf("expected two failed attempts and one recovery attempt, got %d", attempts)
	}
	if slept != time.Second {
		t.Fatalf("expected to wait for breaker cooldown after failures, slept %v", slept)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func mustNewRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

func retryableDialError(errno syscall.Errno) error {
	return fmt.Errorf("dial tcp: connect: %w", errno)
}
