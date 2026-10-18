package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"go.chief.tools/flowguard-proxy/config"
	"go.chief.tools/flowguard-proxy/middleware"

	"github.com/quic-go/quic-go/http3"
)

func proxyProtocolV2Header(command, family byte, addresses []byte, tlvs []byte) []byte {
	header := append([]byte(nil), proxyProtocolV2Signature...)
	header = append(header, 0x20|command, family)
	header = binary.BigEndian.AppendUint16(header, uint16(len(addresses)+len(tlvs)))
	header = append(header, addresses...)
	return append(header, tlvs...)
}

func proxyProtocolV2Addresses(source, destination netip.AddrPort) []byte {
	var addresses []byte
	addresses = append(addresses, source.Addr().AsSlice()...)
	addresses = append(addresses, destination.Addr().AsSlice()...)
	addresses = binary.BigEndian.AppendUint16(addresses, source.Port())
	return binary.BigEndian.AppendUint16(addresses, destination.Port())
}

func TestReadProxyProtocolHeader(t *testing.T) {
	ipv4Source := netip.MustParseAddrPort("203.0.113.7:51000")
	ipv4Destination := netip.MustParseAddrPort("198.51.100.1:443")
	ipv6Source := netip.MustParseAddrPort("[2001:db8::7]:51000")
	ipv6Destination := netip.MustParseAddrPort("[2001:db8::1]:443")
	tlv := []byte{0xEA, 0x00, 0x03, 'v', 'p', 'c'}

	tests := []struct {
		name       string
		input      []byte
		wantClient netip.AddrPort
		wantOK     bool
		wantErr    bool
		// endOfStream sends nothing after input, so a truncated header is
		// not completed by the payload.
		endOfStream bool
	}{
		{
			name:       "v1 TCP4",
			input:      []byte("PROXY TCP4 203.0.113.7 198.51.100.1 51000 443\r\n"),
			wantClient: ipv4Source,
			wantOK:     true,
		},
		{
			name:       "v1 TCP6",
			input:      []byte("PROXY TCP6 2001:db8::7 2001:db8::1 51000 443\r\n"),
			wantClient: ipv6Source,
			wantOK:     true,
		},
		{
			name:  "v1 UNKNOWN",
			input: []byte("PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n"),
		},
		{
			name:       "v2 TCP over IPv4 with TLVs",
			input:      proxyProtocolV2Header(proxyProtocolV2CommandProxy, proxyProtocolV2TCPOverIPv4, proxyProtocolV2Addresses(ipv4Source, ipv4Destination), tlv),
			wantClient: ipv4Source,
			wantOK:     true,
		},
		{
			name:       "v2 TCP over IPv6",
			input:      proxyProtocolV2Header(proxyProtocolV2CommandProxy, proxyProtocolV2TCPOverIPv6, proxyProtocolV2Addresses(ipv6Source, ipv6Destination), nil),
			wantClient: ipv6Source,
			wantOK:     true,
		},
		{
			name:  "v2 LOCAL",
			input: proxyProtocolV2Header(proxyProtocolV2CommandLocal, 0x00, nil, tlv),
		},
		{
			name:  "v2 UDP over IPv4",
			input: proxyProtocolV2Header(proxyProtocolV2CommandProxy, 0x12, proxyProtocolV2Addresses(ipv4Source, ipv4Destination), nil),
		},
		{name: "HTTP GET", input: []byte("GET / HTTP/1.1\r\n")},
		{name: "HTTP POST", input: []byte("POST / HTTP/1.1\r\n")},
		{name: "HTTP PROPFIND", input: []byte("PROPFIND / HTTP/1.1\r\n")},
		{name: "TLS ClientHello", input: []byte{0x16, 0x03, 0x01, 0x00, 0x05}},
		{name: "HTTP/2 preface", input: []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")},
		{
			name:    "v1 without CRLF",
			input:   []byte("PROXY TCP4 203.0.113.7 198.51.100.1 51000 443\n"),
			wantErr: true,
		},
		{
			name:    "v1 too long",
			input:   []byte("PROXY TCP6 " + strings.Repeat("a", 100) + "\r\n"),
			wantErr: true,
		},
		{
			name:    "v1 family mismatch",
			input:   []byte("PROXY TCP4 2001:db8::7 198.51.100.1 51000 443\r\n"),
			wantErr: true,
		},
		{
			name:    "v1 invalid port",
			input:   []byte("PROXY TCP4 203.0.113.7 198.51.100.1 70000 443\r\n"),
			wantErr: true,
		},
		{
			name:    "v1 zoned address",
			input:   []byte("PROXY TCP6 fe80::7%eth0 2001:db8::1 51000 443\r\n"),
			wantErr: true,
		},
		{
			name:    "HTTP request with PROXY method",
			input:   []byte("PROXY / HTTP/1.1\r\n"),
			wantErr: true,
		},
		{
			name:    "v2 unsupported version",
			input:   append(append(append([]byte(nil), proxyProtocolV2Signature...), 0x11, 0x11), 0x00, 0x00),
			wantErr: true,
		},
		{
			name:    "v2 unsupported command",
			input:   proxyProtocolV2Header(0x2, proxyProtocolV2TCPOverIPv4, proxyProtocolV2Addresses(ipv4Source, ipv4Destination), nil),
			wantErr: true,
		},
		{
			name:    "v2 address block too short",
			input:   proxyProtocolV2Header(proxyProtocolV2CommandProxy, proxyProtocolV2TCPOverIPv6, proxyProtocolV2Addresses(ipv4Source, ipv4Destination), nil),
			wantErr: true,
		},
		{
			name:        "v2 truncated",
			input:       proxyProtocolV2Header(proxyProtocolV2CommandProxy, proxyProtocolV2TCPOverIPv4, proxyProtocolV2Addresses(ipv4Source, ipv4Destination), nil)[:20],
			wantErr:     true,
			endOfStream: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := "payload after header"
			if tt.endOfStream {
				payload = ""
			}
			reader := bufio.NewReaderSize(bytes.NewReader(append(append([]byte(nil), tt.input...), payload...)), proxyProtocolReadBufferSize)

			client, ok, err := readProxyProtocolHeader(reader)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got client %v ok %v", client, ok)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tt.wantOK || client != tt.wantClient {
				t.Fatalf("got client %v ok %v, want %v ok %v", client, ok, tt.wantClient, tt.wantOK)
			}

			rest, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("read rest: %v", err)
			}
			want := payload
			if !strings.HasPrefix(string(tt.input), "PROXY ") && !bytes.HasPrefix(tt.input, proxyProtocolV2Signature) {
				want = string(tt.input) + payload
			}
			if string(rest) != want {
				t.Fatalf("got remaining stream %q, want %q", rest, want)
			}
		})
	}
}

type proxyProtocolTestConn struct {
	server *proxyProtocolConn
	client net.Conn
}

func dialProxyProtocolTestConn(t *testing.T, loadBalancer func(netip.Addr) bool, headerTimeout time.Duration) proxyProtocolTestConn {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	wrapped := proxyProtocolListener{Listener: listener, loadBalancer: loadBalancer, headerTimeout: headerTimeout}

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	conn, err := wrapped.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return proxyProtocolTestConn{server: conn.(*proxyProtocolConn), client: client}
}

func trustLoopback(addr netip.Addr) bool {
	return addr.IsLoopback()
}

func TestProxyProtocolConnUsesHeaderFromLoadBalancer(t *testing.T) {
	conn := dialProxyProtocolTestConn(t, trustLoopback, time.Second)
	if _, err := conn.client.Write([]byte("PROXY TCP4 203.0.113.7 198.51.100.1 51000 443\r\nhello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := conn.server.RemoteAddr().String(); got != "203.0.113.7:51000" {
		t.Fatalf("got remote address %q, want the client from the header", got)
	}
	if peer, headerUsed, ok := conn.server.loadBalancerPeer(); !ok || !headerUsed || peer != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("got load balancer %v header used %v ok %v, want 127.0.0.1 with its header used", peer, headerUsed, ok)
	}

	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn.server, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("got payload %q err %v, want hello", buf, err)
	}
}

func TestProxyProtocolConnDiscardsHeaderFromOtherPeers(t *testing.T) {
	for name, loadBalancer := range map[string]func(netip.Addr) bool{
		"other peer":       func(netip.Addr) bool { return false },
		"no load balancer": nil,
	} {
		t.Run(name, func(t *testing.T) {
			conn := dialProxyProtocolTestConn(t, loadBalancer, time.Second)
			if _, err := conn.client.Write([]byte("PROXY TCP4 203.0.113.7 198.51.100.1 51000 443\r\nhello")); err != nil {
				t.Fatalf("write: %v", err)
			}

			if got := conn.server.RemoteAddr().String(); got != conn.client.LocalAddr().String() {
				t.Fatalf("got remote address %q, want the real peer %q", got, conn.client.LocalAddr())
			}
			if peer, _, ok := conn.server.loadBalancerPeer(); ok {
				t.Fatalf("got load balancer %v, want none", peer)
			}

			buf := make([]byte, 5)
			if _, err := io.ReadFull(conn.server, buf); err != nil || string(buf) != "hello" {
				t.Fatalf("got payload %q err %v, want hello with the header removed", buf, err)
			}
		})
	}
}

func TestProxyProtocolConnPassesThroughLoadBalancerWithoutHeader(t *testing.T) {
	conn := dialProxyProtocolTestConn(t, trustLoopback, time.Second)
	request := "POST / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if _, err := conn.client.Write([]byte(request)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := conn.server.RemoteAddr().String(); got != conn.client.LocalAddr().String() {
		t.Fatalf("got remote address %q, want the real peer %q", got, conn.client.LocalAddr())
	}
	if _, headerUsed, ok := conn.server.loadBalancerPeer(); !ok || headerUsed {
		t.Fatalf("got load balancer ok %v header used %v, want a load balancer without a header", ok, headerUsed)
	}

	buf := make([]byte, len(request))
	if _, err := io.ReadFull(conn.server, buf); err != nil || string(buf) != request {
		t.Fatalf("got stream %q err %v, want it unchanged", buf, err)
	}
}

func TestProxyProtocolConnTimesOutIncompleteHeader(t *testing.T) {
	conn := dialProxyProtocolTestConn(t, trustLoopback, 50*time.Millisecond)
	if _, err := conn.client.Write([]byte("PROXY TCP4 203.0.113.7")); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := conn.server.Read(make([]byte, 1))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("got error %v, want a timeout", err)
	}
	if got := conn.server.RemoteAddr().String(); got != conn.client.LocalAddr().String() {
		t.Fatalf("got remote address %q, want the real peer %q", got, conn.client.LocalAddr())
	}
}

func TestProxyProtocolConnKeepsCallerReadDeadline(t *testing.T) {
	conn := dialProxyProtocolTestConn(t, trustLoopback, 10*time.Second)
	if err := conn.server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := conn.client.Write([]byte("PROXY TCP4 203.0.113.7 198.51.100.1 51000 443\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	start := time.Now()
	_, err := conn.server.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got error %v, want the caller's deadline to expire", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("read returned after %v, want the caller's 50ms deadline restored", elapsed)
	}
}

type proxyProtocolCaptureMiddleware struct {
	requests chan *http.Request
}

func (m *proxyProtocolCaptureMiddleware) Handle(w http.ResponseWriter, r *http.Request, _ http.Handler) {
	m.requests <- r
	w.WriteHeader(http.StatusNoContent)
}

func (*proxyProtocolCaptureMiddleware) Stop() {}

// startLoadBalancerTestServer starts a server behind a load balancer on
// 127.0.0.1 that is also trusted for X-Forwarded-For, as when it runs port 80
// in HTTP mode. 198.51.100.10 is a trusted CDN.
func startLoadBalancerTestServer(t *testing.T, scheme string, protocols config.ProtocolSettings) (*Server, *proxyProtocolCaptureMiddleware) {
	t.Helper()

	configMgr := newProxyTestConfigManager(t, config.Config{TrustedProxies: &config.TrustedProxiesConfig{
		IPNets:        []string{"127.0.0.1", "198.51.100.10"},
		ProxyProtocol: &config.ProxyProtocolConfig{IPNets: []string{"127.0.0.1"}},
	}})
	t.Cleanup(configMgr.Stop)

	terminal := &proxyProtocolCaptureMiddleware{requests: make(chan *http.Request, 1)}
	chain := middleware.NewChain()
	chain.Add(middleware.NewIPLookupMiddleware(configMgr))
	chain.Add(terminal)
	t.Cleanup(chain.Stop)

	var tlsConfig *tls.Config
	if scheme == "https" {
		tlsConfig = testServerTLSConfig(t)
	}
	server := NewServer(&ServerConfig{
		scheme:       scheme,
		bindAddr:     "127.0.0.1",
		bindPort:     "0",
		middleware:   chain,
		protocols:    &protocols,
		loadBalancer: configMgr.IsProxyProtocolPeer,
	})
	if err := server.Start(tlsConfig, make(chan error, 1)); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	})

	return server, terminal
}

func TestServerResolvesClientBehindLoadBalancer(t *testing.T) {
	tests := []struct {
		name         string
		scheme       string
		headerClient string
		forwardedFor string
		wantClientIP string
		wantProxyIP  string
	}{
		{
			name:         "https header ignores client forwarding headers",
			scheme:       "https",
			headerClient: "203.0.113.7:51000",
			forwardedFor: "192.0.2.66",
			wantClientIP: "203.0.113.7",
			wantProxyIP:  "127.0.0.1",
		},
		{
			name:         "https without header ignores client forwarding headers",
			scheme:       "https",
			forwardedFor: "192.0.2.66",
			wantClientIP: "127.0.0.1",
		},
		{
			name:         "https header from trusted CDN keeps its forwarding headers",
			scheme:       "https",
			headerClient: "198.51.100.10:51000",
			forwardedFor: "203.0.113.9",
			wantClientIP: "203.0.113.9",
			wantProxyIP:  "127.0.0.1",
		},
		{
			name:         "http header ignores client forwarding headers",
			scheme:       "http",
			headerClient: "203.0.113.7:51000",
			forwardedFor: "192.0.2.66",
			wantClientIP: "203.0.113.7",
			wantProxyIP:  "127.0.0.1",
		},
		{
			name:         "http without header trusts load balancer forwarding headers",
			scheme:       "http",
			forwardedFor: "203.0.113.9",
			wantClientIP: "203.0.113.9",
			wantProxyIP:  "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, terminal := startLoadBalancerTestServer(t, tt.scheme, config.ProtocolSettings{HTTP1: true})

			conn, err := net.Dial("tcp", server.listener.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			if tt.headerClient != "" {
				if _, err := conn.Write(proxyProtocolV2Header(
					proxyProtocolV2CommandProxy,
					proxyProtocolV2TCPOverIPv4,
					proxyProtocolV2Addresses(netip.MustParseAddrPort(tt.headerClient), netip.MustParseAddrPort("198.51.100.1:443")),
					nil,
				)); err != nil {
					t.Fatalf("write header: %v", err)
				}
			}

			var stream net.Conn = conn
			if tt.scheme == "https" {
				stream = tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "example.com"})
			}
			if _, err := fmt.Fprintf(stream, "GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: %s\r\n\r\n", tt.forwardedFor); err != nil {
				t.Fatalf("write request: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(stream), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			resp.Body.Close()

			r := <-terminal.requests
			if got := middleware.GetClientIP(r); got != tt.wantClientIP {
				t.Fatalf("got client IP %q, want %q", got, tt.wantClientIP)
			}
			if got := middleware.GetProxyIP(r); got != tt.wantProxyIP {
				t.Fatalf("got proxy IP %q, want %q", got, tt.wantProxyIP)
			}
			if tt.scheme == "https" && middleware.GetJA4Fingerprint(r) == "" {
				t.Fatal("expected the JA4 fingerprint to survive the PROXY protocol wrapper")
			}
		})
	}
}

func TestServerIgnoresForwardingHeadersOverHTTP3FromLoadBalancer(t *testing.T) {
	server, terminal := startLoadBalancerTestServer(t, "https", config.ProtocolSettings{HTTP3: true})

	transport := &http3.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // The server uses a generated test certificate.
		ServerName:         "example.com",
	}}
	t.Cleanup(func() { transport.Close() })
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	req, err := http.NewRequest(http.MethodGet, "https://"+server.udpConn.LocalAddr().String()+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-For", "192.0.2.66")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("perform HTTP/3 request: %v", err)
	}
	resp.Body.Close()

	r := <-terminal.requests
	if got := middleware.GetClientIP(r); got != "127.0.0.1" {
		t.Fatalf("got client IP %q, want the load balancer instead of the forwarded address", got)
	}
	if middleware.IsProxied(r) {
		t.Fatalf("got proxied request via %q, want none", middleware.GetProxyIP(r))
	}
}
