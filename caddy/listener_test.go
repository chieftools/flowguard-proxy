package flowguardcaddy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"go.chief.tools/flowguard-proxy/fingerprint"
)

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		DNSNames:     []string{"example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func listenWrapped(t *testing.T) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	return (&ListenerWrapper{}).WrapListener(ln)
}

func TestListenerWrapperRecordsJA4BeforeTLS(t *testing.T) {
	wrapped := listenWrapped(t)

	// The JA4 the standalone proxy computes from the same ClientHello.
	want := make(chan string, 1)
	tlsListener := tls.NewListener(wrapped, &tls.Config{
		Certificates: []tls.Certificate{testCertificate(t)},
		NextProtos:   []string{"h2", "http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			want <- fingerprint.JA4FromClientHello(hello, "t")
			return nil, nil
		},
	})

	type result struct {
		ja4  string
		line string
		err  error
	}
	results := make(chan result, 1)
	go func() {
		conn, err := tlsListener.Accept()
		if err != nil {
			results <- result{err: err}
			return
		}
		defer conn.Close()
		line, err := bufio.NewReader(conn).ReadString('\n')
		var ja4 string
		if fc := fingerprintConnFrom(conn); fc != nil {
			ja4 = fc.JA4()
		}
		results <- result{ja4: ja4, line: line, err: err}
	}()

	client, err := tls.Dial("tcp", wrapped.Addr().String(), &tls.Config{
		ServerName:         "example.test",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatalf("TLS handshake through the wrapper: %v", err)
	}
	defer client.Close()
	if _, err := io.WriteString(client, "hello\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := <-results
	if got.err != nil {
		t.Fatalf("server: %v", got.err)
	}
	if got.line != "hello\n" {
		t.Fatalf("server read %q, want the client's data after the handshake", got.line)
	}
	if expected := <-want; got.ja4 == "" || got.ja4 != expected {
		t.Fatalf("JA4 = %q, want %q", got.ja4, expected)
	}
}

func TestListenerWrapperPassesPlainConnectionsThrough(t *testing.T) {
	wrapped := listenWrapped(t)

	type result struct {
		line string
		ja4  string
		err  error
	}
	results := make(chan result, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err != nil {
			results <- result{err: err}
			return
		}
		defer conn.Close()
		line, err := bufio.NewReader(conn).ReadString('\n')
		results <- result{line: line, ja4: fingerprintConnFrom(conn).JA4(), err: err}
	}()

	client, err := net.Dial("tcp", wrapped.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := <-results
	if got.err != nil {
		t.Fatalf("server: %v", got.err)
	}
	if got.line != "GET / HTTP/1.1\r\n" {
		t.Fatalf("server read %q, want the plain request unchanged", got.line)
	}
	if got.ja4 != "" {
		t.Fatalf("JA4 = %q, want none for a plain connection", got.ja4)
	}
}

type stubListener struct {
	net.Listener
	conn net.Conn
}

func (l stubListener) Accept() (net.Conn, error) { return l.conn, nil }

func TestListenerWrapperLeavesTLSConnectionsAlone(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	tlsConn := tls.Server(server, &tls.Config{})

	wrapped := (&ListenerWrapper{}).WrapListener(stubListener{conn: tlsConn})
	conn, err := wrapped.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if conn != net.Conn(tlsConn) {
		t.Fatalf("expected the TLS connection unchanged so Caddy keeps its TLS state, got %T", conn)
	}
}
