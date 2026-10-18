package flowguardcaddy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"go.chief.tools/flowguard-proxy/fingerprint"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
}

// ListenerWrapper reads each connection's TLS ClientHello to compute its JA4
// fingerprint, before Caddy terminates TLS. It must come before the `tls`
// listener wrapper, and after `proxy_protocol` when that is used:
//
//	servers {
//		listener_wrappers {
//			flowguard
//			tls
//		}
//	}
//
// HTTP/3 connections have no JA4, because Caddy does not expose QUIC
// ClientHellos to plugins.
type ListenerWrapper struct {
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.flowguard",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// Provision sets up the wrapper's logger.
func (lw *ListenerWrapper) Provision(ctx caddy.Context) error {
	lw.logger = ctx.Logger()
	return nil
}

// WrapListener wraps l so each accepted connection records its JA4.
func (lw *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	return &fingerprintListener{Listener: l, logger: lw.logger}
}

type fingerprintListener struct {
	net.Listener
	logger     *zap.Logger
	warnedOnce atomic.Bool
}

func (l *fingerprintListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// After the tls wrapper the handshake is no longer visible, and hiding
	// the connection's TLS state would leave Caddy's requests without r.TLS.
	if _, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		if l.warnedOnce.CompareAndSwap(false, true) && l.logger != nil {
			l.logger.Warn("flowguard listener wrapper is placed after tls, so JA4 fingerprints are unavailable; list it before tls in listener_wrappers")
		}
		return conn, nil
	}

	return &fingerprintConn{Conn: conn}, nil
}

// fingerprintConn computes the JA4 fingerprint from the ClientHello on the
// first read, then replays the bytes it read to the TLS server.
type fingerprintConn struct {
	net.Conn

	sniffOnce sync.Once
	replay    io.Reader
	ja4       atomic.Pointer[string]
}

func (c *fingerprintConn) Read(p []byte) (int, error) {
	c.sniffOnce.Do(c.sniff)
	return c.replay.Read(p)
}

// JA4 returns the connection's JA4 fingerprint, or "" when the connection did
// not start with a TLS ClientHello.
func (c *fingerprintConn) JA4() string {
	if ja4 := c.ja4.Load(); ja4 != nil {
		return *ja4
	}
	return ""
}

var errClientHelloCaptured = errors.New("flowguard: client hello captured")

// sniff runs Go's TLS server over the connection until it has parsed the
// ClientHello, so the fingerprint uses exactly the fields the standalone
// proxy sees. The handshake is aborted there, its alert is discarded, and
// everything read is replayed to Caddy's TLS server.
func (c *fingerprintConn) sniff() {
	recorder := &recordingConn{Conn: c.Conn}
	sniffer := tls.Server(recorder, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if ja4 := fingerprint.JA4FromClientHello(hello, "t"); ja4 != "" {
				c.ja4.Store(&ja4)
			}
			return nil, errClientHelloCaptured
		},
	})
	_ = sniffer.Handshake()

	c.replay = io.MultiReader(bytes.NewReader(recorder.read.Bytes()), recorder.unread(c.Conn))
}

// recordingConn keeps what the sniffing TLS server reads, and drops what it
// writes so the client never sees the aborted handshake's alert.
type recordingConn struct {
	net.Conn
	read bytes.Buffer
	err  error
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Write(p[:n])
	if err != nil {
		c.err = err
	}
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	return len(p), nil
}

// The sniffing server must not close or change the real connection.
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

// unread returns the rest of the connection, or the read error the sniffer
// hit so it reaches the TLS server after the replayed bytes.
func (c *recordingConn) unread(conn net.Conn) io.Reader {
	if c.err != nil {
		return errReader{c.err}
	}
	return conn
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// fingerprintConnFrom finds the fingerprintConn under conn, unwrapping
// connections such as *tls.Conn that expose the one they wrap.
func fingerprintConnFrom(conn net.Conn) *fingerprintConn {
	for conn != nil {
		switch c := conn.(type) {
		case *fingerprintConn:
			return c
		case interface{ NetConn() net.Conn }:
			conn = c.NetConn()
		default:
			return nil
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
)
