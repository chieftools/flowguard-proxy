package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PROXY protocol (v1 and v2) support for layer 4 load balancers in front of
// FlowGuard, as specified in https://www.haproxy.org/download/3.0/doc/proxy-protocol.txt.
//
// A header is honoured only when the TCP peer is a trusted proxy. Those peers
// can already set the client address through X-Forwarded-For, so this gives
// them nothing new. The header is optional so that trusted HTTP proxies such as
// CDNs keep working without one. A header from any other peer is read and
// discarded, and the connection keeps its real peer address.

var (
	proxyProtocolV1Prefix    = []byte("PROXY ")
	proxyProtocolV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")
)

const (
	// proxyProtocolV1MaxLength is the longest v1 header, including CRLF.
	proxyProtocolV1MaxLength = 107

	proxyProtocolV2HeaderLength = 16
	proxyProtocolV2CommandLocal = 0x0
	proxyProtocolV2CommandProxy = 0x1
	proxyProtocolV2TCPOverIPv4  = 0x11
	proxyProtocolV2TCPOverIPv6  = 0x21

	// proxyProtocolReadBufferSize holds the header and whatever arrives with
	// it. Bytes read past the header are served from this buffer first.
	proxyProtocolReadBufferSize = 512
)

type proxyProtocolConnContextKey struct{}

type proxyProtocolListener struct {
	net.Listener

	// trusted reports whether a peer may set the client address. Nil trusts
	// no peer.
	trusted func(netip.Addr) bool
	// headerTimeout bounds how long the header may take to arrive, starting
	// when it is first needed.
	headerTimeout time.Duration
}

// Accept does not read from the connection. The header is read on the first
// Read or RemoteAddr call, in the connection's own goroutine, so a slow client
// cannot stall the accept loop.
func (l proxyProtocolListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &proxyProtocolConn{
		Conn:          conn,
		trusted:       l.trusted,
		headerTimeout: l.headerTimeout,
	}, nil
}

type proxyProtocolConn struct {
	net.Conn

	trusted       func(netip.Addr) bool
	headerTimeout time.Duration

	once   sync.Once
	err    error
	reader *bufio.Reader
	remote net.Addr
	peer   netip.Addr

	deadlineMu   sync.Mutex
	readDeadline time.Time
}

func (c *proxyProtocolConn) Read(p []byte) (int, error) {
	c.once.Do(c.readHeader)
	if c.err != nil {
		return 0, c.err
	}

	if c.reader != nil {
		n, err := c.reader.Read(p)
		if c.reader.Buffered() == 0 {
			c.reader = nil
		}
		return n, err
	}

	return c.Conn.Read(p)
}

// RemoteAddr returns the client address from an honoured header, or the real
// peer address otherwise.
func (c *proxyProtocolConn) RemoteAddr() net.Addr {
	c.once.Do(c.readHeader)
	return c.remote
}

// proxyPeer returns the trusted peer that sent an honoured header.
func (c *proxyProtocolConn) proxyPeer() (netip.Addr, bool) {
	c.once.Do(c.readHeader)
	return c.peer, c.peer.IsValid()
}

func (c *proxyProtocolConn) SetDeadline(t time.Time) error {
	c.recordReadDeadline(t)
	return c.Conn.SetDeadline(t)
}

func (c *proxyProtocolConn) SetReadDeadline(t time.Time) error {
	c.recordReadDeadline(t)
	return c.Conn.SetReadDeadline(t)
}

func (c *proxyProtocolConn) recordReadDeadline(t time.Time) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	c.readDeadline = t
}

func (c *proxyProtocolConn) readHeader() {
	c.remote = c.Conn.RemoteAddr()

	if c.headerTimeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.headerTimeout))

		// Restore the deadline the caller set, if any, so the header timeout
		// never replaces or outlives it.
		defer func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()

			_ = c.Conn.SetReadDeadline(c.readDeadline)
		}()
	}

	reader := bufio.NewReaderSize(c.Conn, proxyProtocolReadBufferSize)
	defer func() {
		if reader.Buffered() > 0 {
			c.reader = reader
		}
	}()

	client, ok, err := readProxyProtocolHeader(reader)
	if err != nil {
		c.err = err
		return
	}
	if !ok || c.trusted == nil {
		return
	}

	tcpAddr, isTCP := c.remote.(*net.TCPAddr)
	if !isTCP {
		return
	}
	peer := tcpAddr.AddrPort().Addr().Unmap()
	if !c.trusted(peer) {
		return
	}

	c.peer = peer
	c.remote = net.TCPAddrFromAddrPort(client)
}

// readProxyProtocolHeader consumes a PROXY protocol header if the stream starts
// with one. ok is false when there is no header or it carries no client
// address, in which case the real peer address applies.
func readProxyProtocolHeader(reader *bufio.Reader) (client netip.AddrPort, ok bool, err error) {
	switch version, err := detectProxyProtocolVersion(reader); {
	case err != nil:
		return netip.AddrPort{}, false, err
	case version == 1:
		return readProxyProtocolV1(reader)
	case version == 2:
		return readProxyProtocolV2(reader)
	default:
		return netip.AddrPort{}, false, nil
	}
}

// detectProxyProtocolVersion peeks one byte at a time and stops at the first
// byte that rules out both signatures, so ordinary HTTP and TLS clients are
// never waited on for more than their first byte.
func detectProxyProtocolVersion(reader *bufio.Reader) (int, error) {
	for n := 1; ; n++ {
		peeked, err := reader.Peek(n)
		if err != nil {
			if errors.Is(err, io.EOF) && len(peeked) > 0 {
				return 0, nil
			}
			return 0, err
		}

		v1 := n <= len(proxyProtocolV1Prefix) && bytes.Equal(peeked, proxyProtocolV1Prefix[:n])
		v2 := n <= len(proxyProtocolV2Signature) && bytes.Equal(peeked, proxyProtocolV2Signature[:n])

		switch {
		case v1 && n == len(proxyProtocolV1Prefix):
			return 1, nil
		case v2 && n == len(proxyProtocolV2Signature):
			return 2, nil
		case !v1 && !v2:
			return 0, nil
		}
	}
}

func readProxyProtocolV1(reader *bufio.Reader) (netip.AddrPort, bool, error) {
	line := make([]byte, 0, proxyProtocolV1MaxLength)
	for len(line) < proxyProtocolV1MaxLength {
		b, err := reader.ReadByte()
		if err != nil {
			return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v1: read header: %w", err)
		}
		line = append(line, b)
		if b == '\n' {
			break
		}
	}

	header, found := strings.CutSuffix(string(line), "\r\n")
	if !found {
		return netip.AddrPort{}, false, errors.New("proxy protocol v1: header is not terminated by CRLF within 107 bytes")
	}

	fields := strings.Split(header, " ")
	if len(fields) >= 2 && fields[1] == "UNKNOWN" {
		return netip.AddrPort{}, false, nil
	}
	if len(fields) != 6 {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v1: expected 6 fields, got %d", len(fields))
	}

	var family func(netip.Addr) bool
	switch fields[1] {
	case "TCP4":
		family = netip.Addr.Is4
	case "TCP6":
		family = netip.Addr.Is6
	default:
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v1: unsupported protocol %q", fields[1])
	}

	source, err := parseProxyProtocolV1Addr(fields[2], fields[4], family)
	if err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v1: source: %w", err)
	}
	if _, err := parseProxyProtocolV1Addr(fields[3], fields[5], family); err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v1: destination: %w", err)
	}

	return source, true, nil
}

func parseProxyProtocolV1Addr(rawAddr, rawPort string, family func(netip.Addr) bool) (netip.AddrPort, error) {
	addr, err := netip.ParseAddr(rawAddr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !family(addr) || addr.Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("address %q does not match the protocol family", rawAddr)
	}

	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid port %q", rawPort)
	}

	return netip.AddrPortFrom(addr, uint16(port)), nil
}

func readProxyProtocolV2(reader *bufio.Reader) (netip.AddrPort, bool, error) {
	var header [proxyProtocolV2HeaderLength]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v2: read header: %w", err)
	}

	if version := header[12] >> 4; version != 2 {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v2: unsupported version %d", version)
	}
	command := header[12] & 0x0f
	family := header[13]
	length := int(binary.BigEndian.Uint16(header[14:16]))

	addressLength := 0
	if command == proxyProtocolV2CommandProxy {
		switch family {
		case proxyProtocolV2TCPOverIPv4:
			addressLength = 12
		case proxyProtocolV2TCPOverIPv6:
			addressLength = 36
		}
	} else if command != proxyProtocolV2CommandLocal {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v2: unsupported command %d", command)
	}
	if length < addressLength {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v2: %d byte address block is too short", length)
	}

	// LOCAL connections, such as load balancer health checks, and families
	// other than TCP carry no client address to use.
	addresses := make([]byte, addressLength)
	if _, err := io.ReadFull(reader, addresses); err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v2: read addresses: %w", err)
	}
	// Skip TLVs, such as the AWS VPC endpoint ID.
	if _, err := reader.Discard(length - addressLength); err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v2: read TLVs: %w", err)
	}

	switch addressLength {
	case 12:
		addr := netip.AddrFrom4([4]byte(addresses[0:4]))
		return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(addresses[8:10])), true, nil
	case 36:
		addr := netip.AddrFrom16([16]byte(addresses[0:16]))
		return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(addresses[32:34])), true, nil
	default:
		return netip.AddrPort{}, false, nil
	}
}
