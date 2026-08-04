package proxy

import (
	"container/list"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"flowguard/middleware"
)

const (
	transparentMaxIdleConnsPerPool = 4
	transparentMaxIdleConnsPerHost = 2
)

type transparentTransportKey struct {
	source      netip.Addr
	destination string
	scheme      string
}

type transparentTransportEntry struct {
	key       transparentTransportKey
	transport *http.Transport
	lastUsed  time.Time
	inFlight  int
}

type transparentTransportPool struct {
	mu           sync.Mutex
	entries      map[transparentTransportKey]*list.Element
	lru          *list.List
	maxEntries   int
	idleTimeout  time.Duration
	fwmark       uint32
	closed       bool
	newTransport func(transparentTransportKey, bool) (*http.Transport, error)
}

func newTransparentTransportPool(maxEntries int, idleTimeout time.Duration, fwmark uint32) *transparentTransportPool {
	return &transparentTransportPool{
		entries:     make(map[transparentTransportKey]*list.Element),
		lru:         list.New(),
		maxEntries:  maxEntries,
		idleTimeout: idleTimeout,
		fwmark:      fwmark,
	}
}

func (p *transparentTransportPool) RoundTrip(req *http.Request, key transparentTransportKey) (*http.Response, error) {
	transport, entry, ephemeral, err := p.acquire(key)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		defer p.release(entry)
	}
	if ephemeral {
		defer transport.CloseIdleConnections()
	}
	return transport.RoundTrip(req)
}

func (p *transparentTransportPool) acquire(key transparentTransportKey) (*http.Transport, *transparentTransportEntry, bool, error) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, nil, false, fmt.Errorf("transparent upstream transport pool is closed")
	}
	p.evictExpiredLocked(now)
	if element, ok := p.entries[key]; ok {
		entry := element.Value.(*transparentTransportEntry)
		entry.inFlight++
		entry.lastUsed = now
		p.lru.MoveToFront(element)
		return entry.transport, entry, false, nil
	}

	for len(p.entries) >= p.maxEntries {
		if !p.evictOldestInactiveLocked() {
			break
		}
	}

	newTransport := p.newTransport
	if newTransport == nil {
		newTransport = p.buildTransport
	}
	transport, err := newTransport(key, len(p.entries) >= p.maxEntries)
	if err != nil {
		return nil, nil, false, err
	}
	if len(p.entries) >= p.maxEntries {
		return transport, nil, true, nil
	}

	entry := &transparentTransportEntry{
		key:       key,
		transport: transport,
		lastUsed:  now,
		inFlight:  1,
	}
	element := p.lru.PushFront(entry)
	p.entries[key] = element
	return transport, entry, false, nil
}

func (p *transparentTransportPool) release(entry *transparentTransportEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry.inFlight > 0 {
		entry.inFlight--
	}
	entry.lastUsed = time.Now()
}

func (p *transparentTransportPool) evictExpiredLocked(now time.Time) {
	if p.idleTimeout <= 0 {
		return
	}
	for element := p.lru.Back(); element != nil; {
		previous := element.Prev()
		entry := element.Value.(*transparentTransportEntry)
		if entry.inFlight == 0 && now.Sub(entry.lastUsed) >= p.idleTimeout {
			p.removeLocked(element)
		}
		element = previous
	}
}

func (p *transparentTransportPool) evictOldestInactiveLocked() bool {
	for element := p.lru.Back(); element != nil; element = element.Prev() {
		entry := element.Value.(*transparentTransportEntry)
		if entry.inFlight == 0 {
			p.removeLocked(element)
			return true
		}
	}
	return false
}

func (p *transparentTransportPool) removeLocked(element *list.Element) {
	entry := element.Value.(*transparentTransportEntry)
	delete(p.entries, entry.key)
	p.lru.Remove(element)
	entry.transport.CloseIdleConnections()
}

func (p *transparentTransportPool) buildTransport(key transparentTransportKey, disableKeepAlives bool) (*http.Transport, error) {
	dialContext, err := transparentDialContext(key.source, p.fwmark)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialContext(ctx, network, key.destination)
		},
		DisableKeepAlives:     disableKeepAlives,
		ForceAttemptHTTP2:     upstreamForceAttemptH2,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxIdleConns:          transparentMaxIdleConnsPerPool,
		MaxIdleConnsPerHost:   transparentMaxIdleConnsPerHost,
		IdleConnTimeout:       upstreamIdleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if key.scheme == "https" {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return transport, nil
}

func (p *transparentTransportPool) CloseIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, element := range p.entries {
		element.Value.(*transparentTransportEntry).transport.CloseIdleConnections()
	}
}

func (p *transparentTransportPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	for element := p.lru.Front(); element != nil; element = element.Next() {
		element.Value.(*transparentTransportEntry).transport.CloseIdleConnections()
	}
	p.entries = make(map[transparentTransportKey]*list.Element)
	p.lru.Init()
}

type transparentRoundTripper struct {
	server   *Server
	pool     *transparentTransportPool
	fallback http.RoundTripper
}

func (t *transparentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.server == nil || t.pool == nil {
		return nil, fmt.Errorf("transparent upstream transport is not initialized")
	}
	rawClientIP := middleware.GetClientIP(req)
	clientIP, err := netip.ParseAddr(rawClientIP)
	if err != nil {
		return nil, fmt.Errorf("validated client IP %q is invalid: %w", rawClientIP, err)
	}
	clientIP = clientIP.Unmap()
	if !clientIP.IsGlobalUnicast() {
		return nil, fmt.Errorf("validated client IP %q is not a unicast source address", rawClientIP)
	}
	route, err := t.server.transparentUpstreamRoute(clientIP)
	if err != nil {
		return nil, err
	}
	if route.headerFallback {
		if t.fallback == nil {
			return nil, fmt.Errorf("transparent upstream header fallback is not initialized")
		}
		return t.fallback.RoundTrip(req)
	}
	return t.pool.RoundTrip(req, transparentTransportKey{
		source:      clientIP,
		destination: route.destination,
		scheme:      t.server.config.scheme,
	})
}

func (t *transparentRoundTripper) CloseIdleConnections() {
	if t == nil {
		return
	}
	if t.pool != nil {
		t.pool.CloseIdleConnections()
	}
	if closer, ok := t.fallback.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type transparentUpstreamRoute struct {
	destination    string
	headerFallback bool
}

func (s *Server) transparentUpstreamRoute(clientIP netip.Addr) (transparentUpstreamRoute, error) {
	bindIP, err := netip.ParseAddr(s.config.bindAddr)
	if err != nil {
		return transparentUpstreamRoute{}, fmt.Errorf("invalid server bind address %q: %w", s.config.bindAddr, err)
	}
	bindIP = bindIP.Unmap()
	target := bindIP
	if clientIP.Is4() != bindIP.Is4() {
		counterpart, ok := s.config.addressPairs.counterpart(bindIP.String())
		if !ok {
			if _, _, singleStack := s.config.addressPairs.singleStackFamily(); singleStack && s.config.addressPairs.Complete() {
				return transparentUpstreamRoute{
					destination:    net.JoinHostPort(bindIP.String(), s.upstreamPort()),
					headerFallback: true,
				}, nil
			}
			return transparentUpstreamRoute{}, fmt.Errorf("no %s upstream address pair is configured for bind address %s",
				clientIPFamily(clientIP), bindIP)
		}
		target, err = netip.ParseAddr(counterpart)
		if err != nil {
			return transparentUpstreamRoute{}, fmt.Errorf("invalid paired upstream address %q: %w", counterpart, err)
		}
	}
	return transparentUpstreamRoute{destination: net.JoinHostPort(target.String(), s.upstreamPort())}, nil
}

func clientIPFamily(addr netip.Addr) string {
	if addr.Is4() {
		return "IPv4"
	}
	return "IPv6"
}
