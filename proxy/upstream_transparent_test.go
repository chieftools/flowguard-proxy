package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"flowguard/config"
	"flowguard/middleware"
)

func TestTransparentUpstreamRouteUsesMatchingAndPairedFamilies(t *testing.T) {
	resolution, err := ResolveAddressPairs(&config.Config{}, []string{"192.0.2.10", "2001:db8::10"})
	if err != nil {
		t.Fatalf("ResolveAddressPairs: %v", err)
	}
	server := NewServer(&ServerConfig{
		scheme:       "http",
		bindAddr:     "192.0.2.10",
		addressPairs: resolution,
	})

	ipv4, _ := netip.ParseAddr("198.51.100.20")
	if got, err := server.transparentUpstreamRoute(ipv4); err != nil || got.destination != "192.0.2.10:80" || got.headerFallback {
		t.Fatalf("unexpected IPv4 upstream route %#v, %v", got, err)
	}

	ipv6, _ := netip.ParseAddr("2001:db8::20")
	if got, err := server.transparentUpstreamRoute(ipv6); err != nil || got.destination != "[2001:db8::10]:80" || got.headerFallback {
		t.Fatalf("unexpected IPv6 upstream route %#v, %v", got, err)
	}
}

func TestTransparentUpstreamRouteUsesHeaderFallbackForSingleStack(t *testing.T) {
	tests := []struct {
		name        string
		bindAddr    string
		clientIP    string
		destination string
	}{
		{name: "IPv4 server with IPv6 client", bindAddr: "192.0.2.10", clientIP: "2001:db8::20", destination: "192.0.2.10:80"},
		{name: "IPv6 server with IPv4 client", bindAddr: "2001:db8::10", clientIP: "198.51.100.20", destination: "[2001:db8::10]:80"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolution, err := ResolveAddressPairs(&config.Config{}, []string{tt.bindAddr})
			if err != nil {
				t.Fatalf("ResolveAddressPairs: %v", err)
			}
			server := NewServer(&ServerConfig{scheme: "http", bindAddr: tt.bindAddr, addressPairs: resolution})
			clientIP := netip.MustParseAddr(tt.clientIP)
			route, err := server.transparentUpstreamRoute(clientIP)
			if err != nil {
				t.Fatalf("transparentUpstreamRoute: %v", err)
			}
			if !route.headerFallback || route.destination != tt.destination {
				t.Fatalf("unexpected fallback route: %#v", route)
			}
		})
	}
}

func TestResolveUpstreamClientIPModeOverride(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		override   string
		want       string
		wantErr    bool
	}{
		{name: "configured mode", configured: config.UpstreamClientIPModeHeaders, want: config.UpstreamClientIPModeHeaders},
		{name: "transparent override", configured: config.UpstreamClientIPModeHeaders, override: config.UpstreamClientIPModeTransparent, want: config.UpstreamClientIPModeTransparent},
		{name: "headers override", configured: config.UpstreamClientIPModeTransparent, override: config.UpstreamClientIPModeHeaders, want: config.UpstreamClientIPModeHeaders},
		{name: "invalid override", configured: config.UpstreamClientIPModeHeaders, override: "invalid", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveUpstreamClientIPMode(tt.configured, tt.override)
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveUpstreamClientIPMode() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("resolveUpstreamClientIPMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTransparentUpstreamAddressFailsWithoutCounterpart(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:   "https",
		bindAddr: "192.0.2.10",
	})
	ipv6, _ := netip.ParseAddr("2001:db8::20")
	if _, err := server.transparentUpstreamRoute(ipv6); err == nil {
		t.Fatal("expected cross-family upstream selection to fail without a pair")
	}
}

func TestTransparentUpstreamRouteDoesNotFallbackForAmbiguousDualStack(t *testing.T) {
	resolution, err := ResolveAddressPairs(&config.Config{}, []string{
		"192.0.2.10", "192.0.2.20", "2001:db8::10", "2001:db8::20",
	})
	if err != nil {
		t.Fatalf("ResolveAddressPairs: %v", err)
	}
	if resolution.Complete() {
		t.Fatalf("expected ambiguous resolution, got %#v", resolution)
	}
	server := NewServer(&ServerConfig{scheme: "http", bindAddr: "192.0.2.10", addressPairs: resolution})
	if _, err := server.transparentUpstreamRoute(netip.MustParseAddr("2001:db8::30")); err == nil {
		t.Fatal("ambiguous dual-stack route used header fallback")
	}
}

func TestTransparentRoundTripperFallbackUsesCanonicalHeaders(t *testing.T) {
	resolution, err := ResolveAddressPairs(&config.Config{}, []string{"192.0.2.10"})
	if err != nil {
		t.Fatalf("ResolveAddressPairs: %v", err)
	}
	server := NewServer(&ServerConfig{
		scheme:       "http",
		bindAddr:     "192.0.2.10",
		addressPairs: resolution,
	})

	called := false
	fallback := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		if got := req.Header.Get("X-Forwarded-For"); got != "2001:db8::20" {
			t.Fatalf("X-Forwarded-For = %q", got)
		}
		if got := req.Header.Get("X-Real-IP"); got != "2001:db8::20" {
			t.Fatalf("X-Real-IP = %q", got)
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})
	proxy := server.createReverseProxyWithHost(&url.URL{Scheme: "http", Host: "example.com"}, "example.com")
	proxy.Transport = &transparentRoundTripper{
		server:   server,
		pool:     newTransparentTransportPool(1, time.Minute, 1),
		fallback: fallback,
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set("X-Forwarded-For", "attacker")
	req = req.WithContext(context.WithValue(req.Context(), middleware.ContextKeyClientIP, "2001:db8::20"))
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, req)

	if !called || recorder.Code != http.StatusNoContent {
		t.Fatalf("fallback called=%v status=%d", called, recorder.Code)
	}
}

func TestTransparentRoundTripperDoesNotFallbackAfterTransparentFailure(t *testing.T) {
	resolution, err := ResolveAddressPairs(&config.Config{}, []string{"192.0.2.10"})
	if err != nil {
		t.Fatalf("ResolveAddressPairs: %v", err)
	}
	server := NewServer(&ServerConfig{scheme: "http", bindAddr: "192.0.2.10", addressPairs: resolution})
	wantErr := errors.New("transparent transport failed")
	pool := newTransparentTransportPool(1, time.Minute, 1)
	pool.newTransport = func(transparentTransportKey, bool) (*http.Transport, error) {
		return nil, wantErr
	}
	fallbackCalled := false
	transport := &transparentRoundTripper{
		server: server,
		pool:   pool,
		fallback: roundTripFunc(func(*http.Request) (*http.Response, error) {
			fallbackCalled = true
			return nil, nil
		}),
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.ContextKeyClientIP, "198.51.100.20"))

	if _, err := transport.RoundTrip(req); !errors.Is(err, wantErr) {
		t.Fatalf("RoundTrip error = %v, want %v", err, wantErr)
	}
	if fallbackCalled {
		t.Fatal("transparent failure triggered header fallback")
	}
}

func TestFallbackDialerPinsConfiguredBindAddress(t *testing.T) {
	for _, source := range []string{"192.0.2.10", "2001:db8::10"} {
		dialer := newUpstreamDialer(source, true)
		local, ok := dialer.LocalAddr.(*net.TCPAddr)
		if !ok || !local.IP.Equal(net.ParseIP(source)) {
			t.Fatalf("unexpected pinned source for %s: %#v", source, dialer.LocalAddr)
		}
	}
	if unpinned := newUpstreamDialer("192.0.2.10", false); unpinned.LocalAddr != nil {
		t.Fatalf("ordinary header transport should retain kernel source selection: %#v", unpinned.LocalAddr)
	}
}

func TestTransparentTransportPoolEvictsLeastRecentlyUsedInactiveEntry(t *testing.T) {
	pool := newTransparentTransportPool(2, time.Hour, 1)
	pool.newTransport = func(_ transparentTransportKey, disableKeepAlives bool) (*http.Transport, error) {
		return &http.Transport{DisableKeepAlives: disableKeepAlives}, nil
	}
	t.Cleanup(pool.Close)

	key1 := transparentTestKey("192.0.2.1")
	key2 := transparentTestKey("192.0.2.2")
	key3 := transparentTestKey("192.0.2.3")
	_, entry1, ephemeral, err := pool.acquire(key1)
	if err != nil || ephemeral {
		t.Fatalf("acquire key1: ephemeral=%v err=%v", ephemeral, err)
	}
	pool.release(entry1)
	_, entry2, ephemeral, err := pool.acquire(key2)
	if err != nil || ephemeral {
		t.Fatalf("acquire key2: ephemeral=%v err=%v", ephemeral, err)
	}
	pool.release(entry2)

	_, entry3, ephemeral, err := pool.acquire(key3)
	if err != nil || ephemeral {
		t.Fatalf("acquire key3: ephemeral=%v err=%v", ephemeral, err)
	}
	pool.release(entry3)

	if _, ok := pool.entries[key1]; ok {
		t.Fatal("expected oldest inactive entry to be evicted")
	}
	if _, ok := pool.entries[key2]; !ok {
		t.Fatal("expected second entry to remain")
	}
	if _, ok := pool.entries[key3]; !ok {
		t.Fatal("expected new entry to be pooled")
	}
}

func TestTransparentTransportPoolUsesEphemeralTransportWhenAllEntriesActive(t *testing.T) {
	pool := newTransparentTransportPool(1, time.Hour, 1)
	pool.newTransport = func(_ transparentTransportKey, disableKeepAlives bool) (*http.Transport, error) {
		return &http.Transport{DisableKeepAlives: disableKeepAlives}, nil
	}
	t.Cleanup(pool.Close)

	_, active, ephemeral, err := pool.acquire(transparentTestKey("192.0.2.1"))
	if err != nil || ephemeral {
		t.Fatalf("acquire active entry: ephemeral=%v err=%v", ephemeral, err)
	}
	transport, entry, ephemeral, err := pool.acquire(transparentTestKey("192.0.2.2"))
	if err != nil {
		t.Fatalf("acquire overflow entry: %v", err)
	}
	if !ephemeral || entry != nil || !transport.DisableKeepAlives {
		t.Fatalf("expected non-pooled no-keepalive transport, got ephemeral=%v entry=%v transport=%#v",
			ephemeral, entry, transport)
	}
	pool.release(active)
}

func transparentTestKey(source string) transparentTransportKey {
	addr, _ := netip.ParseAddr(source)
	return transparentTransportKey{
		source:      addr,
		destination: "192.0.2.10:80",
		scheme:      "http",
	}
}
