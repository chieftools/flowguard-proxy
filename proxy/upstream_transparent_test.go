package proxy

import (
	"net/http"
	"net/netip"
	"testing"
	"time"

	"flowguard/config"
)

func TestTransparentUpstreamAddressUsesMatchingFamily(t *testing.T) {
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
	if got, err := server.transparentUpstreamAddress(ipv4); err != nil || got != "192.0.2.10:80" {
		t.Fatalf("unexpected IPv4 upstream address %q, %v", got, err)
	}

	ipv6, _ := netip.ParseAddr("2001:db8::20")
	if got, err := server.transparentUpstreamAddress(ipv6); err != nil || got != "[2001:db8::10]:80" {
		t.Fatalf("unexpected IPv6 upstream address %q, %v", got, err)
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
	if _, err := server.transparentUpstreamAddress(ipv6); err == nil {
		t.Fatal("expected cross-family upstream selection to fail without a pair")
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
