package config

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"flowguard/cache"
	"flowguard/iplist"
)

func TestTrustedProxySetDeduplicatesLocalEntries(t *testing.T) {
	manager := &Manager{}
	set, _, err := manager.buildTrustedProxySet(&TrustedProxiesConfig{IPNets: []string{
		"192.0.2.10", "192.0.2.10/32", "2001:db8::1", "2001:db8::1",
	}}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if set.Size() != 2 {
		t.Fatalf("expected 2 deduplicated networks, got %d", set.Size())
	}
}

func TestRefreshTrustedProxiesUpdatesState(t *testing.T) {
	manager := &Manager{
		config: &Config{
			TrustedProxies: &TrustedProxiesConfig{
				IPNets:                 []string{"192.0.2.10", "2001:db8::1"},
				RefreshIntervalSeconds: 120,
			},
		},
	}

	if err := manager.RefreshTrustedProxies(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !manager.IsTrustedProxy("192.0.2.10") {
		t.Fatal("expected ipv4 trusted proxy to be loaded into manager state")
	}
	if !manager.IsTrustedProxy("2001:db8::1") {
		t.Fatal("expected ipv6 trusted proxy to be loaded into manager state")
	}
	if got := manager.GetRefreshInterval(); got != 120*time.Second {
		t.Fatalf("expected configured refresh interval, got %v", got)
	}
}

func TestRefreshTrustedProxiesRejectsInvalidEntry(t *testing.T) {
	manager := &Manager{
		config: &Config{
			TrustedProxies: &TrustedProxiesConfig{
				IPNets: []string{"not-an-ip"},
			},
		},
	}

	err := manager.RefreshTrustedProxies()
	if err == nil || !strings.Contains(err.Error(), "invalid IP address") {
		t.Fatalf("expected invalid IP error, got %v", err)
	}
}

func TestRefreshTrustedProxiesUpdatesURLSource(t *testing.T) {
	var body atomic.Value
	body.Store("192.0.2.0/24\n")
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body.Load().(string)))
	}))

	manager := newTrustedProxyTestManager(t, server, "")
	if err := manager.RefreshTrustedProxies(); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	if !manager.IsTrustedProxy("192.0.2.1") {
		t.Fatal("expected initial URL range to be trusted")
	}

	body.Store("198.51.100.0/24\n")
	if err := manager.RefreshTrustedProxies(); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if manager.IsTrustedProxy("192.0.2.1") || !manager.IsTrustedProxy("198.51.100.1") {
		t.Fatal("expected refreshed URL range to replace the old range")
	}
}

func TestTrustedProxyRefreshLoopUpdatesURLSource(t *testing.T) {
	synctest.Test(t, testTrustedProxyRefreshLoopUpdatesURLSource)
}

func testTrustedProxyRefreshLoopUpdatesURLSource(t *testing.T) {
	var body atomic.Value
	body.Store("192.0.2.0/24\n")
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body.Load().(string)))
	}))

	manager := newTrustedProxyTestManager(t, server, "")
	if err := manager.RefreshTrustedProxies(); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	body.Store("198.51.100.0/24\n")

	manager.StartTrustedProxyRefresh()
	defer func() {
		close(manager.stopTrustedProxyRefresh)
		manager.trustedProxyRefreshWG.Wait()
	}()

	synctest.Sleep(time.Second)
	if !manager.IsTrustedProxy("198.51.100.1") || manager.IsTrustedProxy("192.0.2.1") {
		t.Fatal("periodic refresh did not atomically replace the URL source")
	}
}

func TestRefreshTrustedProxiesRetainsLastKnownGoodSource(t *testing.T) {
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.0/24\n"))
	}))

	manager := newTrustedProxyTestManager(t, server, "")
	if err := manager.RefreshTrustedProxies(); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}

	// Simulate the cache becoming unavailable after a valid source was loaded.
	manager.cache = nil
	if err := manager.RefreshTrustedProxies(); err != nil {
		t.Fatalf("failed refresh should retain the source: %v", err)
	}
	if !manager.IsTrustedProxy("192.0.2.1") {
		t.Fatal("expected last-known-good URL range to remain trusted")
	}
}

func TestRefreshTrustedProxiesRetainsOnlyFailedSource(t *testing.T) {
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/live" {
			_, _ = w.Write([]byte("198.51.100.0/24\n"))
			return
		}
		http.Error(w, "source unavailable", http.StatusServiceUnavailable)
	}))

	manager := newTrustedProxyTestManager(t, server, "/live")
	failedURL := server.URL + "/failed"
	manager.config.TrustedProxies.IPNets = []string{server.URL + "/live", failedURL}
	lastGood := iplist.NewSet([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	manager.trustedProxySources[failedURL] = lastGood
	manager.trustedProxySet = lastGood

	if err := manager.RefreshTrustedProxies(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !manager.IsTrustedProxy("198.51.100.1") || !manager.IsTrustedProxy("203.0.113.1") {
		t.Fatal("successful source update and failed source fallback were not both applied")
	}
}

func TestRefreshTrustedProxiesAcceptsSuccessfulEmptySource(t *testing.T) {
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# intentionally empty\n"))
	}))

	manager := newTrustedProxyTestManager(t, server, "")
	lastGood := iplist.NewSet([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	manager.trustedProxySources[server.URL] = lastGood
	manager.trustedProxySet = lastGood

	if err := manager.RefreshTrustedProxies(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if manager.IsTrustedProxy("192.0.2.1") {
		t.Fatal("a successful empty source should remove its previous networks")
	}
	if source := manager.trustedProxySources[server.URL]; source == nil || source.Size() != 0 {
		t.Fatal("successful empty source state was not retained")
	}
}

func TestTrustedProxyURLFailureOnColdStartIsFailClosed(t *testing.T) {
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))

	manager := newTrustedProxyTestManager(t, server, "")
	set, sources, err := manager.buildTrustedProxySet(manager.config.TrustedProxies, false)
	if err != nil {
		t.Fatalf("cold-start build: %v", err)
	}
	if set.Size() != 0 || len(sources) != 0 {
		t.Fatalf("failed source should contribute no trust, got %d networks", set.Size())
	}
}

func TestTrustedProxyRemovedURLDoesNotRetainOldSource(t *testing.T) {
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.0/24\n"))
	}))

	manager := newTrustedProxyTestManager(t, server, "")
	if err := manager.RefreshTrustedProxies(); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}

	set, sources, err := manager.buildTrustedProxySet(&TrustedProxiesConfig{
		IPNets: []string{"198.51.100.1"},
	}, false)
	if err != nil {
		t.Fatalf("build without old URL: %v", err)
	}
	if set.Contains(mustParseAddr(t, "192.0.2.1")) || !set.Contains(mustParseAddr(t, "198.51.100.1")) {
		t.Fatal("removed URL source leaked into the new effective set")
	}
	if len(sources) != 0 {
		t.Fatalf("expected removed URL source state to be discarded, got %d", len(sources))
	}
}

func newTrustedProxyTestManager(t *testing.T, server *httptest.Server, sourcePath string) *Manager {
	t.Helper()
	httpClient := server.Client()
	c, err := cache.NewCache(t.TempDir(), "FlowGuard/test", false, cache.WithHTTPClient(httpClient))
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	source := server.URL + sourcePath
	return &Manager{
		cache:                   c,
		stopTrustedProxyRefresh: make(chan struct{}),
		wakeTrustedProxyRefresh: make(chan struct{}, 1),
		config: &Config{TrustedProxies: &TrustedProxiesConfig{
			IPNets:                 []string{source},
			RefreshIntervalSeconds: 1,
		}},
		trustedProxySources: make(map[string]*iplist.Set),
	}
}

func mustParseAddr(t *testing.T, raw string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatalf("parse address %q: %v", raw, err)
	}
	return addr
}

func TestLoadAcceptsTrustedProxyHeaderAuthOnly(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "trusted_proxies": {
    "header_auth": {
      "values": ["secret-one", "secret-two"]
    }
  }
}`)

	manager, err := loadTestManager(configPath)
	if err != nil {
		t.Fatalf("load manager: %v", err)
	}

	header, values, ok := manager.GetTrustedProxyHeaderAuth()
	if !ok {
		t.Fatal("expected trusted proxy header auth to be configured")
	}
	if header != DefaultTrustedProxyHeaderAuthHeader {
		t.Fatalf("expected configured header, got %q", header)
	}
	if len(values) != 2 || values[0] != "secret-one" || values[1] != "secret-two" {
		t.Fatalf("unexpected header auth values: %v", values)
	}
}

func TestLoadAcceptsCustomTrustedProxyHeaderAuthHeader(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "trusted_proxies": {
    "header_auth": {
      "header": "Custom-Trusted-Proxy-Secret",
      "values": ["secret"]
    }
  }
}`)

	manager, err := loadTestManager(configPath)
	if err != nil {
		t.Fatalf("load manager: %v", err)
	}

	header, _, ok := manager.GetTrustedProxyHeaderAuth()
	if !ok {
		t.Fatal("expected trusted proxy header auth to be configured")
	}
	if header != "Custom-Trusted-Proxy-Secret" {
		t.Fatalf("expected configured header, got %q", header)
	}
}

func TestLoadRejectsTrustedProxiesWithoutTrustSource(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "trusted_proxies": {
    "refresh_interval_seconds": 120
  }
}`)

	_, err := loadTestManager(configPath)
	if err == nil || err.Error() != "trusted_proxies must configure ipnets or header_auth" {
		t.Fatalf("expected missing trust source error, got %v", err)
	}
}

func TestLoadRejectsEmptyTrustedProxyHeaderAuthHeader(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "trusted_proxies": {
    "header_auth": {
      "header": "",
      "values": ["secret"]
    }
  }
}`)

	_, err := loadTestManager(configPath)
	if err == nil || err.Error() != "trusted_proxies.header_auth.header must not be empty" {
		t.Fatalf("expected empty header error, got %v", err)
	}
}

func TestLoadRejectsEmptyTrustedProxyHeaderAuthValue(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "trusted_proxies": {
    "header_auth": {
      "values": ["secret", ""]
    }
  }
}`)

	_, err := loadTestManager(configPath)
	if err == nil || err.Error() != "trusted_proxies.header_auth.values[1] must not be empty" {
		t.Fatalf("expected empty value error, got %v", err)
	}
}
