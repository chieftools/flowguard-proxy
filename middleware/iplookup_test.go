package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"flowguard/config"
)

func newIPLookupTestConfigManager(t *testing.T, trustedProxiesJSON string) *config.Manager {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), "config.json")
	body := `{"trusted_proxies":` + trustedProxiesJSON + `}`
	if err := os.WriteFile(configPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	manager, err := config.NewManager(configPath, "FlowGuard/test", "test", "", false)
	if err != nil {
		t.Fatalf("new config manager: %v", err)
	}
	t.Cleanup(manager.Stop)

	return manager
}

func TestExtractIPsUsesHeaderAuthForXForwardedFor(t *testing.T) {
	manager := newIPLookupTestConfigManager(t, `{
  "header_auth": {
    "values": ["proxy-secret"]
  }
}`)
	ipLookup := &IPLookupMiddleware{configMgr: manager}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set(config.DefaultTrustedProxyHeaderAuthHeader, "proxy-secret")

	clientIP, proxyIP := ipLookup.extractIPs(req)

	if clientIP != "203.0.113.9" {
		t.Fatalf("expected forwarded client IP, got %q", clientIP)
	}
	if proxyIP != "198.51.100.10" {
		t.Fatalf("expected remote peer as proxy IP, got %q", proxyIP)
	}
	if got := req.Header.Get(config.DefaultTrustedProxyHeaderAuthHeader); got != "" {
		t.Fatalf("expected trusted proxy auth header to be stripped, got %q", got)
	}
}

func TestExtractIPsUsesHeaderAuthForXRealIP(t *testing.T) {
	manager := newIPLookupTestConfigManager(t, `{
  "header_auth": {
    "values": ["proxy-secret"]
  }
}`)
	ipLookup := &IPLookupMiddleware{configMgr: manager}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Real-IP", "203.0.113.10")
	req.Header.Set(config.DefaultTrustedProxyHeaderAuthHeader, "proxy-secret")

	clientIP, proxyIP := ipLookup.extractIPs(req)

	if clientIP != "203.0.113.10" {
		t.Fatalf("expected X-Real-IP client IP, got %q", clientIP)
	}
	if proxyIP != "198.51.100.10" {
		t.Fatalf("expected remote peer as proxy IP, got %q", proxyIP)
	}
	if got := req.Header.Get(config.DefaultTrustedProxyHeaderAuthHeader); got != "" {
		t.Fatalf("expected trusted proxy auth header to be stripped, got %q", got)
	}
}

func TestExtractIPsIgnoresForwardedHeadersWhenHeaderAuthInvalid(t *testing.T) {
	manager := newIPLookupTestConfigManager(t, `{
  "header_auth": {
    "values": ["proxy-secret"]
  }
}`)
	ipLookup := &IPLookupMiddleware{configMgr: manager}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("X-Real-IP", "203.0.113.10")
	req.Header.Set(config.DefaultTrustedProxyHeaderAuthHeader, "wrong-secret")

	clientIP, proxyIP := ipLookup.extractIPs(req)

	if clientIP != "198.51.100.10" {
		t.Fatalf("expected remote address as client IP, got %q", clientIP)
	}
	if proxyIP != "" {
		t.Fatalf("expected empty proxy IP, got %q", proxyIP)
	}
	if got := req.Header.Get(config.DefaultTrustedProxyHeaderAuthHeader); got != "" {
		t.Fatalf("expected trusted proxy auth header to be stripped, got %q", got)
	}
}

func TestExtractIPsStripsHeaderAuthWhenIPTrusted(t *testing.T) {
	manager := newIPLookupTestConfigManager(t, `{
  "ipnets": ["198.51.100.10"],
  "header_auth": {
    "values": ["proxy-secret"]
  }
}`)
	ipLookup := &IPLookupMiddleware{configMgr: manager}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set(config.DefaultTrustedProxyHeaderAuthHeader, "wrong-secret")

	clientIP, proxyIP := ipLookup.extractIPs(req)

	if clientIP != "203.0.113.9" {
		t.Fatalf("expected forwarded client IP from trusted peer, got %q", clientIP)
	}
	if proxyIP != "198.51.100.10" {
		t.Fatalf("expected remote peer as proxy IP, got %q", proxyIP)
	}
	if got := req.Header.Get(config.DefaultTrustedProxyHeaderAuthHeader); got != "" {
		t.Fatalf("expected trusted proxy auth header to be stripped, got %q", got)
	}
}

func TestIPLookupHandleStripsHeaderBeforeNextHandler(t *testing.T) {
	manager := newIPLookupTestConfigManager(t, `{
  "header_auth": {
    "values": ["proxy-secret"]
  }
}`)
	ipLookup := &IPLookupMiddleware{configMgr: manager}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set(config.DefaultTrustedProxyHeaderAuthHeader, "proxy-secret")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(config.DefaultTrustedProxyHeaderAuthHeader); got != "" {
			t.Fatalf("expected trusted proxy auth header to be stripped before next handler, got %q", got)
		}
		if got := GetClientIP(r); got != "203.0.113.9" {
			t.Fatalf("expected forwarded client IP in context, got %q", got)
		}
	})

	ipLookup.Handle(httptest.NewRecorder(), req, next)
}

func TestExtractIPsRejectsMalformedTrustedForwardingChain(t *testing.T) {
	manager := newIPLookupTestConfigManager(t, `{
  "ipnets": ["198.51.100.10"]
}`)
	ipLookup := &IPLookupMiddleware{configMgr: manager}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, not-an-ip")

	clientIP, proxyIP := ipLookup.extractIPs(req)

	if clientIP != "198.51.100.10" {
		t.Fatalf("expected fail-closed fallback to immediate peer, got %q", clientIP)
	}
	if proxyIP != "" {
		t.Fatalf("expected malformed chain not to mark request as proxied, got %q", proxyIP)
	}
}

func TestExtractIPsIgnoresClientControlledForwardingEntries(t *testing.T) {
	manager := newIPLookupTestConfigManager(t, `{
  "ipnets": ["198.51.100.0/24"]
}`)
	ipLookup := &IPLookupMiddleware{configMgr: manager}

	for _, xff := range []string{
		"127.0.0.1, 203.0.113.9",
		"::ffff:127.0.0.1, 203.0.113.9",
		"not-an-ip, 203.0.113.9",
		"192.0.2.1, 127.0.0.4, 203.0.113.9",
		"127.0.0.1, 203.0.113.9, 198.51.100.20",
	} {
		t.Run(xff, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			req.RemoteAddr = "198.51.100.10:12345"
			req.Header.Set("X-Forwarded-For", xff)

			clientIP, proxyIP := ipLookup.extractIPs(req)

			if clientIP != "203.0.113.9" {
				t.Fatalf("expected rightmost untrusted client IP, got %q", clientIP)
			}
			if proxyIP != "198.51.100.10" {
				t.Fatalf("expected immediate peer as proxy, got %q", proxyIP)
			}
		})
	}
}

func TestExtractIPsRejectsMalformedEntryBetweenTrustedProxies(t *testing.T) {
	manager := newIPLookupTestConfigManager(t, `{
  "ipnets": ["198.51.100.0/24"]
}`)
	ipLookup := &IPLookupMiddleware{configMgr: manager}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 127.0.0.1, 198.51.100.20")

	clientIP, proxyIP := ipLookup.extractIPs(req)

	if clientIP != "198.51.100.10" {
		t.Fatalf("expected fail-closed fallback to immediate peer, got %q", clientIP)
	}
	if proxyIP != "" {
		t.Fatalf("expected malformed chain not to mark request as proxied, got %q", proxyIP)
	}
}

func TestExtractIPsUsesLeftmostEntryWhenChainFullyTrusted(t *testing.T) {
	manager := newIPLookupTestConfigManager(t, `{
  "ipnets": ["198.51.100.0/24"]
}`)
	ipLookup := &IPLookupMiddleware{configMgr: manager}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.30, 198.51.100.20")

	clientIP, proxyIP := ipLookup.extractIPs(req)

	if clientIP != "198.51.100.30" {
		t.Fatalf("expected leftmost trusted IP, got %q", clientIP)
	}
	if proxyIP != "198.51.100.10" {
		t.Fatalf("expected immediate peer as proxy, got %q", proxyIP)
	}
}

func TestExtractIPsCombinesRepeatedXForwardedForHeaders(t *testing.T) {
	manager := newIPLookupTestConfigManager(t, `{
  "ipnets": ["198.51.100.0/24"]
}`)
	ipLookup := &IPLookupMiddleware{configMgr: manager}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Add("X-Forwarded-For", "192.0.2.66")
	req.Header.Add("X-Forwarded-For", "203.0.113.9")

	clientIP, proxyIP := ipLookup.extractIPs(req)

	if clientIP != "203.0.113.9" {
		t.Fatalf("expected client IP from last header line, got %q", clientIP)
	}
	if proxyIP != "198.51.100.10" {
		t.Fatalf("expected immediate peer as proxy, got %q", proxyIP)
	}
}

func TestExtractIPsRejectsRepeatedXRealIPHeaders(t *testing.T) {
	manager := newIPLookupTestConfigManager(t, `{
  "ipnets": ["198.51.100.0/24"]
}`)
	ipLookup := &IPLookupMiddleware{configMgr: manager}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Add("X-Real-IP", "192.0.2.66")
	req.Header.Add("X-Real-IP", "203.0.113.9")

	clientIP, proxyIP := ipLookup.extractIPs(req)

	if clientIP != "198.51.100.10" {
		t.Fatalf("expected fail-closed fallback to immediate peer, got %q", clientIP)
	}
	if proxyIP != "" {
		t.Fatalf("expected ambiguous X-Real-IP not to mark request as proxied, got %q", proxyIP)
	}
}

func TestExtractIPsCanonicalizesForwardedAddressWithPort(t *testing.T) {
	manager := newIPLookupTestConfigManager(t, `{
  "ipnets": ["198.51.100.10"]
}`)
	ipLookup := &IPLookupMiddleware{configMgr: manager}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "[2001:db8::10]:443")

	clientIP, proxyIP := ipLookup.extractIPs(req)

	if clientIP != "2001:db8::10" {
		t.Fatalf("expected canonical IPv6 client IP, got %q", clientIP)
	}
	if proxyIP != "198.51.100.10" {
		t.Fatalf("expected immediate peer as proxy, got %q", proxyIP)
	}
}

func TestExtractIPsRecordsProxyProtocolPeerAsProxy(t *testing.T) {
	manager := newIPLookupTestConfigManager(t, `{"ipnets": ["10.0.0.0/8", "198.51.100.10"]}`)
	ipLookup := &IPLookupMiddleware{configMgr: manager}

	tests := []struct {
		name         string
		remoteAddr   string
		forwardedFor string
		wantClientIP string
	}{
		{
			name:         "client from header",
			remoteAddr:   "203.0.113.9:51000",
			wantClientIP: "203.0.113.9",
		},
		{
			name:         "untrusted client forwarding headers ignored",
			remoteAddr:   "203.0.113.9:51000",
			forwardedFor: "192.0.2.1",
			wantClientIP: "203.0.113.9",
		},
		{
			name:         "trusted proxy behind load balancer",
			remoteAddr:   "198.51.100.10:51000",
			forwardedFor: "203.0.113.9",
			wantClientIP: "203.0.113.9",
		},
		{
			name:         "trusted proxy with malformed forwarding chain",
			remoteAddr:   "198.51.100.10:51000",
			forwardedFor: "not-an-ip",
			wantClientIP: "198.51.100.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.forwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.forwardedFor)
			}
			req = WithProxyProtocolPeer(req, "10.0.0.5")

			clientIP, proxyIP := ipLookup.extractIPs(req)

			if clientIP != tt.wantClientIP {
				t.Fatalf("got client IP %q, want %q", clientIP, tt.wantClientIP)
			}
			if proxyIP != "10.0.0.5" {
				t.Fatalf("got proxy IP %q, want the load balancer that sent the PROXY header", proxyIP)
			}
		})
	}
}
