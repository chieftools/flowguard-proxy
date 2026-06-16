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
