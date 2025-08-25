package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTrustedProxyManager(t *testing.T) {
	// Create a test server that returns IP ranges
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "192.168.1.0/24")
		fmt.Fprintln(w, "10.0.0.0/8")
		fmt.Fprintln(w, "# Comment line")
		fmt.Fprintln(w, "172.16.0.0/12")
		fmt.Fprintln(w, "2001:db8::/32")
	}))
	defer ts.Close()

	// Create manager with test server URL
	mgr := NewTrustedProxyManager([]string{ts.URL}, 1*time.Hour, "test-agent", t.TempDir())

	// Start the manager
	if err := mgr.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer mgr.Stop()

	// Test cases
	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.100", true},
		{"10.10.10.10", true},
		{"172.16.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2001:db8::1", true},
		{"2001:db9::1", false},
	}

	for _, test := range tests {
		result := mgr.IsTrustedProxy(test.ip)
		if result != test.expected {
			t.Errorf("IsTrustedProxy(%s) = %v, expected %v", test.ip, result, test.expected)
		}
	}

	// Test that we loaded the expected number of networks
	nets := mgr.GetTrustedNets()
	if len(nets) != 4 {
		t.Errorf("Expected 4 networks, got %d", len(nets))
	}
}

func TestIPFilterWithTrustedProxy(t *testing.T) {
	// Create a test server for trusted proxy IPs
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "192.168.1.0/24")
	}))
	defer ts.Close()

	// Create IP filter and trusted proxy manager
	ipFilter := NewIPFilter("test_v4", "test_v6")
	mgr := NewTrustedProxyManager([]string{ts.URL}, 1*time.Hour, "test-agent", t.TempDir())

	if err := mgr.Start(); err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}
	defer mgr.Stop()

	ipFilter.SetTrustedProxyManager(mgr)

	// Test getClientIP with trusted proxy
	tests := []struct {
		remoteAddr string
		xff        string
		xri        string
		expected   string
	}{
		// Request from trusted proxy with X-Forwarded-For
		{"192.168.1.100:12345", "203.0.113.1, 198.51.100.2", "", "198.51.100.2"},
		// Request from trusted proxy with X-Real-IP
		{"192.168.1.100:12345", "", "203.0.113.1", "203.0.113.1"},
		// Request from untrusted IP (should ignore headers)
		{"8.8.8.8:12345", "203.0.113.1", "198.51.100.2", "8.8.8.8"},
		// Request from trusted proxy with all trusted IPs in XFF
		{"192.168.1.100:12345", "192.168.1.50, 192.168.1.60", "", "192.168.1.50"},
	}

	for _, test := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = test.remoteAddr
		if test.xff != "" {
			req.Header.Set("X-Forwarded-For", test.xff)
		}
		if test.xri != "" {
			req.Header.Set("X-Real-IP", test.xri)
		}

		result := ipFilter.getClientIP(req)
		if result != test.expected {
			t.Errorf("getClientIP() with RemoteAddr=%s, XFF=%s, XRI=%s = %s, expected %s",
				test.remoteAddr, test.xff, test.xri, result, test.expected)
		}
	}
}
