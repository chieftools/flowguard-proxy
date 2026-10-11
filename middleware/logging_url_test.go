package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetRequestURLInfo_NormalizesDomainAndKeepsRawHostInFullURL(t *testing.T) {
	tests := []struct {
		host               string
		domain             string
		registerableDomain string
		full               string
	}{
		{"staging.example.com", "staging.example.com", "example.com", "https://staging.example.com/admin?x=1"},
		{"STAGING.Example.com.:443", "staging.example.com", "example.com", "https://STAGING.Example.com.:443/admin?x=1"},
		{"[2001:DB8::1]:443", "2001:db8::1", "2001:db8::1", "https://[2001:DB8::1]:443/admin?x=1"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.test/admin?x=1", nil)
			req.URL.Scheme = ""
			req.URL.Host = ""
			req.Host = tt.host

			info := getRequestURLInfo(req)
			if info.Domain != tt.domain {
				t.Errorf("domain = %q, want %q", info.Domain, tt.domain)
			}
			if info.RegisterableDomain != tt.registerableDomain {
				t.Errorf("registerable_domain = %q, want %q", info.RegisterableDomain, tt.registerableDomain)
			}
			if info.Full != tt.full {
				t.Errorf("full = %q, want %q", info.Full, tt.full)
			}
		})
	}
}
