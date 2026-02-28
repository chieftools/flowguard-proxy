package normalization

import "testing"

func TestRegisterableDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"subdomain", "sub.example.com", "example.com"},
		{"multi-part TLD", "sub.example.co.uk", "example.co.uk"},
		{"already registerable", "example.com", "example.com"},
		{"IPv4", "192.168.1.1", "192.168.1.1"},
		{"IPv6", "[::1]", "::1"},
		{"IPv4 with port", "192.168.1.1:8080", "192.168.1.1"},
		{"domain with port", "example.com:443", "example.com"},
		{"bare hostname", "localhost", "localhost"},
		{"deep subdomain", "a.b.c.example.com", "example.com"},
		{"subdomain with port", "sub.example.com:8443", "example.com"},
		{"multi-part TLD with port", "sub.example.co.uk:443", "example.co.uk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RegisterableDomain(tt.input)
			if got != tt.expected {
				t.Errorf("RegisterableDomain(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
