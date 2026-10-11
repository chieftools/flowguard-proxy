package normalization

import "testing"

func TestHost(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"lowercase", "staging.example.com", "staging.example.com"},
		{"uppercase", "STAGING.EXAMPLE.COM", "staging.example.com"},
		{"mixed case", "Staging.Example.com", "staging.example.com"},
		{"trailing dot", "staging.example.com.", "staging.example.com"},
		{"port", "staging.example.com:443", "staging.example.com"},
		{"everything", "STAGING.example.COM.:8443", "staging.example.com"},
		{"IPv4 with port", "192.0.2.1:80", "192.0.2.1"},
		{"IPv6", "[2001:DB8::1]", "2001:db8::1"},
		{"IPv6 with port", "[2001:db8::1]:443", "2001:db8::1"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Host(tt.input); got != tt.expected {
				t.Errorf("Host(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

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
		{"uppercase multi-part TLD", "STAGING.EXAMPLE.CO.UK", "example.co.uk"},
		{"trailing dot", "staging.example.com.", "example.com"},
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
