package config

import (
	"strings"
	"testing"
)

func TestValidateBindAddresses(t *testing.T) {
	tests := []struct {
		name          string
		bindAddresses []string
		wantErr       string
	}{
		{name: "IPv4 and IPv6", bindAddresses: []string{"10.0.0.5", "fd00::5"}},
		{name: "not an address", bindAddresses: []string{"10.0.0"}, wantErr: "server.bind_addresses[0] must be a specific IP address"},
		{name: "unspecified address", bindAddresses: []string{"10.0.0.5", "0.0.0.0"}, wantErr: "server.bind_addresses[1] must be a specific IP address"},
		{name: "zoned address", bindAddresses: []string{"fe80::1%eth0"}, wantErr: "must be a specific IP address"},
		{name: "duplicate mapped address", bindAddresses: []string{"10.0.0.5", "::ffff:10.0.0.5"}, wantErr: "duplicate address 10.0.0.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBindAddresses(&Config{Server: &ServerConfig{BindAddresses: tt.bindAddresses}})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateBindAddresses: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}
