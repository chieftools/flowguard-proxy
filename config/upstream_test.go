package config

import (
	"strings"
	"testing"
)

func TestTransparentUpstreamSettingsDefaults(t *testing.T) {
	cfg := &Config{}

	if got := cfg.UpstreamClientIPMode(); got != UpstreamClientIPModeHeaders {
		t.Fatalf("expected default mode %q, got %q", UpstreamClientIPModeHeaders, got)
	}
	settings := cfg.TransparentUpstreamSettings()
	if settings.FWMark != DefaultTransparentFWMark ||
		settings.RouteTable != DefaultTransparentRouteTable ||
		settings.RulePriority != DefaultTransparentRulePriority ||
		settings.MaxClientPools != DefaultTransparentMaxClientPools ||
		settings.PoolIdleSeconds != DefaultTransparentPoolIdleSeconds {
		t.Fatalf("unexpected transparent defaults: %#v", settings)
	}
}

func TestTransparentUpstreamSettingsOverrides(t *testing.T) {
	cfg := &Config{Server: &ServerConfig{Upstream: &UpstreamConfig{
		ClientIPMode: UpstreamClientIPModeTransparent,
		Transparent: &TransparentUpstreamConfig{
			FWMark:          100,
			RouteTable:      101,
			RulePriority:    102,
			MaxClientPools:  103,
			PoolIdleSeconds: 104,
			AddressPairs: []AddressPair{{
				IPv4: "192.0.2.10",
				IPv6: "2001:db8::10",
			}},
		},
	}}}

	if got := cfg.UpstreamClientIPMode(); got != UpstreamClientIPModeTransparent {
		t.Fatalf("expected transparent mode, got %q", got)
	}
	settings := cfg.TransparentUpstreamSettings()
	if settings.FWMark != 100 || settings.RouteTable != 101 ||
		settings.RulePriority != 102 || settings.MaxClientPools != 103 ||
		settings.PoolIdleSeconds != 104 || len(settings.AddressPairs) != 1 {
		t.Fatalf("unexpected settings: %#v", settings)
	}
}

func TestValidateUpstreamConfig(t *testing.T) {
	tests := []struct {
		name     string
		upstream *UpstreamConfig
		wantErr  string
	}{
		{
			name: "valid explicit pair",
			upstream: &UpstreamConfig{
				ClientIPMode: UpstreamClientIPModeTransparent,
				Transparent: &TransparentUpstreamConfig{
					AddressPairs: []AddressPair{{IPv4: "192.0.2.10", IPv6: "2001:db8::10"}},
				},
			},
		},
		{
			name:     "unknown mode",
			upstream: &UpstreamConfig{ClientIPMode: "automatic"},
			wantErr:  "client_ip_mode",
		},
		{
			name: "reserved route table",
			upstream: &UpstreamConfig{Transparent: &TransparentUpstreamConfig{
				RouteTable: 254,
			}},
			wantErr: "reserved routing table",
		},
		{
			name: "wrong address family",
			upstream: &UpstreamConfig{Transparent: &TransparentUpstreamConfig{
				AddressPairs: []AddressPair{{IPv4: "2001:db8::1", IPv6: "2001:db8::2"}},
			}},
			wantErr: "valid IPv4",
		},
		{
			name: "duplicate address",
			upstream: &UpstreamConfig{Transparent: &TransparentUpstreamConfig{
				AddressPairs: []AddressPair{
					{IPv4: "192.0.2.1", IPv6: "2001:db8::1"},
					{IPv4: "192.0.2.1", IPv6: "2001:db8::2"},
				},
			}},
			wantErr: "duplicate IPv4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUpstreamConfig(&Config{Server: &ServerConfig{Upstream: tt.upstream}})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateUpstreamConfig: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}
