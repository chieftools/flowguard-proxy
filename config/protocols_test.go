package config

import "testing"

func boolPtr(v bool) *bool {
	return &v
}

func TestProtocolSettingsDefaultsToAllEnabled(t *testing.T) {
	settings := (*Config)(nil).ProtocolSettings()

	if !settings.HTTP1 || !settings.HTTP2 || !settings.HTTP3 {
		t.Fatalf("expected all protocols enabled by default, got %+v", settings)
	}
}

func TestProtocolSettingsAppliesOverrides(t *testing.T) {
	cfg := &Config{
		Server: &ServerConfig{
			Protocols: &ProtocolsConfig{
				HTTP1: boolPtr(false),
				HTTP3: boolPtr(false),
			},
		},
	}

	settings := cfg.ProtocolSettings()

	if settings.HTTP1 {
		t.Fatal("expected HTTP/1 to be disabled")
	}
	if !settings.HTTP2 {
		t.Fatal("expected HTTP/2 to keep its default enabled state")
	}
	if settings.HTTP3 {
		t.Fatal("expected HTTP/3 to be disabled")
	}
}

func TestAdvertiseHTTP3DefaultsToDisabled(t *testing.T) {
	if (*Config)(nil).AdvertiseHTTP3() {
		t.Fatal("expected HTTP/3 advertisement to be disabled by default")
	}
}

func TestAdvertiseHTTP3AppliesOverride(t *testing.T) {
	cfg := &Config{
		Server: &ServerConfig{
			AdvertiseHTTP3: boolPtr(true),
		},
	}

	if !cfg.AdvertiseHTTP3() {
		t.Fatal("expected HTTP/3 advertisement to be enabled")
	}
}
