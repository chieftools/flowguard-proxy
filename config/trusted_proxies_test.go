package config

import (
	"strings"
	"testing"
	"time"
)

func TestParseIPOrCIDR(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "ipv4 address", input: "192.0.2.10", want: "192.0.2.10/32"},
		{name: "ipv6 address", input: "2001:db8::1", want: "2001:db8::1/128"},
		{name: "cidr", input: "192.0.2.0/24", want: "192.0.2.0/24"},
		{name: "invalid", input: "not-an-ip", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIPOrCIDR(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.String() != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got.String())
			}
		})
	}
}

func TestParseIPRangesSkipsCommentsBlankLinesAndInvalidEntries(t *testing.T) {
	manager := &Manager{}
	ranges, err := manager.parseIPRanges([]byte(`
# comment
192.0.2.0/24

not-an-ip
2001:db8::1
`), "test-source")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ranges) != 2 {
		t.Fatalf("expected 2 parsed ranges, got %d", len(ranges))
	}
	if ranges[0].String() != "192.0.2.0/24" {
		t.Fatalf("expected first range to be 192.0.2.0/24, got %s", ranges[0].String())
	}
	if ranges[1].String() != "2001:db8::1/128" {
		t.Fatalf("expected second range to be 2001:db8::1/128, got %s", ranges[1].String())
	}
}

func TestParseTrustedProxiesDeduplicatesLocalEntries(t *testing.T) {
	manager := &Manager{}
	ranges, err := manager.parseTrustedProxies([]string{
		"192.0.2.10",
		"192.0.2.10/32",
		"2001:db8::1",
		"2001:db8::1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ranges) != 2 {
		t.Fatalf("expected 2 deduplicated ranges, got %d", len(ranges))
	}
	if ranges[0].String() != "192.0.2.10/32" {
		t.Fatalf("expected first range to be 192.0.2.10/32, got %s", ranges[0].String())
	}
	if ranges[1].String() != "2001:db8::1/128" {
		t.Fatalf("expected second range to be 2001:db8::1/128, got %s", ranges[1].String())
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
