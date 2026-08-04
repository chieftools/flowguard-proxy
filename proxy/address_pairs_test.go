package proxy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"flowguard/config"
)

func TestResolveAddressPairsUsesExplicitThenSinglePair(t *testing.T) {
	cfg := &config.Config{Server: &config.ServerConfig{Upstream: &config.UpstreamConfig{
		Transparent: &config.TransparentUpstreamConfig{
			AddressPairs: []config.AddressPair{{
				IPv4: "192.0.2.10",
				IPv6: "2001:db8::10",
			}},
		},
	}}}
	resolution, err := ResolveAddressPairs(cfg, []string{
		"192.0.2.10", "2001:db8::10", "192.0.2.20", "2001:db8::20",
	})
	if err != nil {
		t.Fatalf("ResolveAddressPairs: %v", err)
	}
	want := []ResolvedAddressPair{
		{IPv4: "192.0.2.10", IPv6: "2001:db8::10", Provenance: "explicit"},
		{IPv4: "192.0.2.20", IPv6: "2001:db8::20", Provenance: "single-pair"},
	}
	if !reflect.DeepEqual(resolution.Pairs, want) {
		t.Fatalf("unexpected pairs:\n got: %#v\nwant: %#v", resolution.Pairs, want)
	}
	if !resolution.Complete() {
		t.Fatalf("expected complete pairing, unresolved: %v", resolution.Unresolved)
	}
}

func TestResolveAddressPairsUsesNginxColisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nginx.conf")
	body := `events {}
http {
  server {
    listen 192.0.2.10:443 ssl;
    listen [2001:db8::20]:443 ssl;
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write nginx config: %v", err)
	}
	cfg := &config.Config{Host: &config.HostConfig{NginxConfigPath: path}}

	resolution, err := ResolveAddressPairs(cfg, []string{
		"192.0.2.10", "192.0.2.20", "2001:db8::10", "2001:db8::20",
	})
	if err != nil {
		t.Fatalf("ResolveAddressPairs: %v", err)
	}
	if len(resolution.Pairs) != 2 ||
		resolution.Pairs[0] != (ResolvedAddressPair{
			IPv4: "192.0.2.10", IPv6: "2001:db8::20", Provenance: "nginx",
		}) ||
		resolution.Pairs[1] != (ResolvedAddressPair{
			IPv4: "192.0.2.20", IPv6: "2001:db8::10", Provenance: "single-pair",
		}) {
		t.Fatalf("unexpected NGINX pair resolution: %#v", resolution.Pairs)
	}
	if !resolution.Complete() {
		t.Fatalf("expected the one remaining pair to resolve, got %v", resolution.Unresolved)
	}
}

func TestResolveAddressPairsRejectsExplicitNonBindAddress(t *testing.T) {
	cfg := &config.Config{Server: &config.ServerConfig{Upstream: &config.UpstreamConfig{
		Transparent: &config.TransparentUpstreamConfig{
			AddressPairs: []config.AddressPair{{
				IPv4: "192.0.2.99",
				IPv6: "2001:db8::10",
			}},
		},
	}}}
	if _, err := ResolveAddressPairs(cfg, []string{"192.0.2.10", "2001:db8::10"}); err == nil {
		t.Fatal("expected non-bind address pair to fail")
	}
}
