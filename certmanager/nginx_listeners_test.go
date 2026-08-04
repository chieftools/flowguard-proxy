package certmanager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeNginxListenerConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write nginx config: %v", err)
	}
	return path
}

func TestDiscoverNginxAddressPairs(t *testing.T) {
	path := writeNginxListenerConfig(t, `
events {}
http {
    server {
        listen 192.0.2.10:443 ssl;
        listen [2001:db8::10]:443 ssl;
    }
    server {
        listen 192.0.2.20:80;
        listen [2001:db8::20]:80;
    }
}`)

	pairs, warnings, err := DiscoverNginxAddressPairs(path)
	if err != nil {
		t.Fatalf("DiscoverNginxAddressPairs: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(pairs) != 2 ||
		pairs[0] != (NginxAddressPair{IPv4: "192.0.2.10", IPv6: "2001:db8::10"}) ||
		pairs[1] != (NginxAddressPair{IPv4: "192.0.2.20", IPv6: "2001:db8::20"}) {
		t.Fatalf("unexpected pairs: %#v", pairs)
	}
}

func TestDiscoverNginxAddressPairsRejectsAmbiguity(t *testing.T) {
	path := writeNginxListenerConfig(t, `
events {}
http {
    server {
        listen 192.0.2.10:443 ssl;
        listen 192.0.2.11:443 ssl;
        listen [2001:db8::10]:443 ssl;
        listen 443 ssl;
        listen [::]:443 ssl;
    }
}`)

	pairs, warnings, err := DiscoverNginxAddressPairs(path)
	if err != nil {
		t.Fatalf("DiscoverNginxAddressPairs: %v", err)
	}
	if len(pairs) != 0 {
		t.Fatalf("expected no guessed pairs, got %#v", pairs)
	}
	if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, " "), "ambiguous") {
		t.Fatalf("expected ambiguity warning, got %v", warnings)
	}
}
