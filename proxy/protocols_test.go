package proxy

import (
	"slices"
	"testing"

	"flowguard/config"
)

func TestTLSNextProtosReflectConfiguredProtocols(t *testing.T) {
	tests := []struct {
		name     string
		settings config.ProtocolSettings
		want     []string
	}{
		{
			name:     "all tcp tls protocols",
			settings: config.ProtocolSettings{HTTP1: true, HTTP2: true},
			want:     []string{"h2", "http/1.1"},
		},
		{
			name:     "http2 disabled",
			settings: config.ProtocolSettings{HTTP1: true, HTTP2: false},
			want:     []string{"http/1.1"},
		},
		{
			name:     "http1 disabled",
			settings: config.ProtocolSettings{HTTP1: false, HTTP2: true},
			want:     []string{"h2"},
		},
		{
			name:     "tcp tls disabled",
			settings: config.ProtocolSettings{},
			want:     []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tlsNextProtos(tt.settings); !slices.Equal(got, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestHTTPServerProtocolsReflectConfiguredProtocols(t *testing.T) {
	settings := config.ProtocolSettings{HTTP1: false, HTTP2: true}

	cleartext := httpServerProtocols(settings, false)
	if cleartext.HTTP1() || cleartext.HTTP2() {
		t.Fatalf("expected cleartext protocols to be disabled, got %s", cleartext)
	}

	tlsProtocols := httpServerProtocols(settings, true)
	if tlsProtocols.HTTP1() || !tlsProtocols.HTTP2() {
		t.Fatalf("expected TLS protocols to allow only HTTP/2, got %s", tlsProtocols)
	}
}
