package proxy

import (
	"strings"
	"testing"

	"flowguard/config"
)

func TestInspectNetworkReportsTransparentReadinessInHeaderMode(t *testing.T) {
	cfg := &config.Config{}
	inspection, err := InspectNetwork(cfg, []string{"192.0.2.10", "2001:db8::10"})
	if err != nil {
		t.Fatalf("InspectNetwork: %v", err)
	}
	if inspection.Mode != config.UpstreamClientIPModeHeaders {
		t.Fatalf("expected configured header mode, got %q", inspection.Mode)
	}
	if !inspection.HeaderReady || !inspection.Ready {
		t.Fatalf("expected configured header mode to be ready: %#v", inspection)
	}
	if len(inspection.Prerequisites) == 0 {
		t.Fatal("expected transparent prerequisites to be inspected in header mode")
	}
	if len(inspection.Pairing.Pairs) != 1 {
		t.Fatalf("expected transparent address pairing to be reported, got %#v", inspection.Pairing)
	}
}

func TestInspectNetworkConfiguredReadinessFollowsTransparentMode(t *testing.T) {
	cfg := &config.Config{Server: &config.ServerConfig{Upstream: &config.UpstreamConfig{
		ClientIPMode: config.UpstreamClientIPModeTransparent,
	}}}
	inspection, err := InspectNetwork(cfg, []string{"192.0.2.10"})
	if err != nil {
		t.Fatalf("InspectNetwork: %v", err)
	}
	if inspection.Ready != inspection.TransparentReady {
		t.Fatalf("configured readiness must follow transparent readiness: %#v", inspection)
	}
	if len(inspection.TransparentWarnings) != 1 ||
		!strings.Contains(inspection.TransparentWarnings[0], "IPv4-only") ||
		!strings.Contains(inspection.TransparentWarnings[0], "validated IPv6 clients") ||
		!strings.Contains(inspection.TransparentWarnings[0], "192.0.2.10") {
		t.Fatalf("expected actionable single-stack warning: %#v", inspection.TransparentWarnings)
	}
}

func TestInspectNetworkCompleteDualStackHasNoFallbackWarning(t *testing.T) {
	cfg := &config.Config{Server: &config.ServerConfig{Upstream: &config.UpstreamConfig{
		ClientIPMode: config.UpstreamClientIPModeTransparent,
	}}}
	inspection, err := InspectNetwork(cfg, []string{"192.0.2.10", "2001:db8::10"})
	if err != nil {
		t.Fatalf("InspectNetwork: %v", err)
	}
	if len(inspection.TransparentWarnings) != 0 {
		t.Fatalf("unexpected dual-stack fallback warning: %v", inspection.TransparentWarnings)
	}
}

func TestInspectNetworkAmbiguousDualStackRemainsUnreadyWithoutFallback(t *testing.T) {
	cfg := &config.Config{Server: &config.ServerConfig{Upstream: &config.UpstreamConfig{
		ClientIPMode: config.UpstreamClientIPModeTransparent,
	}}}
	inspection, err := InspectNetwork(cfg, []string{
		"192.0.2.10", "192.0.2.20", "2001:db8::10", "2001:db8::20",
	})
	if err != nil {
		t.Fatalf("InspectNetwork: %v", err)
	}
	if inspection.Pairing.Complete() || inspection.TransparentReady || inspection.Ready {
		t.Fatalf("ambiguous dual-stack inspection unexpectedly ready: %#v", inspection)
	}
	if len(inspection.TransparentWarnings) != 0 {
		t.Fatalf("ambiguous dual-stack inspection advertised fallback: %v", inspection.TransparentWarnings)
	}
}

func TestFormatNetworkInspectionShowsBothModes(t *testing.T) {
	report := FormatNetworkInspection(NetworkInspection{
		Mode:             config.UpstreamClientIPModeHeaders,
		BindAddresses:    []string{"192.0.2.10"},
		HeaderReady:      true,
		TransparentReady: false,
		Ready:            true,
		Prerequisites: []NetworkPrerequisite{{
			Name: "operating system", Ready: false, Details: "transparent mode requires Linux",
		}},
	})

	for _, expected := range []string{
		"Configured upstream client IP mode: headers",
		"Header mode (configured):",
		"Transparent mode:",
		"Ready: false",
		"Configured mode ready: true",
	} {
		if !strings.Contains(report, expected) {
			t.Fatalf("expected report to contain %q:\n%s", expected, report)
		}
	}
}

func TestFormatNetworkInspectionHighlightsHeaderFallback(t *testing.T) {
	report := FormatNetworkInspection(NetworkInspection{
		Mode:                config.UpstreamClientIPModeTransparent,
		BindAddresses:       []string{"192.0.2.10"},
		HeaderReady:         true,
		TransparentReady:    true,
		Ready:               true,
		TransparentWarnings: []string{"transparent upstream is IPv4-only; validated IPv6 clients will use canonical header fallback from 192.0.2.10; the backend must trust these FlowGuard source addresses"},
	})

	for _, expected := range []string{
		"Transparent mode (configured):",
		"WARNING: transparent upstream is IPv4-only",
		"canonical header fallback from 192.0.2.10",
		"Configured mode ready: true",
	} {
		if !strings.Contains(report, expected) {
			t.Fatalf("expected report to contain %q:\n%s", expected, report)
		}
	}
}
