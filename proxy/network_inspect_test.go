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
