package proxy

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"flowguard/config"
)

type inspectionCommandResult struct {
	output string
	err    error
}

type inspectionCommandRunner struct {
	responses map[string]inspectionCommandResult
	commands  []string
}

func (r *inspectionCommandRunner) Run(string, ...string) error {
	return errors.New("unexpected Run call")
}

func (r *inspectionCommandRunner) Output(name string, args ...string) ([]byte, error) {
	command := strings.Join(append([]string{name}, args...), " ")
	r.commands = append(r.commands, command)
	response, ok := r.responses[command]
	if !ok {
		return nil, fmt.Errorf("unexpected command: %s", command)
	}
	return []byte(response.output), response.err
}

func TestInspectMangleIdentityHandlesNftablesMissingChainBug(t *testing.T) {
	const (
		ipv4Inspect = "iptables -t mangle -S FLOWGUARD_UPSTREAM"
		ipv6Inspect = "ip6tables -t mangle -S FLOWGUARD_UPSTREAM"
		ipv4Nft     = "nft list chain ip mangle FLOWGUARD_UPSTREAM"
		ipv6Nft     = "nft list chain ip6 mangle FLOWGUARD_UPSTREAM"
		ipv4Output  = "iptables -t mangle -S OUTPUT"
	)
	compatibilityError := "iptables v1.8.7 (nf_tables): chain `FLOWGUARD_UPSTREAM' in table `mangle' is incompatible, use 'nft' tool."
	ipv6CompatibilityError := "ip6tables v1.8.7 (nf_tables): chain `FLOWGUARD_UPSTREAM' in table `mangle' is incompatible, use 'nft' tool."
	exitError := errors.New("exit status 1")
	settings := config.TransparentUpstreamSettings{FWMark: 17991}

	tests := []struct {
		name         string
		family       int
		command      string
		responses    map[string]inspectionCommandResult
		wantReady    bool
		wantDetails  []string
		wantCommands []string
	}{
		{
			name:    "ordinary missing IPv4 chain",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: "iptables: No chain/target/match by that name.", err: exitError},
			},
			wantReady:    true,
			wantDetails:  []string{"dedicated chain name is available"},
			wantCommands: []string{ipv4Inspect},
		},
		{
			name:    "iptables 1.8.7 false error for missing IPv4 chain",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: compatibilityError, err: exitError},
				ipv4Nft:     {output: "Error: No such file or directory", err: exitError},
			},
			wantReady:    true,
			wantDetails:  []string{"available", "verified with nftables"},
			wantCommands: []string{ipv4Inspect, ipv4Nft},
		},
		{
			name:    "iptables 1.8.7 false error for missing IPv6 chain",
			family:  6,
			command: "ip6tables",
			responses: map[string]inspectionCommandResult{
				ipv6Inspect: {output: ipv6CompatibilityError, err: exitError},
				ipv6Nft:     {output: "Error: No such file or directory", err: exitError},
			},
			wantReady:    true,
			wantDetails:  []string{"available", "verified with nftables"},
			wantCommands: []string{ipv6Inspect, ipv6Nft},
		},
		{
			name:    "native chain exists",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: compatibilityError, err: exitError},
				ipv4Nft:     {output: "table ip mangle { chain FLOWGUARD_UPSTREAM { } }"},
			},
			wantReady:    false,
			wantDetails:  []string{"incompatible", "native nftables confirms that the chain exists"},
			wantCommands: []string{ipv4Inspect, ipv4Nft},
		},
		{
			name:    "nft is not installed",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: compatibilityError, err: exitError},
				ipv4Nft:     {err: errors.New(`exec: "nft": executable file not found in $PATH`)},
			},
			wantReady:    false,
			wantDetails:  []string{"could not verify the chain with nft", "executable file not found"},
			wantCommands: []string{ipv4Inspect, ipv4Nft},
		},
		{
			name:    "nft permission failure",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: compatibilityError, err: exitError},
				ipv4Nft:     {output: "Error: Could not process rule: Operation not permitted", err: exitError},
			},
			wantReady:    false,
			wantDetails:  []string{"could not verify the chain with nft", "Operation not permitted"},
			wantCommands: []string{ipv4Inspect, ipv4Nft},
		},
		{
			name:    "unexpected nft failure",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: compatibilityError, err: exitError},
				ipv4Nft:     {output: "Error: cache initialization failed", err: exitError},
			},
			wantReady:    false,
			wantDetails:  []string{"could not verify the chain with nft", "cache initialization failed"},
			wantCommands: []string{ipv4Inspect, ipv4Nft},
		},
		{
			name:    "existing compatible chain",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: strings.Join([]string{
					"-N FLOWGUARD_UPSTREAM",
					"-A FLOWGUARD_UPSTREAM -m mark --mark 0x4647 -j CONNMARK --save-mark",
					"-A FLOWGUARD_UPSTREAM -m connmark --mark 0x4647 -j CONNMARK --restore-mark",
				}, "\n")},
				ipv4Output: {output: "-P OUTPUT ACCEPT"},
			},
			wantReady:    true,
			wantDetails:  []string{"FlowGuard-compatible"},
			wantCommands: []string{ipv4Inspect, ipv4Output},
		},
		{
			name:    "existing unmanaged chain",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: "-A FLOWGUARD_UPSTREAM -j ACCEPT"},
			},
			wantReady:    false,
			wantDetails:  []string{"contains an unmanaged rule"},
			wantCommands: []string{ipv4Inspect},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &inspectionCommandRunner{responses: tt.responses}
			got := inspectMangleIdentityWithRunner(tt.family, tt.command, settings, runner)
			if got.Ready != tt.wantReady {
				t.Fatalf("Ready = %t, want %t: %#v", got.Ready, tt.wantReady, got)
			}
			for _, detail := range tt.wantDetails {
				if !strings.Contains(got.Details, detail) {
					t.Fatalf("details %q do not contain %q", got.Details, detail)
				}
			}
			if !reflect.DeepEqual(runner.commands, tt.wantCommands) {
				t.Fatalf("commands = %#v, want %#v", runner.commands, tt.wantCommands)
			}
		})
	}
}

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
