package proxy

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"go.chief.tools/flowguard-proxy/config"
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
		ipv4Table   = "iptables -t mangle -S"
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
			name:    "iptables 1.8.5 false error for missing IPv4 chain",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {
					output: "# Warning: iptables-legacy tables present, use iptables-legacy to see them\niptables: Incompatible with this kernel.",
					err:    exitError,
				},
				ipv4Nft: {output: "Error: No such file or directory", err: exitError},
			},
			wantReady:    true,
			wantDetails:  []string{"available", "verified with nftables"},
			wantCommands: []string{ipv4Inspect, ipv4Nft},
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
			name:    "nft is not installed and the mangle table has no chain",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: compatibilityError, err: exitError},
				ipv4Nft:     {err: errors.New(`exec: "nft": executable file not found in $PATH`)},
				ipv4Table:   {output: "-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n-N KUBE-MARK\n"},
			},
			wantReady:    true,
			wantDetails:  []string{"available", "verified from the mangle table"},
			wantCommands: []string{ipv4Inspect, ipv4Nft, ipv4Table},
		},
		{
			name:    "nft is not installed and the mangle table has the chain",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: compatibilityError, err: exitError},
				ipv4Nft:     {err: errors.New(`exec: "nft": executable file not found in $PATH`)},
				ipv4Table:   {output: "-P OUTPUT ACCEPT\n-N FLOWGUARD_UPSTREAM\n"},
			},
			wantReady:    false,
			wantDetails:  []string{"incompatible", "mangle table confirms that the chain exists"},
			wantCommands: []string{ipv4Inspect, ipv4Nft, ipv4Table},
		},
		{
			name:    "nft is not installed and the mangle table cannot be listed",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: compatibilityError, err: exitError},
				ipv4Nft:     {err: errors.New(`exec: "nft": executable file not found in $PATH`)},
				ipv4Table:   {output: "iptables v1.8.7 (nf_tables): table `mangle' is incompatible, use 'nft' tool.", err: exitError},
			},
			wantReady:    false,
			wantDetails:  []string{"could not verify the chain with nft", "executable file not found", "table `mangle' is incompatible"},
			wantCommands: []string{ipv4Inspect, ipv4Nft, ipv4Table},
		},
		{
			name:    "nft permission failure",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: compatibilityError, err: exitError},
				ipv4Nft:     {output: "Error: Could not process rule: Operation not permitted", err: exitError},
				ipv4Table:   {output: "iptables v1.8.7 (nf_tables): Could not fetch rule set generation id: Permission denied", err: exitError},
			},
			wantReady:    false,
			wantDetails:  []string{"could not verify the chain with nft", "Operation not permitted", "Permission denied"},
			wantCommands: []string{ipv4Inspect, ipv4Nft, ipv4Table},
		},
		{
			name:    "unexpected nft failure",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: compatibilityError, err: exitError},
				ipv4Nft:     {output: "Error: cache initialization failed", err: exitError},
				ipv4Table:   {output: "-P OUTPUT ACCEPT"},
			},
			wantReady:    true,
			wantDetails:  []string{"verified from the mangle table"},
			wantCommands: []string{ipv4Inspect, ipv4Nft, ipv4Table},
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
			name:    "existing compatible chain with legacy tables warning",
			family:  4,
			command: "iptables",
			responses: map[string]inspectionCommandResult{
				ipv4Inspect: {output: strings.Join([]string{
					"# Warning: iptables-legacy tables present, use iptables-legacy to see them",
					"-N FLOWGUARD_UPSTREAM",
					"-A FLOWGUARD_UPSTREAM -m mark --mark 0x4647 -j CONNMARK --save-mark",
				}, "\n")},
				ipv4Output: {output: strings.Join([]string{
					"# Warning: iptables-legacy tables present, use iptables-legacy to see them",
					"-P OUTPUT ACCEPT",
				}, "\n")},
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

func TestInspectNetworkPrefersExplicitThenConfiguredBindAddresses(t *testing.T) {
	cfg := &config.Config{Server: &config.ServerConfig{BindAddresses: []string{"10.0.0.5"}}}

	configured, err := InspectNetwork(cfg, nil)
	if err != nil {
		t.Fatalf("InspectNetwork: %v", err)
	}
	explicit, err := InspectNetwork(cfg, []string{"10.0.0.6"})
	if err != nil {
		t.Fatalf("InspectNetwork: %v", err)
	}

	if len(configured.BindAddresses) != 1 || configured.BindAddresses[0] != "10.0.0.5" {
		t.Fatalf("expected configured bind addresses, got %v", configured.BindAddresses)
	}
	if len(explicit.BindAddresses) != 1 || explicit.BindAddresses[0] != "10.0.0.6" {
		t.Fatalf("expected explicit bind addresses to take precedence, got %v", explicit.BindAddresses)
	}
}

func TestNoPublicIPAddressesErrorSuggestsSetupBind(t *testing.T) {
	err := noPublicIPAddressesError()

	if !errors.Is(err, ErrNoPublicIPAddresses) {
		t.Fatalf("expected ErrNoPublicIPAddresses, got %v", err)
	}
	if !strings.Contains(err.Error(), "run flowguard setup --bind ") {
		t.Fatalf("expected --bind hint, got %v", err)
	}
}
