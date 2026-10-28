package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"testing"

	"go.chief.tools/flowguard-proxy/config"
	"go.chief.tools/flowguard-proxy/proxy"
)

func TestPromptSetupServerConfigurationDefaultsToTransparentWhenReady(t *testing.T) {
	resetSetupTestGlobals(t)
	setupInspectNetwork = func(*config.Config, []string) (proxy.NetworkInspection, error) {
		return readySetupTransparentInspection(), nil
	}
	var output bytes.Buffer
	setupOutput = &output
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("\n", 5)))
	cfg := &config.Config{}

	patch, err := promptSetupServerConfiguration(reader, cfg, false)
	if err != nil {
		t.Fatalf("promptSetupServerConfiguration: %v", err)
	}
	if patch.Upstream == nil || patch.Upstream.ClientIPMode != config.UpstreamClientIPModeTransparent {
		t.Fatalf("expected transparent mode, got %+v", patch.Upstream)
	}
	if patch.Upstream.Transparent == nil || len(patch.Upstream.Transparent.AddressPairs) != 1 {
		t.Fatalf("expected resolved address pair, got %+v", patch.Upstream.Transparent)
	}
	if patch.Protocols == nil || !patch.Protocols.HTTP1 || !patch.Protocols.HTTP2 || !patch.Protocols.HTTP3 {
		t.Fatalf("expected all protocols enabled, got %+v", patch.Protocols)
	}
	if patch.AdvertiseHTTP3 == nil || *patch.AdvertiseHTTP3 {
		t.Fatalf("expected HTTP/3 advertisement disabled, got %v", patch.AdvertiseHTTP3)
	}
	if !strings.Contains(output.String(), "transparent: available") {
		t.Fatalf("expected availability output, got:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "(*) 2. transparent") {
		t.Fatalf("expected radio-style transparent default, got:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "[x] 1. HTTP/1.1") {
		t.Fatalf("expected checkbox-style protocols, got:\n%s", output.String())
	}
	if !strings.Contains(output.String(), setupHeadersDocumentationURL) || !strings.Contains(output.String(), setupTransparentDocumentationURL) {
		t.Fatalf("expected documentation links for both modes, got:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "  Upstream client IP mode:\n") || !strings.Contains(output.String(), "  ✓ Selected server settings:\n") {
		t.Fatalf("expected indented setup headings, got:\n%s", output.String())
	}
}

func TestPromptSetupServerConfigurationPreservesDiscoverDefaults(t *testing.T) {
	resetSetupTestGlobals(t)
	setupInspectNetwork = func(*config.Config, []string) (proxy.NetworkInspection, error) {
		return readySetupTransparentInspection(), nil
	}
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("\n", 5)))
	http1, http2, http3, advertise := false, true, true, true
	cfg := &config.Config{Server: &config.ServerConfig{
		Protocols:      &config.ProtocolsConfig{HTTP1: &http1, HTTP2: &http2, HTTP3: &http3},
		Upstream:       &config.UpstreamConfig{ClientIPMode: config.UpstreamClientIPModeHeaders},
		AdvertiseHTTP3: &advertise,
	}}

	patch, err := promptSetupServerConfiguration(reader, cfg, true)
	if err != nil {
		t.Fatalf("promptSetupServerConfiguration: %v", err)
	}
	if patch.Upstream.ClientIPMode != config.UpstreamClientIPModeHeaders {
		t.Fatalf("expected configured headers default, got %s", patch.Upstream.ClientIPMode)
	}
	if patch.Protocols.HTTP1 || !patch.Protocols.HTTP2 || !patch.Protocols.HTTP3 {
		t.Fatalf("expected configured protocol defaults, got %+v", patch.Protocols)
	}
	if patch.AdvertiseHTTP3 == nil || !*patch.AdvertiseHTTP3 {
		t.Fatalf("expected configured HTTP/3 advertisement default, got %v", patch.AdvertiseHTTP3)
	}
}

func TestPromptSetupServerConfigurationFallsBackToHeadersAndShowsRequirements(t *testing.T) {
	resetSetupTestGlobals(t)
	setupInspectNetwork = func(*config.Config, []string) (proxy.NetworkInspection, error) {
		return proxy.NetworkInspection{
			HeaderReady:      true,
			TransparentReady: false,
			Prerequisites: []proxy.NetworkPrerequisite{{
				Name: "root privileges", Ready: false, Details: "run setup as root",
			}},
		}, nil
	}
	var output bytes.Buffer
	setupOutput = &output
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("\n", 5)))

	patch, err := promptSetupServerConfiguration(reader, &config.Config{}, false)
	if err != nil {
		t.Fatalf("promptSetupServerConfiguration: %v", err)
	}
	if patch.Upstream.ClientIPMode != config.UpstreamClientIPModeHeaders {
		t.Fatalf("expected headers fallback, got %s", patch.Upstream.ClientIPMode)
	}
	if !strings.Contains(output.String(), "Needed: root privileges — run setup as root") {
		t.Fatalf("expected actionable requirement, got:\n%s", output.String())
	}
}

func TestPromptSetupServerConfigurationShowsVerbosePairingDiagnostics(t *testing.T) {
	resetSetupTestGlobals(t)
	verbose = true
	setupInspectNetwork = func(*config.Config, []string) (proxy.NetworkInspection, error) {
		return proxy.NetworkInspection{
			HeaderReady:      true,
			TransparentReady: true,
			Diagnostics:      []string{"bind addresses: using private test addresses"},
			Pairing: proxy.AddressPairResolution{
				Pairs: []proxy.ResolvedAddressPair{{
					IPv4: "10.20.30.10", IPv6: "fd12:3456:789a::10", Provenance: "nginx",
				}},
				Diagnostics: []string{"nginx: accepted 10.20.30.10 <-> fd12:3456:789a::10"},
			},
			Prerequisites: []proxy.NetworkPrerequisite{{
				Name: "address pairing", Ready: true, Details: "all addresses resolved",
			}},
		}, nil
	}
	var output bytes.Buffer
	setupOutput = &output
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("\n", 4)))

	if _, err := promptSetupServerConfiguration(reader, &config.Config{}, false); err != nil {
		t.Fatalf("promptSetupServerConfiguration: %v", err)
	}
	for _, expected := range []string{
		"Verbose network detection:",
		"bind addresses: using private test addresses",
		"nginx: accepted 10.20.30.10 <-> fd12:3456:789a::10",
		"prerequisite [ok] address pairing: all addresses resolved",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("expected verbose output to contain %q:\n%s", expected, output.String())
		}
	}
}

func TestPromptSetupServerConfigurationKeepsConfiguredTransparentDefaultWhenUnavailable(t *testing.T) {
	resetSetupTestGlobals(t)
	setupInspectNetwork = func(*config.Config, []string) (proxy.NetworkInspection, error) {
		return proxy.NetworkInspection{
			HeaderReady:      true,
			TransparentReady: false,
			Prerequisites: []proxy.NetworkPrerequisite{{
				Name: "root privileges", Ready: false, Details: "run setup as root",
			}},
		}, nil
	}
	var output bytes.Buffer
	setupOutput = &output
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("\n", 5)))
	cfg := &config.Config{Server: &config.ServerConfig{Upstream: &config.UpstreamConfig{
		ClientIPMode: config.UpstreamClientIPModeTransparent,
	}}}

	patch, err := promptSetupServerConfiguration(reader, cfg, true)
	if err != nil {
		t.Fatalf("promptSetupServerConfiguration: %v", err)
	}
	if patch.Upstream.ClientIPMode != config.UpstreamClientIPModeTransparent {
		t.Fatalf("expected configured transparent default, got %s", patch.Upstream.ClientIPMode)
	}
	if !strings.Contains(output.String(), "remains the default because it is already configured") {
		t.Fatalf("expected configured-mode explanation, got:\n%s", output.String())
	}
}

func TestPromptSetupServerConfigurationConfiguresAmbiguousAddressPairs(t *testing.T) {
	resetSetupTestGlobals(t)
	setupInspectNetwork = func(cfg *config.Config, _ []string) (proxy.NetworkInspection, error) {
		pairs := cfg.TransparentUpstreamSettings().AddressPairs
		if len(pairs) == 0 {
			return proxy.NetworkInspection{
				HeaderReady:      true,
				TransparentReady: false,
				Pairing: proxy.AddressPairResolution{
					Unresolved: []string{"192.0.2.10", "2001:db8::10"},
				},
				Prerequisites: []proxy.NetworkPrerequisite{{
					Name: "address pairing", Ready: false, Details: "unresolved bind addresses",
				}},
			}, nil
		}
		return proxy.NetworkInspection{
			HeaderReady:      true,
			TransparentReady: true,
			Pairing: proxy.AddressPairResolution{Pairs: []proxy.ResolvedAddressPair{{
				IPv4: pairs[0].IPv4, IPv6: pairs[0].IPv6, Provenance: "explicit",
			}}},
		}, nil
	}
	var output bytes.Buffer
	setupOutput = &output
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("\n", 7)))
	cfg := &config.Config{}

	patch, err := promptSetupServerConfiguration(reader, cfg, false)
	if err != nil {
		t.Fatalf("promptSetupServerConfiguration: %v", err)
	}
	if patch.Upstream.ClientIPMode != config.UpstreamClientIPModeTransparent {
		t.Fatalf("expected transparent mode after pairing, got %s", patch.Upstream.ClientIPMode)
	}
	pairs := patch.Upstream.Transparent.AddressPairs
	if len(pairs) != 1 || pairs[0].IPv4 != "192.0.2.10" || pairs[0].IPv6 != "2001:db8::10" {
		t.Fatalf("unexpected address pairs: %+v", pairs)
	}
	modePrompt := strings.Index(output.String(), "Choose upstream client IP mode")
	pairPrompt := strings.Index(output.String(), "Configure address pairs now?")
	if modePrompt == -1 || pairPrompt == -1 || modePrompt > pairPrompt {
		t.Fatalf("expected client IP mode before address pairing, got:\n%s", output.String())
	}
}

func TestPromptSetupServerConfigurationUsesCommandLineAddressPairs(t *testing.T) {
	resetSetupTestGlobals(t)
	setupAddressPairs = []config.AddressPair{
		{IPv4: "192.0.2.10", IPv6: "2001:db8::10"},
		{IPv4: "192.0.2.20", IPv6: "2001:db8::20"},
	}
	bindAddrs := []string{"192.0.2.10", "192.0.2.20", "2001:db8::10", "2001:db8::20"}
	setupInspectNetwork = func(cfg *config.Config, _ []string) (proxy.NetworkInspection, error) {
		var pairs []proxy.ResolvedAddressPair
		for _, pair := range cfg.TransparentUpstreamSettings().AddressPairs {
			pairs = append(pairs, proxy.ResolvedAddressPair{IPv4: pair.IPv4, IPv6: pair.IPv6, Provenance: "explicit"})
		}
		return proxy.NetworkInspection{
			BindAddresses:    bindAddrs,
			HeaderReady:      true,
			TransparentReady: len(pairs) == 2,
			Pairing:          proxy.AddressPairResolution{Pairs: pairs},
		}, nil
	}
	var output bytes.Buffer
	setupOutput = &output
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("\n", 5)))
	cfg := &config.Config{Server: &config.ServerConfig{Upstream: &config.UpstreamConfig{
		ClientIPMode: config.UpstreamClientIPModeHeaders,
		Transparent: &config.TransparentUpstreamConfig{AddressPairs: []config.AddressPair{
			{IPv4: "192.0.2.10", IPv6: "2001:db8::20"},
		}},
	}}}

	patch, err := promptSetupServerConfiguration(reader, cfg, true)
	if err != nil {
		t.Fatalf("promptSetupServerConfiguration: %v", err)
	}
	if patch.Upstream.ClientIPMode != config.UpstreamClientIPModeTransparent {
		t.Fatalf("expected command-line pairs to make transparent the default, got %s", patch.Upstream.ClientIPMode)
	}
	pairs := patch.Upstream.Transparent.AddressPairs
	if len(pairs) != 2 ||
		pairs[0].IPv4 != "192.0.2.10" || pairs[0].IPv6 != "2001:db8::10" ||
		pairs[1].IPv4 != "192.0.2.20" || pairs[1].IPv6 != "2001:db8::20" {
		t.Fatalf("expected command-line pairs to replace the configured pair, got %+v", pairs)
	}
	if strings.Contains(output.String(), "Configure address pairs now?") {
		t.Fatalf("expected no pairing prompt for paired addresses, got:\n%s", output.String())
	}
}

func TestPromptSetupServerConfigurationUsesCommandLineIPv4OnlyAddress(t *testing.T) {
	resetSetupTestGlobals(t)
	setupAddressPairs = []config.AddressPair{
		{IPv4: "192.0.2.10", IPv6: "2001:db8::10"},
		{IPv4: "192.0.2.20"},
	}
	bindAddrs := []string{"192.0.2.10", "192.0.2.20", "2001:db8::10"}
	setupInspectNetwork = func(cfg *config.Config, _ []string) (proxy.NetworkInspection, error) {
		pairing, err := proxy.ResolveAddressPairs(cfg, bindAddrs)
		return proxy.NetworkInspection{
			BindAddresses:    bindAddrs,
			HeaderReady:      true,
			TransparentReady: err == nil && pairing.Complete(),
			Pairing:          pairing,
		}, nil
	}
	var output bytes.Buffer
	setupOutput = &output
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("\n", 5)))
	cfg := &config.Config{Server: &config.ServerConfig{Upstream: &config.UpstreamConfig{
		Transparent: &config.TransparentUpstreamConfig{AddressPairs: []config.AddressPair{
			{IPv4: "192.0.2.20", IPv6: "2001:db8::10"},
		}},
	}}}

	patch, err := promptSetupServerConfiguration(reader, cfg, false)
	if err != nil {
		t.Fatalf("promptSetupServerConfiguration: %v", err)
	}
	if patch.Upstream.ClientIPMode != config.UpstreamClientIPModeTransparent {
		t.Fatalf("expected transparent mode, got %s", patch.Upstream.ClientIPMode)
	}
	pairs := patch.Upstream.Transparent.AddressPairs
	if len(pairs) != 2 ||
		pairs[0].IPv4 != "192.0.2.10" || pairs[0].IPv6 != "2001:db8::10" ||
		pairs[1].IPv4 != "192.0.2.20" || pairs[1].IPv6 != "" {
		t.Fatalf("expected the pair and the IPv4-only address, got %+v", pairs)
	}
	if !strings.Contains(output.String(), "Address pair: 192.0.2.20 (IPv4-only, explicit)") {
		t.Fatalf("expected IPv4-only address in output, got:\n%s", output.String())
	}
}

func TestPromptSetupServerConfigurationRejectsCommandLinePairsForUnboundAddresses(t *testing.T) {
	resetSetupTestGlobals(t)
	setupAddressPairs = []config.AddressPair{{IPv4: "192.0.2.10", IPv6: "2001:db8::99"}}
	setupInspectNetwork = func(*config.Config, []string) (proxy.NetworkInspection, error) {
		return proxy.NetworkInspection{
			BindAddresses: []string{"192.0.2.10", "2001:db8::10"},
			HeaderReady:   true,
		}, nil
	}

	_, err := promptSetupServerConfiguration(bufio.NewReader(strings.NewReader("")), &config.Config{}, false)
	if err == nil || !strings.Contains(err.Error(), "2001:db8::99 is not a bind address") {
		t.Fatalf("expected unbound address error, got %v", err)
	}
}

func TestParseSetupAddressPairs(t *testing.T) {
	pairs, err := parseSetupAddressPairs([]string{"45.151.158.60=2a0b:3c40:1:142:0::1", " ::ffff:45.151.158.61 = 2a0e:5540:12:5c1c::1 ", "45.151.158.62= "})
	if err != nil {
		t.Fatalf("parseSetupAddressPairs: %v", err)
	}
	want := []config.AddressPair{
		{IPv4: "45.151.158.60", IPv6: "2a0b:3c40:1:142::1"},
		{IPv4: "45.151.158.61", IPv6: "2a0e:5540:12:5c1c::1"},
		{IPv4: "45.151.158.62"},
	}
	if len(pairs) != len(want) || pairs[0] != want[0] || pairs[1] != want[1] || pairs[2] != want[2] {
		t.Fatalf("pairs = %+v, want %+v", pairs, want)
	}

	for value, wantErr := range map[string]string{
		"45.151.158.60":                    "expected IPV4=IPV6",
		"2a0b:3c40:1:142::1=45.151.158.60": "is not an IPv4 address",
		"45.151.158.60=45.151.158.61":      "is not an IPv6 address",
		"45.151.158.60=::ffff:1.2.3.4":     "is not an IPv6 address",
	} {
		if _, err := parseSetupAddressPairs([]string{value}); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("parseSetupAddressPairs(%q) error = %v, want %q", value, err, wantErr)
		}
	}
	if _, err := parseSetupAddressPairs([]string{
		"45.151.158.60=2a0b:3c40:1:142::1",
		"45.151.158.61=2a0b:3c40:1:142::1",
	}); err == nil || !strings.Contains(err.Error(), "already paired") {
		t.Fatalf("expected duplicate address error, got %v", err)
	}
	if _, err := parseSetupAddressPairs([]string{
		"45.151.158.60=2a0b:3c40:1:142::1",
		"45.151.158.60=",
	}); err == nil || !strings.Contains(err.Error(), "already paired") {
		t.Fatalf("expected duplicate IPv4-only address error, got %v", err)
	}
}

func TestPromptSetupServerConfigurationSkipsAddressPairingForHeaders(t *testing.T) {
	resetSetupTestGlobals(t)
	setupInspectNetwork = func(*config.Config, []string) (proxy.NetworkInspection, error) {
		return proxy.NetworkInspection{
			HeaderReady:      true,
			TransparentReady: false,
			Pairing: proxy.AddressPairResolution{
				Unresolved: []string{"192.0.2.10", "2001:db8::10"},
			},
			Prerequisites: []proxy.NetworkPrerequisite{{
				Name: "address pairing", Ready: false, Details: "unresolved bind addresses",
			}},
		}, nil
	}
	var output bytes.Buffer
	setupOutput = &output
	reader := bufio.NewReader(strings.NewReader("1\n\n\n"))
	cfg := &config.Config{}

	patch, err := promptSetupServerConfiguration(reader, cfg, false)
	if err != nil {
		t.Fatalf("promptSetupServerConfiguration: %v", err)
	}
	if patch.Upstream.ClientIPMode != config.UpstreamClientIPModeHeaders {
		t.Fatalf("expected headers mode, got %s", patch.Upstream.ClientIPMode)
	}
	if len(cfg.TransparentUpstreamSettings().AddressPairs) != 0 {
		t.Fatalf("expected no configured address pairs, got %+v", cfg.TransparentUpstreamSettings().AddressPairs)
	}
	if strings.Contains(output.String(), "Configure address pairs now?") || strings.Contains(output.String(), "IPv6 counterpart") {
		t.Fatalf("expected address pairing to be skipped for headers mode, got:\n%s", output.String())
	}
}

func TestPromptSetupProtocolsTogglesCheckboxes(t *testing.T) {
	resetSetupTestGlobals(t)
	var output bytes.Buffer
	setupOutput = &output
	reader := bufio.NewReader(strings.NewReader("1, 3\n\n"))

	protocols, err := promptSetupProtocols(reader, &config.Config{}, false)
	if err != nil {
		t.Fatalf("promptSetupProtocols: %v", err)
	}
	if protocols.HTTP1 || !protocols.HTTP2 || protocols.HTTP3 {
		t.Fatalf("unexpected toggled protocols: %+v", protocols)
	}
	if strings.Count(output.String(), "Enabled server protocols:") != 2 {
		t.Fatalf("expected checkbox list to be redrawn after toggling, got:\n%s", output.String())
	}
}

func TestPromptSetupProtocolsRequiresOneCheckbox(t *testing.T) {
	resetSetupTestGlobals(t)
	var output bytes.Buffer
	setupOutput = &output
	reader := bufio.NewReader(strings.NewReader("1 2 3\n\n1\n\n"))

	protocols, err := promptSetupProtocols(reader, &config.Config{}, false)
	if err != nil {
		t.Fatalf("promptSetupProtocols: %v", err)
	}
	if !protocols.HTTP1 || protocols.HTTP2 || protocols.HTTP3 {
		t.Fatalf("unexpected protocols after recovery: %+v", protocols)
	}
	if !strings.Contains(output.String(), "At least one option must be selected") {
		t.Fatalf("expected minimum-selection warning, got:\n%s", output.String())
	}
}

func readySetupTransparentInspection() proxy.NetworkInspection {
	return proxy.NetworkInspection{
		HeaderReady:      true,
		TransparentReady: true,
		Pairing: proxy.AddressPairResolution{Pairs: []proxy.ResolvedAddressPair{{
			IPv4: "192.0.2.10", IPv6: "2001:db8::10", Provenance: "single-pair",
		}}},
	}
}

func TestParseSetupBindAddresses(t *testing.T) {
	addrs, err := parseSetupBindAddresses(" 10.0.0.5, ::ffff:10.0.0.6 ,fd00::5")
	if err != nil {
		t.Fatalf("parseSetupBindAddresses: %v", err)
	}
	if want := []string{"10.0.0.5", "10.0.0.6", "fd00::5"}; strings.Join(addrs, ",") != strings.Join(want, ",") {
		t.Fatalf("addrs = %v, want %v", addrs, want)
	}

	for value, wantErr := range map[string]string{
		"10.0.0":            `invalid --bind address "10.0.0"`,
		"10.0.0.5,":         `invalid --bind address ""`,
		"0.0.0.0":           `invalid --bind address "0.0.0.0"`,
		"10.0.0.5,10.0.0.5": "10.0.0.5 is listed more than once",
		"fe80::1%eth0":      `invalid --bind address "fe80::1%eth0"`,
	} {
		if _, err := parseSetupBindAddresses(value); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("parseSetupBindAddresses(%q) error = %v, want %q", value, err, wantErr)
		}
	}
}

func TestPromptSetupServerConfigurationUsesCommandLineBindAddresses(t *testing.T) {
	resetSetupTestGlobals(t)
	setupBindAddrs = []string{"10.0.0.5"}
	setupInterfaceIPAddresses = func() ([]string, error) { return []string{"10.0.0.5", "10.0.0.6"}, nil }
	var inspectedBindAddrs []string
	setupInspectNetwork = func(cfg *config.Config, _ []string) (proxy.NetworkInspection, error) {
		inspectedBindAddrs = cfg.BindAddresses()
		inspection := readySetupTransparentInspection()
		inspection.BindAddresses = inspectedBindAddrs
		return inspection, nil
	}
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("\n", 5)))
	cfg := &config.Config{}

	patch, err := promptSetupServerConfiguration(reader, cfg, false)
	if err != nil {
		t.Fatalf("promptSetupServerConfiguration: %v", err)
	}
	if strings.Join(inspectedBindAddrs, ",") != "10.0.0.5" {
		t.Fatalf("expected inspection of the --bind addresses, got %v", inspectedBindAddrs)
	}
	if strings.Join(patch.BindAddresses, ",") != "10.0.0.5" {
		t.Fatalf("expected --bind addresses in the patch, got %v", patch.BindAddresses)
	}
	if patch.Upstream.ClientIPMode != config.UpstreamClientIPModeTransparent {
		t.Fatalf("expected transparent mode, got %s", patch.Upstream.ClientIPMode)
	}
}

func TestPromptSetupServerConfigurationRejectsBindAddressesNotOnThisMachine(t *testing.T) {
	resetSetupTestGlobals(t)
	setupBindAddrs = []string{"10.0.0.9"}
	setupInterfaceIPAddresses = func() ([]string, error) { return []string{"10.0.0.5"}, nil }

	_, err := promptSetupServerConfiguration(bufio.NewReader(strings.NewReader("")), &config.Config{}, false)
	if err == nil || !strings.Contains(err.Error(), "--bind 10.0.0.9: address is not assigned to this machine (local addresses: 10.0.0.5)") {
		t.Fatalf("expected unassigned address error, got %v", err)
	}
}

func TestPromptSetupServerConfigurationWarnsWithoutPublicAddresses(t *testing.T) {
	resetSetupTestGlobals(t)
	setupInspectNetwork = func(*config.Config, []string) (proxy.NetworkInspection, error) {
		return proxy.NetworkInspection{}, fmt.Errorf("%w; run flowguard setup --bind 10.0.0.5", proxy.ErrNoPublicIPAddresses)
	}
	var output bytes.Buffer
	setupOutput = &output

	if _, err := promptSetupServerConfiguration(bufio.NewReader(strings.NewReader(strings.Repeat("\n", 5))), &config.Config{}, false); err != nil {
		t.Fatalf("promptSetupServerConfiguration: %v", err)
	}

	if !strings.Contains(output.String(), "Warning: no public IP addresses found on this machine; run flowguard setup --bind 10.0.0.5") {
		t.Fatalf("expected --bind hint, got:\n%s", output.String())
	}
}
