package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"flowguard/api"
	"flowguard/config"
	"flowguard/proxy"

	"charm.land/huh/v2"
)

func TestResolveSetupInteractionMode(t *testing.T) {
	tests := []struct {
		name                  string
		disabled              bool
		disabledByEnvironment bool
		accessible            bool
		terminalStreams       bool
		term                  string
		want                  setupInteractionMode
	}{
		{name: "terminal UI", terminalStreams: true, term: "xterm-256color", want: setupInteractionTUI},
		{name: "accessible", accessible: true, terminalStreams: true, term: "xterm-256color", want: setupInteractionAccessible},
		{name: "flag overrides accessible", disabled: true, accessible: true, terminalStreams: true, want: setupInteractionPlain},
		{name: "environment override", disabledByEnvironment: true, accessible: true, terminalStreams: true, want: setupInteractionPlain},
		{name: "dumb terminal", terminalStreams: true, term: "dumb", want: setupInteractionPlain},
		{name: "redirected streams", terminalStreams: false, term: "xterm-256color", want: setupInteractionPlain},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := resolveSetupInteractionMode(test.disabled, test.disabledByEnvironment, test.accessible, test.terminalStreams, test.term)
			if got != test.want {
				t.Fatalf("resolveSetupInteractionMode() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestAccessibleSetupServerFormUsesBufferedIO(t *testing.T) {
	resetSetupTestGlobals(t)
	setupLookupEnvironment = func(name string) (string, bool) {
		if name == "ACCESSIBLE" {
			return "1", true
		}
		return "", false
	}
	setupInspectNetwork = func(*config.Config, []string) (proxy.NetworkInspection, error) {
		return readySetupTransparentInspection(), nil
	}
	var output bytes.Buffer
	setupOutput = &output
	reader := bufio.NewReader(strings.NewReader("\n0\n\n"))

	patch, err := promptSetupServerConfiguration(reader, &config.Config{}, false)
	if err != nil {
		t.Fatalf("promptSetupServerConfiguration: %v", err)
	}
	if patch.Upstream.ClientIPMode != config.UpstreamClientIPModeTransparent {
		t.Fatalf("expected transparent mode, got %s", patch.Upstream.ClientIPMode)
	}
	if patch.Protocols == nil || !patch.Protocols.HTTP1 || !patch.Protocols.HTTP2 || !patch.Protocols.HTTP3 {
		t.Fatalf("expected all protocols enabled, got %+v", patch.Protocols)
	}
	if !strings.Contains(output.String(), "Upstream client IP mode") || !strings.Contains(output.String(), "Enabled server protocols") {
		t.Fatalf("expected accessible form output, got:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "Selected server settings:") ||
		!strings.Contains(output.String(), "Upstream client IP mode: transparent") ||
		!strings.Contains(output.String(), "Enabled server protocols: HTTP/1.1, HTTP/2, HTTP/3") {
		t.Fatalf("expected selected values in output history, got:\n%s", output.String())
	}
}

func TestSetupProtocolFieldShowsEveryOption(t *testing.T) {
	protocols := []string{"http1", "http2", "http3"}
	view := newSetupProtocolField(&protocols).View()

	for _, protocol := range []string{"HTTP/1.1", "HTTP/2", "HTTP/3"} {
		if !strings.Contains(view, protocol) {
			t.Fatalf("expected protocol picker to show %s, got:\n%s", protocol, view)
		}
	}
}

func TestPromptSetupAddressPairsUsesIPv4BasesAndRemainingIPv6Addresses(t *testing.T) {
	resetSetupTestGlobals(t)
	inspection := proxy.NetworkInspection{Pairing: proxy.AddressPairResolution{Unresolved: []string{
		"2001:db8::20", "192.0.2.20", "2001:db8::10", "192.0.2.10",
	}}}
	reader := bufio.NewReader(strings.NewReader("\n2\n\n"))
	cfg := &config.Config{}

	updated, err := promptSetupAddressPairs(reader, cfg, inspection)
	if err != nil {
		t.Fatalf("promptSetupAddressPairs: %v", err)
	}
	if !updated {
		t.Fatal("expected address pairs to be configured")
	}
	pairs := cfg.TransparentUpstreamSettings().AddressPairs
	if len(pairs) != 2 {
		t.Fatalf("expected two address pairs, got %+v", pairs)
	}
	if pairs[0].IPv4 != "192.0.2.10" || pairs[0].IPv6 != "2001:db8::20" {
		t.Fatalf("unexpected first IPv4-based pair: %+v", pairs[0])
	}
	if pairs[1].IPv4 != "192.0.2.20" || pairs[1].IPv6 != "2001:db8::10" {
		t.Fatalf("expected the remaining IPv6 address, got %+v", pairs[1])
	}
}

func TestPromptSetupAddressPairsRejectsMismatchedFamiliesWithoutPrompting(t *testing.T) {
	resetSetupTestGlobals(t)
	var output bytes.Buffer
	setupOutput = &output
	cfg := &config.Config{}
	inspection := proxy.NetworkInspection{Pairing: proxy.AddressPairResolution{Unresolved: []string{
		"192.0.2.10", "192.0.2.20", "2001:db8::10",
	}}}

	updated, err := promptSetupAddressPairs(bufio.NewReader(strings.NewReader("")), cfg, inspection)
	if err != nil {
		t.Fatalf("promptSetupAddressPairs: %v", err)
	}
	if updated || len(cfg.TransparentUpstreamSettings().AddressPairs) != 0 {
		t.Fatalf("expected no configured pairs, got %+v", cfg.TransparentUpstreamSettings().AddressPairs)
	}
	if !strings.Contains(output.String(), "cannot form a complete one-to-one mapping") {
		t.Fatalf("expected actionable mismatch output, got:\n%s", output.String())
	}
}

func TestSetupFormCancellationDoesNotPatchOrStore(t *testing.T) {
	resetSetupTestGlobals(t)
	setupLookupEnvironment = func(name string) (string, bool) {
		if name == "ACCESSIBLE" {
			return "1", true
		}
		return "", false
	}
	setupRunForm = func(*huh.Form) error { return huh.ErrUserAborted }
	patchCalled := false
	client := &fakeSetupClient{
		initialConfig: `{"host":{"cert_path":"/already"}}`,
		patchFunc: func(payload api.ConfigPatch) error {
			patchCalled = true
			return nil
		},
	}

	err := setupHostWithClient(client)
	if !errors.Is(err, huh.ErrUserAborted) {
		t.Fatalf("expected setup cancellation, got %v", err)
	}
	if patchCalled {
		t.Fatal("expected cancellation before PATCH")
	}
	if _, statErr := os.Stat(configFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected cancellation before storing configuration, stat error: %v", statErr)
	}
}

func TestRunSetupStepUsesAccessibleSpinner(t *testing.T) {
	resetSetupTestGlobals(t)
	setupLookupEnvironment = func(name string) (string, bool) {
		if name == "ACCESSIBLE" {
			return "1", true
		}
		return "", false
	}
	var output bytes.Buffer
	setupOutput = &output
	run := false

	if err := runSetupStep("Doing work", "Work complete", func() error {
		run = true
		return nil
	}); err != nil {
		t.Fatalf("runSetupStep: %v", err)
	}
	if !run || !strings.Contains(output.String(), "Doing work") || !strings.Contains(output.String(), "✓ Work complete") {
		t.Fatalf("expected accessible progress output, got %q", output.String())
	}
	if output.String() != "Doing work...\n✓ Work complete\n" {
		t.Fatalf("expected compact progress output, got %q", output.String())
	}
}

func TestRunSetupStepDoesNotQueryTerminalBackgroundColor(t *testing.T) {
	resetSetupTestGlobals(t)
	setupStreamsAreTerminal = func() bool { return true }
	setupInput = strings.NewReader("")
	var output bytes.Buffer
	setupOutput = &output
	wantErr := errors.New("API rejected update")

	err := runSetupStep("Updating control plane", "Updated control plane", func() error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected action error, got %v", err)
	}
	if strings.Contains(output.String(), "\x1b]11;") {
		t.Fatalf("unexpected terminal background-color query in output: %q", output.String())
	}
	if strings.Contains(output.String(), "\x1b[2K\n") {
		t.Fatalf("unexpected blank line after clearing spinner: %q", output.String())
	}
	if !strings.Contains(output.String(), "✗ Updating control plane failed") {
		t.Fatalf("expected failure output, got %q", output.String())
	}
}
