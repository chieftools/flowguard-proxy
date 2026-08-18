package cmd

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"flowguard/api"
	"flowguard/config"
	"flowguard/proxy"

	"charm.land/huh/v2"
)

const (
	setupHeadersDocumentationURL     = "https://github.com/chieftools/flowguard-proxy#headers-upstream-client-ip"
	setupTransparentDocumentationURL = "https://github.com/chieftools/flowguard-proxy#transparent-upstream-client-ip"
)

func promptSetupServerConfiguration(reader *bufio.Reader, cfg *config.Config, rediscover bool) (api.ServerConfigPatch, error) {
	inspection := inspectSetupNetwork(cfg)
	printSetupNetworkOptions(inspection)
	defaultMode := config.UpstreamClientIPModeHeaders
	allowConfiguredTransparent := false
	if rediscover {
		defaultMode = cfg.UpstreamClientIPMode()
		allowConfiguredTransparent = defaultMode == config.UpstreamClientIPModeTransparent
		if allowConfiguredTransparent && !inspection.TransparentReady {
			fmt.Fprintln(setupOutput, "  Transparent mode remains the default because it is already configured; resolve the requirements above before running FlowGuard.")
		}
	} else if setupTransparentCanBeSelected(inspection, false) {
		defaultMode = config.UpstreamClientIPModeTransparent
	}

	mode, err := promptSetupMode(
		reader,
		inspection,
		defaultMode,
		allowConfiguredTransparent,
	)
	if err != nil {
		return api.ServerConfigPatch{}, err
	}
	if mode == config.UpstreamClientIPModeTransparent && len(inspection.Pairing.Unresolved) > 0 {
		updated, err := promptSetupAddressPairs(reader, cfg, inspection)
		if err != nil {
			return api.ServerConfigPatch{}, err
		}
		if !updated {
			return api.ServerConfigPatch{}, fmt.Errorf("transparent mode requires complete address pairing")
		}
		inspection = inspectSetupNetwork(cfg)
		if !inspection.TransparentReady && !allowConfiguredTransparent {
			return api.ServerConfigPatch{}, fmt.Errorf("transparent mode remains unavailable after configuring address pairs")
		}
	}

	protocols, advertiseHTTP3, err := promptSetupServerProtocols(reader, cfg, rediscover)
	if err != nil {
		return api.ServerConfigPatch{}, err
	}
	printSetupServerSettingsSummary(mode, protocols, advertiseHTTP3)

	upstream := &api.UpstreamConfigPatch{ClientIPMode: mode}
	if mode == config.UpstreamClientIPModeTransparent {
		upstream.Transparent = &api.TransparentUpstreamConfigPatch{
			AddressPairs: setupAddressPairPatches(inspection.Pairing.Pairs),
		}
	}

	return api.ServerConfigPatch{
		Protocols: &api.ProtocolsConfigPatch{
			HTTP1: protocols.HTTP1,
			HTTP2: protocols.HTTP2,
			HTTP3: protocols.HTTP3,
		},
		AdvertiseHTTP3: &advertiseHTTP3,
		Upstream:       upstream,
	}, nil
}

func inspectSetupNetwork(cfg *config.Config) proxy.NetworkInspection {
	inspection, err := setupInspectNetwork(cfg, nil)
	if err == nil {
		return inspection
	}

	return proxy.NetworkInspection{
		Mode:             cfg.UpstreamClientIPMode(),
		HeaderReady:      true,
		TransparentReady: false,
		Prerequisites: []proxy.NetworkPrerequisite{{
			Name: "network inspection", Ready: false, Details: err.Error(),
		}},
	}
}

func promptSetupAddressPairs(reader *bufio.Reader, cfg *config.Config, inspection proxy.NetworkInspection) (bool, error) {
	ipv4, ipv6 := setupUnresolvedAddressFamilies(inspection.Pairing.Unresolved)

	fmt.Fprintln(setupOutput, "\nTransparent mode needs an IPv4/IPv6 mapping for each dual-stack bind address.")
	fmt.Fprintf(setupOutput, "  Unpaired IPv4 addresses: %s\n", setupListOrNone(ipv4))
	fmt.Fprintf(setupOutput, "  Unpaired IPv6 addresses: %s\n", setupListOrNone(ipv6))
	if len(ipv4) == 0 || len(ipv4) != len(ipv6) {
		fmt.Fprintln(setupOutput, "  These addresses cannot form a complete one-to-one mapping; update the bind addresses or nginx configuration before selecting transparent mode.")
		return false, nil
	}

	configure, err := promptYesNo(reader, setupOutput, "Configure address pairs now?", true)
	if err != nil || !configure {
		return false, err
	}

	availableV6 := append([]string(nil), ipv6...)
	manualPairs := make([]config.AddressPair, 0, len(ipv4))
	for _, v4 := range ipv4 {
		labels := make([]string, len(availableV6))
		for i, v6 := range availableV6 {
			labels[i] = v6
		}
		selected, err := promptChoice(reader, setupOutput, "IPv6 counterpart for "+v4, labels, 0)
		if err != nil {
			return false, err
		}
		manualPairs = append(manualPairs, config.AddressPair{IPv4: v4, IPv6: availableV6[selected]})
		availableV6 = append(availableV6[:selected], availableV6[selected+1:]...)
	}

	pairs := make([]config.AddressPair, 0, len(inspection.Pairing.Pairs)+len(manualPairs))
	for _, pair := range inspection.Pairing.Pairs {
		pairs = append(pairs, config.AddressPair{IPv4: pair.IPv4, IPv6: pair.IPv6})
	}
	pairs = append(pairs, manualPairs...)
	setSetupAddressPairs(cfg, pairs)
	return true, nil
}

func setupUnresolvedAddressFamilies(unresolved []string) ([]string, []string) {
	var ipv4, ipv6 []string
	for _, raw := range unresolved {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if addr.Is4() {
			ipv4 = append(ipv4, addr.String())
		} else if addr.Is6() && !addr.Is4In6() {
			ipv6 = append(ipv6, addr.String())
		}
	}
	sort.Strings(ipv4)
	sort.Strings(ipv6)
	return ipv4, ipv6
}

func setupTransparentCanBeSelected(inspection proxy.NetworkInspection, allowConfiguredTransparent bool) bool {
	if inspection.TransparentReady || allowConfiguredTransparent {
		return true
	}
	if len(inspection.Pairing.Unresolved) == 0 {
		return false
	}
	for _, prerequisite := range inspection.Prerequisites {
		if !prerequisite.Ready && prerequisite.Name != "address pairing" {
			return false
		}
	}

	ipv4, ipv6 := setupUnresolvedAddressFamilies(inspection.Pairing.Unresolved)
	return len(ipv4) > 0 && len(ipv4) == len(ipv6)
}

func setSetupAddressPairs(cfg *config.Config, pairs []config.AddressPair) {
	if cfg.Server == nil {
		cfg.Server = &config.ServerConfig{}
	}
	if cfg.Server.Upstream == nil {
		cfg.Server.Upstream = &config.UpstreamConfig{}
	}
	if cfg.Server.Upstream.Transparent == nil {
		cfg.Server.Upstream.Transparent = &config.TransparentUpstreamConfig{}
	}
	cfg.Server.Upstream.Transparent.AddressPairs = append([]config.AddressPair(nil), pairs...)
}

func printSetupNetworkOptions(inspection proxy.NetworkInspection) {
	if verbose {
		fmt.Fprint(setupOutput, proxy.FormatNetworkDiagnostics(inspection))
	}
	fmt.Fprintln(setupOutput, "  Upstream client IP mode:")
	fmt.Fprintln(setupOutput, "    headers: available")
	fmt.Fprintf(setupOutput, "      Documentation: %s\n", setupHeadersDocumentationURL)
	fmt.Fprintln(setupOutput, "      Requires the backend to trust FlowGuard's canonical forwarding headers.")
	transparentStatus := "available"
	if !inspection.TransparentReady {
		transparentStatus = "unavailable"
		if setupTransparentCanBeSelected(inspection, false) {
			transparentStatus = "available after address pairing"
		}
	}
	fmt.Fprintf(setupOutput, "    transparent: %s\n", transparentStatus)
	fmt.Fprintf(setupOutput, "      Documentation: %s\n", setupTransparentDocumentationURL)
	if len(inspection.Pairing.Pairs) > 0 {
		for _, pair := range inspection.Pairing.Pairs {
			fmt.Fprintf(setupOutput, "      Address pair: %s <-> %s (%s)\n", pair.IPv4, pair.IPv6, pair.Provenance)
		}
	}
	for _, warning := range inspection.Pairing.Warnings {
		fmt.Fprintf(setupOutput, "      Warning: %s\n", warning)
	}
	for _, warning := range inspection.TransparentWarnings {
		fmt.Fprintf(setupOutput, "      Warning: %s\n", warning)
	}
	if !inspection.TransparentReady {
		for _, prerequisite := range inspection.Prerequisites {
			if !prerequisite.Ready {
				fmt.Fprintf(setupOutput, "      Needed: %s — %s\n", prerequisite.Name, prerequisite.Details)
			}
		}
	}
}

func promptSetupMode(reader *bufio.Reader, inspection proxy.NetworkInspection, defaultMode string, allowConfiguredTransparent bool) (string, error) {
	canSelectTransparent := setupTransparentCanBeSelected(inspection, allowConfiguredTransparent)
	if currentSetupInteractionMode() == setupInteractionPlain {
		options := []string{"headers", "transparent"}
		defaultIndex := 0
		if defaultMode == config.UpstreamClientIPModeTransparent {
			defaultIndex = 1
		}

		for {
			selected, err := promptChoice(reader, setupOutput, "Choose upstream client IP mode", options, defaultIndex)
			if err != nil {
				return "", err
			}
			mode := options[selected]
			if mode != config.UpstreamClientIPModeTransparent || canSelectTransparent {
				return mode, nil
			}
			fmt.Fprintln(setupOutput, "  Transparent mode cannot be selected until the requirements above are met.")
			defaultIndex = 0
		}
	}

	mode := defaultMode
	modeField := huh.NewSelect[string]().
		Title("Upstream client IP mode").
		Description("Choose how backends receive the validated client IP.").
		Options(
			huh.NewOption("Headers — canonical forwarding headers", config.UpstreamClientIPModeHeaders),
			huh.NewOption("Transparent — preserve the TCP source address", config.UpstreamClientIPModeTransparent),
		).
		Value(&mode).
		Validate(func(selected string) error {
			if selected == config.UpstreamClientIPModeTransparent && !canSelectTransparent {
				return fmt.Errorf("transparent mode is unavailable; resolve the requirements shown above")
			}
			return nil
		})
	form := newSetupForm(huh.NewGroup(modeField).Title("Server settings · Client IP"))
	if err := runSetupForm(form, reader, setupOutput); err != nil {
		return "", err
	}
	return mode, nil
}

func promptSetupServerProtocols(reader *bufio.Reader, cfg *config.Config, rediscover bool) (config.ProtocolSettings, bool, error) {
	if currentSetupInteractionMode() == setupInteractionPlain {
		protocols, err := promptSetupProtocols(reader, cfg, rediscover)
		if err != nil {
			return config.ProtocolSettings{}, false, err
		}
		advertiseHTTP3 := false
		if protocols.HTTP3 {
			defaultAdvertise := rediscover && cfg.AdvertiseHTTP3()
			advertiseHTTP3, err = promptYesNo(reader, setupOutput, "Advertise HTTP/3 support to clients?", defaultAdvertise)
			if err != nil {
				return config.ProtocolSettings{}, false, err
			}
		}
		return protocols, advertiseHTTP3, nil
	}

	protocolDefaults := config.DefaultProtocolSettings()
	if rediscover {
		protocolDefaults = cfg.ProtocolSettings()
	}
	protocols := setupEnabledProtocolNames(protocolDefaults)

	protocolField := newSetupProtocolField(&protocols)

	form := newSetupForm(huh.NewGroup(protocolField).Title("Server settings · Protocols"))
	if err := runSetupForm(form, reader, setupOutput); err != nil {
		return config.ProtocolSettings{}, false, err
	}

	selectedProtocols := config.ProtocolSettings{
		HTTP1: setupContainsString(protocols, "http1"),
		HTTP2: setupContainsString(protocols, "http2"),
		HTTP3: setupContainsString(protocols, "http3"),
	}
	advertiseHTTP3 := false
	if selectedProtocols.HTTP3 {
		defaultAdvertise := rediscover && cfg.AdvertiseHTTP3()
		var err error
		advertiseHTTP3, err = promptYesNo(reader, setupOutput, "Advertise HTTP/3 support to clients?", defaultAdvertise)
		if err != nil {
			return config.ProtocolSettings{}, false, err
		}
	}

	return selectedProtocols, advertiseHTTP3, nil
}

func newSetupProtocolField(protocols *[]string) *huh.MultiSelect[string] {
	return huh.NewMultiSelect[string]().
		Title("Enabled server protocols").
		Description("Space toggles a protocol; Enter continues.").
		Height(5).
		Options(
			huh.NewOption("HTTP/1.1", "http1"),
			huh.NewOption("HTTP/2", "http2"),
			huh.NewOption("HTTP/3", "http3"),
		).
		Value(protocols).
		Validate(func(selected []string) error {
			if len(selected) == 0 {
				return fmt.Errorf("at least one protocol must be enabled")
			}
			return nil
		})
}

func printSetupServerSettingsSummary(mode string, protocols config.ProtocolSettings, advertiseHTTP3 bool) {
	labels := make([]string, 0, 3)
	if protocols.HTTP1 {
		labels = append(labels, "HTTP/1.1")
	}
	if protocols.HTTP2 {
		labels = append(labels, "HTTP/2")
	}
	if protocols.HTTP3 {
		labels = append(labels, "HTTP/3")
	}

	fmt.Fprintln(setupOutput, "  ✓ Selected server settings:")
	fmt.Fprintf(setupOutput, "    Upstream client IP mode: %s\n", mode)
	fmt.Fprintf(setupOutput, "    Enabled server protocols: %s\n", strings.Join(labels, ", "))
	if protocols.HTTP3 {
		fmt.Fprintf(setupOutput, "    Advertise HTTP/3: %t\n", advertiseHTTP3)
	}
}

func setupEnabledProtocolNames(protocols config.ProtocolSettings) []string {
	result := make([]string, 0, 3)
	if protocols.HTTP1 {
		result = append(result, "http1")
	}
	if protocols.HTTP2 {
		result = append(result, "http2")
	}
	if protocols.HTTP3 {
		result = append(result, "http3")
	}
	return result
}

func setupContainsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func promptSetupProtocols(reader *bufio.Reader, cfg *config.Config, rediscover bool) (config.ProtocolSettings, error) {
	defaults := config.DefaultProtocolSettings()
	if rediscover {
		defaults = cfg.ProtocolSettings()
	}

	selected, err := promptCheckboxes(
		reader,
		setupOutput,
		"Enabled server protocols",
		[]string{"HTTP/1.1", "HTTP/2", "HTTP/3"},
		[]bool{defaults.HTTP1, defaults.HTTP2, defaults.HTTP3},
		true,
	)
	if err != nil {
		return config.ProtocolSettings{}, err
	}

	return config.ProtocolSettings{HTTP1: selected[0], HTTP2: selected[1], HTTP3: selected[2]}, nil
}

func promptChoicePlain(reader *bufio.Reader, output io.Writer, question string, options []string, defaultIndex int) (int, error) {
	if len(options) == 0 || defaultIndex < 0 || defaultIndex >= len(options) {
		return 0, fmt.Errorf("invalid choice options")
	}

	for {
		fmt.Fprintln(output)
		for index, option := range options {
			marker := "( )"
			if index == defaultIndex {
				marker = "(*)"
			}
			fmt.Fprintf(output, "  %s %d. %s\n", marker, index+1, option)
		}
		fmt.Fprintf(output, "\n  %s [%d]: ", question, defaultIndex+1)
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			return 0, fmt.Errorf("failed to read response: %w", err)
		}
		answer := strings.TrimSpace(line)
		fmt.Fprintln(output)
		if answer == "" {
			return defaultIndex, nil
		}
		selected, parseErr := strconv.Atoi(answer)
		if parseErr == nil && selected >= 1 && selected <= len(options) {
			return selected - 1, nil
		}
		fmt.Fprintf(output, "  Please choose a number from 1 to %d.\n", len(options))
	}
}

func promptCheckboxesPlain(reader *bufio.Reader, output io.Writer, title string, labels []string, defaults []bool, requireOne bool) ([]bool, error) {
	if len(labels) == 0 || len(labels) != len(defaults) {
		return nil, fmt.Errorf("invalid checkbox options")
	}

	selected := append([]bool(nil), defaults...)
	for {
		fmt.Fprintf(output, "\n%s:\n", title)
		for index, label := range labels {
			marker := "[ ]"
			if selected[index] {
				marker = "[x]"
			}
			fmt.Fprintf(output, "  %s %d. %s\n", marker, index+1, label)
		}
		fmt.Fprintln(output, "\n  Enter numbers to toggle (for example: 1 3).")
		fmt.Fprint(output, "  Press Enter to continue: ")

		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}
		answer := strings.TrimSpace(line)
		fmt.Fprintln(output)
		if answer == "" {
			if !requireOne || anySetupCheckboxSelected(selected) {
				return selected, nil
			}
			fmt.Fprintln(output, "  At least one option must be selected.")
			continue
		}

		tokens := strings.FieldsFunc(answer, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		})
		indices := make(map[int]bool, len(tokens))
		valid := len(tokens) > 0
		for _, token := range tokens {
			value, parseErr := strconv.Atoi(token)
			if parseErr != nil || value < 1 || value > len(labels) {
				valid = false
				break
			}
			indices[value-1] = true
		}
		if !valid {
			fmt.Fprintf(output, "  Please enter numbers from 1 to %d, separated by spaces or commas.\n", len(labels))
			continue
		}
		for index := range indices {
			selected[index] = !selected[index]
		}
	}
}

func anySetupCheckboxSelected(selected []bool) bool {
	for _, value := range selected {
		if value {
			return true
		}
	}
	return false
}

func setupAddressPairPatches(pairs []proxy.ResolvedAddressPair) []api.AddressPairConfigPatch {
	result := make([]api.AddressPairConfigPatch, 0, len(pairs))
	for _, pair := range pairs {
		result = append(result, api.AddressPairConfigPatch{IPv4: pair.IPv4, IPv6: pair.IPv6})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].IPv4 == result[j].IPv4 {
			return result[i].IPv6 < result[j].IPv6
		}
		return result[i].IPv4 < result[j].IPv4
	})
	return result
}

func setupListOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

func validateSetupPatchResponse(cfg *config.Config, payload api.ConfigPatch) error {
	if payload.Host != nil {
		certPath, acmePath, nginxConfigPath := configuredSetupPaths(cfg)
		if payload.Host.CertPath != "" && certPath != payload.Host.CertPath {
			return fmt.Errorf("updated configuration did not include certificate path %s", payload.Host.CertPath)
		}
		if payload.Host.NginxConfigPath != "" && nginxConfigPath != payload.Host.NginxConfigPath {
			return fmt.Errorf("updated configuration did not include nginx path %s", payload.Host.NginxConfigPath)
		}
		if payload.Host.ACMEPath != "" && acmePath != payload.Host.ACMEPath {
			return fmt.Errorf("updated configuration did not include Traefik ACME path %s", payload.Host.ACMEPath)
		}
	}
	if payload.Fail2Ban != nil && cfg.Fail2BanEnabled() != payload.Fail2Ban.Enabled {
		return fmt.Errorf("updated configuration did not include fail2ban.enabled=%t", payload.Fail2Ban.Enabled)
	}
	if payload.Server == nil {
		return nil
	}
	if payload.Server.Upstream != nil && cfg.UpstreamClientIPMode() != payload.Server.Upstream.ClientIPMode {
		return fmt.Errorf("updated configuration did not include upstream client IP mode %s", payload.Server.Upstream.ClientIPMode)
	}
	if payload.Server.Protocols != nil {
		protocols := cfg.ProtocolSettings()
		expected := payload.Server.Protocols
		if protocols.HTTP1 != expected.HTTP1 || protocols.HTTP2 != expected.HTTP2 || protocols.HTTP3 != expected.HTTP3 {
			return fmt.Errorf("updated configuration did not include the selected server protocols")
		}
	}
	if payload.Server.AdvertiseHTTP3 != nil && cfg.AdvertiseHTTP3() != *payload.Server.AdvertiseHTTP3 {
		return fmt.Errorf("updated configuration did not include advertise_http3=%t", *payload.Server.AdvertiseHTTP3)
	}
	if payload.Server.Upstream != nil && payload.Server.Upstream.Transparent != nil {
		actual := cfg.TransparentUpstreamSettings().AddressPairs
		if !equalSetupAddressPairs(actual, payload.Server.Upstream.Transparent.AddressPairs) {
			return fmt.Errorf("updated configuration did not include the selected transparent address pairs")
		}
	}
	return nil
}

func equalSetupAddressPairs(actual []config.AddressPair, expected []api.AddressPairConfigPatch) bool {
	if len(actual) != len(expected) {
		return false
	}
	actualValues := make([]string, 0, len(actual))
	for _, pair := range actual {
		actualValues = append(actualValues, pair.IPv4+"\x00"+pair.IPv6)
	}
	expectedValues := make([]string, 0, len(expected))
	for _, pair := range expected {
		expectedValues = append(expectedValues, pair.IPv4+"\x00"+pair.IPv6)
	}
	sort.Strings(actualValues)
	sort.Strings(expectedValues)
	return strings.Join(actualValues, "\n") == strings.Join(expectedValues, "\n")
}
