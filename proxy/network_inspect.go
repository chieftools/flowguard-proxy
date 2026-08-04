package proxy

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"flowguard/config"
)

type NetworkPrerequisite struct {
	Name    string
	Ready   bool
	Details string
}

type NetworkInspection struct {
	Mode                string
	BindAddresses       []string
	Pairing             AddressPairResolution
	Prerequisites       []NetworkPrerequisite
	Diagnostics         []string
	TransparentWarnings []string
	HeaderReady         bool
	TransparentReady    bool
	Ready               bool
}

func InspectNetwork(cfg *config.Config, bindAddrs []string) (NetworkInspection, error) {
	autoDetected := len(bindAddrs) == 0
	if len(bindAddrs) == 0 {
		var err error
		bindAddrs, err = DetectPublicIPAddresses()
		if err != nil {
			return NetworkInspection{}, err
		}
	}
	mode := cfg.UpstreamClientIPMode()
	inspection := NetworkInspection{
		Mode:             mode,
		BindAddresses:    append([]string(nil), bindAddrs...),
		HeaderReady:      true,
		TransparentReady: true,
	}
	sort.Strings(inspection.BindAddresses)
	if autoDetected {
		inspection.Diagnostics = append(inspection.Diagnostics, fmt.Sprintf(
			"bind addresses: auto-detected %d public address(es): %s",
			len(inspection.BindAddresses), strings.Join(inspection.BindAddresses, ", "),
		))
	} else {
		inspection.Diagnostics = append(inspection.Diagnostics, fmt.Sprintf(
			"bind addresses: using %d configured address(es): %s",
			len(inspection.BindAddresses), strings.Join(inspection.BindAddresses, ", "),
		))
	}
	addPrerequisite := func(prerequisite NetworkPrerequisite) {
		inspection.Prerequisites = append(inspection.Prerequisites, prerequisite)
		inspection.TransparentReady = inspection.TransparentReady && prerequisite.Ready
	}
	finish := func() (NetworkInspection, error) {
		switch inspection.Mode {
		case config.UpstreamClientIPModeHeaders:
			inspection.Ready = inspection.HeaderReady
		case config.UpstreamClientIPModeTransparent:
			inspection.Ready = inspection.TransparentReady
		default:
			inspection.Ready = false
		}
		return inspection, nil
	}

	pairing, err := ResolveAddressPairs(cfg, bindAddrs)
	if err != nil {
		addPrerequisite(NetworkPrerequisite{
			Name: "address pairing", Ready: false, Details: err.Error(),
		})
	} else if !pairing.Complete() {
		addPrerequisite(NetworkPrerequisite{
			Name: "address pairing", Ready: false, Details: "unresolved: " + strings.Join(pairing.Unresolved, ", "),
		})
	} else {
		addPrerequisite(NetworkPrerequisite{
			Name: "address pairing", Ready: true, Details: "single-stack or all dual-stack addresses are deterministic",
		})
	}
	inspection.Pairing = pairing
	if warning := transparentHeaderFallbackWarning(pairing, bindAddrs); warning != "" {
		inspection.TransparentWarnings = append(inspection.TransparentWarnings, warning)
	}
	if runtime.GOOS != "linux" {
		addPrerequisite(NetworkPrerequisite{
			Name: "operating system", Ready: false, Details: "transparent mode requires Linux",
		})
		return finish()
	}
	rootReady := os.Geteuid() == 0
	rootDetails := "effective user is root"
	if !rootReady {
		rootDetails = "run this command and the FlowGuard service as root"
	}
	addPrerequisite(NetworkPrerequisite{
		Name: "root privileges", Ready: rootReady, Details: rootDetails,
	})

	families, familyErr := transparentAddressFamilies(bindAddrs)
	if familyErr != nil {
		return inspection, familyErr
	}
	ipReady := false
	for _, command := range []string{"ip"} {
		path, lookupErr := exec.LookPath(command)
		ready := lookupErr == nil
		ipReady = ready
		details := path
		if lookupErr != nil {
			details = lookupErr.Error()
		}
		addPrerequisite(NetworkPrerequisite{Name: command, Ready: ready, Details: details})
	}
	for _, item := range []struct {
		family  int
		command string
	}{{4, "iptables"}, {6, "ip6tables"}} {
		family, command := item.family, item.command
		if !families[family] {
			continue
		}
		path, lookupErr := exec.LookPath(command)
		ready := lookupErr == nil
		details := path
		if lookupErr != nil {
			details = lookupErr.Error()
		}
		addPrerequisite(NetworkPrerequisite{Name: command, Ready: ready, Details: details})
		if ready {
			if rootReady {
				identity := inspectMangleIdentity(family, command, cfg.TransparentUpstreamSettings())
				addPrerequisite(identity)
			} else {
				addPrerequisite(NetworkPrerequisite{
					Name:  fmt.Sprintf("IPv%d mangle identity", family),
					Ready: false, Details: "requires root privileges to inspect",
				})
			}
		}
	}
	if families[4] {
		data, readErr := os.ReadFile("/proc/sys/net/ipv4/conf/all/src_valid_mark")
		ready := readErr == nil
		details := strings.TrimSpace(string(data))
		if readErr != nil {
			details = readErr.Error()
		} else if details == "0" {
			details = "currently 0; FlowGuard will set it to 1 while running"
		}
		addPrerequisite(NetworkPrerequisite{
			Name: "net.ipv4.conf.all.src_valid_mark", Ready: ready, Details: details,
		})
	}

	settings := cfg.TransparentUpstreamSettings()
	addPrerequisite(NetworkPrerequisite{
		Name:  "routing identity",
		Ready: true,
		Details: fmt.Sprintf("fwmark=%d table=%d priority=%d",
			settings.FWMark, settings.RouteTable, settings.RulePriority),
	})
	if ipReady {
		for _, family := range []int{4, 6} {
			if !families[family] {
				continue
			}
			routing := inspectRoutingIdentity(family, settings)
			addPrerequisite(routing)
		}
	}
	return finish()
}

func FormatNetworkDiagnostics(inspection NetworkInspection) string {
	var output strings.Builder
	output.WriteString("  Verbose network detection:\n")
	for _, diagnostic := range inspection.Diagnostics {
		fmt.Fprintf(&output, "    - %s\n", diagnostic)
	}
	for _, diagnostic := range inspection.Pairing.Diagnostics {
		fmt.Fprintf(&output, "    - %s\n", diagnostic)
	}
	for _, prerequisite := range inspection.Prerequisites {
		status := "ok"
		if !prerequisite.Ready {
			status = "failed"
		}
		fmt.Fprintf(&output, "    - prerequisite [%s] %s: %s\n", status, prerequisite.Name, prerequisite.Details)
	}
	return output.String()
}

func inspectMangleIdentity(family int, command string, settings config.TransparentUpstreamSettings) NetworkPrerequisite {
	name := fmt.Sprintf("IPv%d mangle identity", family)
	output, err := exec.Command(command, "-t", "mangle", "-S", transparentFirewallChain).CombinedOutput()
	if err != nil {
		details := strings.TrimSpace(string(output))
		lower := strings.ToLower(details)
		if strings.Contains(lower, "no chain") ||
			strings.Contains(lower, "does not exist") ||
			strings.Contains(lower, "no such file") {
			return NetworkPrerequisite{Name: name, Ready: true, Details: "dedicated chain name is available"}
		}
		return NetworkPrerequisite{Name: name, Ready: false, Details: details}
	}

	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line != "" && !isManagedTransparentChainLine(line, settings.FWMark) {
			return NetworkPrerequisite{
				Name: name, Ready: false,
				Details: fmt.Sprintf("%s contains an unmanaged rule: %s", transparentFirewallChain, line),
			}
		}
	}
	output, err = exec.Command(command, "-t", "mangle", "-S", "OUTPUT").CombinedOutput()
	if err != nil {
		return NetworkPrerequisite{Name: name, Ready: false, Details: strings.TrimSpace(string(output))}
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if strings.Contains(line, "-j "+transparentFirewallChain) && !isManagedTransparentJumpLine(line) {
			return NetworkPrerequisite{
				Name: name, Ready: false,
				Details: fmt.Sprintf("OUTPUT contains an unmanaged jump to %s: %s", transparentFirewallChain, line),
			}
		}
	}
	return NetworkPrerequisite{Name: name, Ready: true, Details: "existing dedicated chain is FlowGuard-compatible"}
}

func inspectRoutingIdentity(family int, settings config.TransparentUpstreamSettings) NetworkPrerequisite {
	prefix := "-4"
	cidr := "0.0.0.0/0"
	if family == 6 {
		prefix = "-6"
		cidr = "::/0"
	}
	name := fmt.Sprintf("IPv%d routing identity", family)
	priority := strconv.FormatUint(uint64(settings.RulePriority), 10)
	markDecimal := strconv.FormatUint(uint64(settings.FWMark), 10)
	markHex := fmt.Sprintf("0x%x", settings.FWMark)
	table := strconv.FormatUint(uint64(settings.RouteTable), 10)

	ruleOutput, err := exec.Command("ip", prefix, "rule", "show").CombinedOutput()
	if err != nil {
		return NetworkPrerequisite{Name: name, Ready: false, Details: strings.TrimSpace(string(ruleOutput))}
	}
	for _, line := range strings.Split(string(ruleOutput), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, priority+":") {
			continue
		}
		expected := (strings.Contains(line, "fwmark "+markDecimal) || strings.Contains(line, "fwmark "+markHex)) &&
			(strings.Contains(line, "lookup "+table) || strings.Contains(line, "lookup "+routeTableName(settings.RouteTable)))
		if !expected {
			return NetworkPrerequisite{
				Name: name, Ready: false,
				Details: fmt.Sprintf("policy rule priority %s is already in use: %s", priority, line),
			}
		}
	}

	routeOutput, err := exec.Command("ip", prefix, "route", "show", "table", table).CombinedOutput()
	if err != nil {
		if isMissingRoutingTableError(routeOutput) {
			return NetworkPrerequisite{
				Name: name, Ready: true,
				Details: "routing table does not exist yet; table and rule priority are available",
			}
		}
		return NetworkPrerequisite{Name: name, Ready: false, Details: strings.TrimSpace(string(routeOutput))}
	}
	routes := strings.TrimSpace(string(routeOutput))
	if routes == "" {
		return NetworkPrerequisite{Name: name, Ready: true, Details: "routing table and rule priority are available"}
	}
	for _, line := range strings.Split(routes, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "local" &&
			(fields[1] == "default" || fields[1] == cidr) &&
			fields[2] == "dev" && fields[3] == "lo" {
			continue
		}
		return NetworkPrerequisite{
			Name: name, Ready: false,
			Details: fmt.Sprintf("routing table %s is already in use: %s", table, line),
		}
	}
	return NetworkPrerequisite{Name: name, Ready: true, Details: "existing FlowGuard-compatible policy route"}
}

func FormatNetworkInspection(inspection NetworkInspection) string {
	var output strings.Builder
	fmt.Fprintf(&output, "Configured upstream client IP mode: %s\n", inspection.Mode)
	fmt.Fprintf(&output, "Bind addresses: %s\n", strings.Join(inspection.BindAddresses, ", "))
	output.WriteString("\nHeader mode")
	if inspection.Mode == config.UpstreamClientIPModeHeaders {
		output.WriteString(" (configured)")
	}
	output.WriteString(":\n")
	output.WriteString("  Uses canonical X-Forwarded-For, X-Real-IP, X-Forwarded-Host, and X-Forwarded-Proto headers.\n")
	output.WriteString("  The backend must trust only requests that reached it through FlowGuard.\n")
	fmt.Fprintf(&output, "  Ready: %s\n", strconv.FormatBool(inspection.HeaderReady))

	output.WriteString("\nTransparent mode")
	if inspection.Mode == config.UpstreamClientIPModeTransparent {
		output.WriteString(" (configured)")
	}
	output.WriteString(":\n")
	if len(inspection.Pairing.Pairs) == 0 {
		output.WriteString("  Address pairs: none\n")
	} else {
		output.WriteString("  Address pairs:\n")
		for _, pair := range inspection.Pairing.Pairs {
			fmt.Fprintf(&output, "    %s <-> %s (%s)\n", pair.IPv4, pair.IPv6, pair.Provenance)
		}
	}
	if len(inspection.Pairing.Unresolved) > 0 {
		fmt.Fprintf(&output, "  Unresolved addresses: %s\n", strings.Join(inspection.Pairing.Unresolved, ", "))
	}
	for _, warning := range inspection.Pairing.Warnings {
		fmt.Fprintf(&output, "  Warning: %s\n", warning)
	}
	for _, warning := range inspection.TransparentWarnings {
		fmt.Fprintf(&output, "  WARNING: %s\n", warning)
	}
	if len(inspection.Prerequisites) > 0 {
		output.WriteString("  Prerequisites:\n")
		for _, prerequisite := range inspection.Prerequisites {
			status := "ok"
			if !prerequisite.Ready {
				status = "unavailable"
			}
			fmt.Fprintf(&output, "    [%s] %s: %s\n", status, prerequisite.Name, prerequisite.Details)
		}
	}
	fmt.Fprintf(&output, "  Ready: %s\n", strconv.FormatBool(inspection.TransparentReady))
	fmt.Fprintf(&output, "\nConfigured mode ready: %s\n", strconv.FormatBool(inspection.Ready))
	return output.String()
}
