package proxy

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"go.chief.tools/flowguard-proxy/certmanager"
	"go.chief.tools/flowguard-proxy/config"
)

type ResolvedAddressPair struct {
	IPv4       string
	IPv6       string
	Provenance string
}

// Describe formats the pair for setup and inspection output.
func (p ResolvedAddressPair) Describe() string {
	if p.IPv6 == "" {
		return fmt.Sprintf("%s (IPv4-only, %s)", p.IPv4, p.Provenance)
	}
	return fmt.Sprintf("%s <-> %s (%s)", p.IPv4, p.IPv6, p.Provenance)
}

type AddressPairResolution struct {
	Pairs       []ResolvedAddressPair
	Unresolved  []string
	Warnings    []string
	Diagnostics []string

	// counterparts maps each paired address to its counterpart. IPv4-only
	// addresses map to the zero address.
	counterparts map[netip.Addr]netip.Addr
	hasIPv4      bool
	hasIPv6      bool
}

func ResolveAddressPairs(cfg *config.Config, bindAddrs []string) (AddressPairResolution, error) {
	resolution := AddressPairResolution{counterparts: make(map[netip.Addr]netip.Addr)}
	bindSet := make(map[netip.Addr]bool)
	var ipv4 []netip.Addr
	var ipv6 []netip.Addr
	for _, raw := range bindAddrs {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return resolution, fmt.Errorf("invalid bind address %q: %w", raw, err)
		}
		addr = addr.Unmap()
		if bindSet[addr] {
			continue
		}
		bindSet[addr] = true
		if addr.Is4() {
			resolution.hasIPv4 = true
			ipv4 = append(ipv4, addr)
		} else {
			resolution.hasIPv6 = true
			ipv6 = append(ipv6, addr)
		}
	}
	resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf(
		"pairing: considering %d IPv4 bind address(es) [%s] and %d IPv6 bind address(es) [%s]",
		len(ipv4), formatAddresses(ipv4), len(ipv6), formatAddresses(ipv6),
	))

	addPair := func(v4, v6 netip.Addr, provenance string) error {
		if !v4.Is4() || !v6.Is6() || v6.Is4In6() {
			return fmt.Errorf("invalid %s address pair %s/%s", provenance, v4, v6)
		}
		if !bindSet[v4] || !bindSet[v6] {
			return fmt.Errorf("%s address pair %s/%s must reference configured bind addresses", provenance, v4, v6)
		}
		if existing, ok := resolution.counterparts[v4]; ok && existing != v6 {
			return fmt.Errorf("IPv4 bind address %s has conflicting counterparts %s and %s", v4, existing, v6)
		}
		if existing, ok := resolution.counterparts[v6]; ok && existing != v4 {
			return fmt.Errorf("IPv6 bind address %s has conflicting counterparts %s and %s", v6, existing, v4)
		}
		if resolution.counterparts[v4] == v6 {
			return nil
		}
		resolution.counterparts[v4] = v6
		resolution.counterparts[v6] = v4
		resolution.Pairs = append(resolution.Pairs, ResolvedAddressPair{
			IPv4:       v4.String(),
			IPv6:       v6.String(),
			Provenance: provenance,
		})
		return nil
	}

	addIPv4Only := func(v4 netip.Addr) error {
		if !v4.Is4() {
			return fmt.Errorf("invalid explicit IPv4-only address %s", v4)
		}
		if !bindSet[v4] {
			return fmt.Errorf("explicit IPv4-only address %s must reference a configured bind address", v4)
		}
		if _, ok := resolution.counterparts[v4]; ok {
			return fmt.Errorf("IPv4 bind address %s is configured more than once", v4)
		}
		resolution.counterparts[v4] = netip.Addr{}
		resolution.Pairs = append(resolution.Pairs, ResolvedAddressPair{
			IPv4:       v4.String(),
			Provenance: "explicit",
		})
		return nil
	}

	settings := cfg.TransparentUpstreamSettings()
	if len(settings.AddressPairs) == 0 {
		resolution.Diagnostics = append(resolution.Diagnostics, "explicit: no configured address pairs")
	}
	for _, pair := range settings.AddressPairs {
		v4, _ := netip.ParseAddr(pair.IPv4)
		if pair.IPv6 == "" {
			if err := addIPv4Only(v4.Unmap()); err != nil {
				resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf("explicit: rejected IPv4-only %s: %v", pair.IPv4, err))
				return resolution, err
			}
			resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf("explicit: accepted %s as IPv4-only", v4.Unmap()))
			continue
		}
		v6, _ := netip.ParseAddr(pair.IPv6)
		if err := addPair(v4.Unmap(), v6.Unmap(), "explicit"); err != nil {
			resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf("explicit: rejected %s <-> %s: %v", pair.IPv4, pair.IPv6, err))
			return resolution, err
		}
		resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf("explicit: accepted %s <-> %s", v4.Unmap(), v6.Unmap()))
	}

	addDiscoveredPairs := func(source string, discovered []certmanager.AddressPair) {
		for _, pair := range discovered {
			v4, _ := netip.ParseAddr(pair.IPv4)
			v6, _ := netip.ParseAddr(pair.IPv6)
			if !bindSet[v4] || !bindSet[v6] {
				var missing []string
				if !bindSet[v4] {
					missing = append(missing, v4.String())
				}
				if !bindSet[v6] {
					missing = append(missing, v6.String())
				}
				resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf(
					"%s: ignored discovered pair %s <-> %s because %s are not FlowGuard bind addresses",
					source, v4, v6, strings.Join(missing, ", "),
				))
				continue
			}
			if counterpart, v4Assigned := resolution.counterparts[v4]; v4Assigned {
				reason := "already has a counterpart"
				if !counterpart.IsValid() {
					reason = "is configured as IPv4-only"
				}
				resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf(
					"%s: ignored discovered pair %s <-> %s because %s %s",
					source, v4, v6, v4, reason,
				))
				continue
			}
			if _, v6Assigned := resolution.counterparts[v6]; v6Assigned {
				resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf(
					"%s: ignored discovered pair %s <-> %s because %s already has a counterpart",
					source, v4, v6, v6,
				))
				continue
			}
			if err := addPair(v4, v6, source); err != nil {
				resolution.Warnings = append(resolution.Warnings, err.Error())
				resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf("%s: rejected %s <-> %s: %v", source, v4, v6, err))
			} else {
				resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf("%s: applied %s <-> %s", source, v4, v6))
			}
		}
	}

	if cfg != nil && cfg.Host != nil && cfg.Host.NginxConfigPath != "" {
		discovered, warnings, diagnostics, err := certmanager.DiscoverNginxAddressPairsWithDiagnostics(cfg.Host.NginxConfigPath)
		resolution.Diagnostics = append(resolution.Diagnostics, diagnostics...)
		if err != nil {
			resolution.Warnings = append(resolution.Warnings, err.Error())
		} else {
			resolution.Warnings = append(resolution.Warnings, warnings...)
			addDiscoveredPairs("nginx", discovered)
		}
	} else {
		resolution.Diagnostics = append(resolution.Diagnostics, "nginx: skipped because host.nginx_config_path is not configured")
	}

	if cfg != nil && cfg.Host != nil && certmanager.IsDirectAdminRoot(cfg.Host.CertPath) {
		discovered, warnings, diagnostics := certmanager.DiscoverDirectAdminAddressPairs(cfg.Host.CertPath)
		resolution.Diagnostics = append(resolution.Diagnostics, diagnostics...)
		resolution.Warnings = append(resolution.Warnings, warnings...)
		addDiscoveredPairs("directadmin", discovered)
	} else {
		resolution.Diagnostics = append(resolution.Diagnostics, "directadmin: skipped because host.cert_path is not a DirectAdmin installation")
	}

	var remainingV4 []netip.Addr
	var remainingV6 []netip.Addr
	for _, addr := range ipv4 {
		if _, ok := resolution.counterparts[addr]; !ok {
			remainingV4 = append(remainingV4, addr)
		}
	}
	for _, addr := range ipv6 {
		if _, ok := resolution.counterparts[addr]; !ok {
			remainingV6 = append(remainingV6, addr)
		}
	}

	matchedV4 := make(map[netip.Addr]bool)
	matchedV6 := make(map[netip.Addr]bool)
	if len(remainingV4) == 0 || len(remainingV6) == 0 {
		resolution.Diagnostics = append(resolution.Diagnostics, "ipv4-suffix: not applicable without unmatched addresses from both families")
	} else {
		for _, v4 := range remainingV4 {
			var match netip.Addr
			var candidates []string
			matches := 0
			for _, v6 := range remainingV6 {
				if ipv6HasDecimalIPv4Suffix(v6, v4) {
					match = v6
					matches++
					candidates = append(candidates, v6.String())
				}
			}
			if matches == 0 {
				resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf(
					"ipv4-suffix: no IPv6 bind address ends with decimal IPv4 octets for %s",
					v4,
				))
				continue
			}
			if matches > 1 {
				resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf(
					"ipv4-suffix: %s matched multiple IPv6 bind addresses [%s]; left unresolved",
					v4, strings.Join(candidates, ", "),
				))
				continue
			}
			if err := addPair(v4, match, "ipv4-suffix"); err != nil {
				return resolution, err
			}
			resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf("ipv4-suffix: accepted %s <-> %s", v4, match))
			matchedV4[v4] = true
			matchedV6[match] = true
		}
	}
	remainingV4 = filterUnmatchedAddresses(remainingV4, matchedV4)
	remainingV6 = filterUnmatchedAddresses(remainingV6, matchedV6)

	if len(remainingV4) == 1 && len(remainingV6) == 1 {
		if err := addPair(remainingV4[0], remainingV6[0], "single-pair"); err != nil {
			return resolution, err
		}
		resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf(
			"single-pair: accepted the only remaining addresses %s <-> %s",
			remainingV4[0], remainingV6[0],
		))
		remainingV4 = nil
		remainingV6 = nil
	} else {
		resolution.Diagnostics = append(resolution.Diagnostics, fmt.Sprintf(
			"single-pair: not applicable with %d unmatched IPv4 and %d unmatched IPv6 address(es)",
			len(remainingV4), len(remainingV6),
		))
	}

	if len(ipv4) > 0 && len(ipv6) > 0 {
		for _, addr := range append(remainingV4, remainingV6...) {
			resolution.Unresolved = append(resolution.Unresolved, addr.String())
		}
	}
	sort.Strings(resolution.Unresolved)
	if len(resolution.Unresolved) == 0 {
		resolution.Diagnostics = append(resolution.Diagnostics, "pairing: all dual-stack bind addresses were resolved")
	} else {
		resolution.Diagnostics = append(resolution.Diagnostics, "pairing: unresolved bind addresses: "+strings.Join(resolution.Unresolved, ", "))
	}

	sort.Slice(resolution.Pairs, func(i, j int) bool {
		return resolution.Pairs[i].IPv4 < resolution.Pairs[j].IPv4
	})
	sort.Strings(resolution.Warnings)
	return resolution, nil
}

func ipv6HasDecimalIPv4Suffix(ipv6, ipv4 netip.Addr) bool {
	if !ipv4.Is4() || !ipv6.Is6() || ipv6.Is4In6() {
		return false
	}

	// This convention copies each decimal IPv4 octet verbatim into an IPv6
	// hextet, so decimal octet 208 is represented by numeric hextet 0x208.
	v4 := ipv4.As4()
	v6 := ipv6.As16()
	for index, octet := range v4 {
		expected, err := strconv.ParseUint(strconv.Itoa(int(octet)), 16, 16)
		if err != nil || binary.BigEndian.Uint16(v6[8+index*2:10+index*2]) != uint16(expected) {
			return false
		}
	}
	return true
}

func filterUnmatchedAddresses(addresses []netip.Addr, matched map[netip.Addr]bool) []netip.Addr {
	remaining := addresses[:0]
	for _, address := range addresses {
		if !matched[address] {
			remaining = append(remaining, address)
		}
	}
	return remaining
}

func formatAddresses(addresses []netip.Addr) string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address.String())
	}
	sort.Strings(values)
	return strings.Join(values, ", ")
}

func (r AddressPairResolution) counterpart(address string) (string, bool) {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return "", false
	}
	counterpart, ok := r.counterparts[addr.Unmap()]
	if !ok || !counterpart.IsValid() {
		return "", false
	}
	return counterpart.String(), true
}

// ipv4Only reports whether address was explicitly configured without an IPv6
// counterpart.
func (r AddressPairResolution) ipv4Only(address string) bool {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	counterpart, ok := r.counterparts[addr.Unmap()]
	return ok && !counterpart.IsValid()
}

func (r AddressPairResolution) Complete() bool {
	return len(r.Unresolved) == 0
}

func (r AddressPairResolution) singleStackFamily() (available, missing string, ok bool) {
	switch {
	case r.hasIPv4 && !r.hasIPv6:
		return "IPv4", "IPv6", true
	case r.hasIPv6 && !r.hasIPv4:
		return "IPv6", "IPv4", true
	default:
		return "", "", false
	}
}

func transparentHeaderFallbackWarning(pairing AddressPairResolution, bindAddrs []string) string {
	if !pairing.Complete() {
		return ""
	}
	available, missing, ok := pairing.singleStackFamily()
	if !ok {
		return ipv4OnlyHeaderFallbackWarning(pairing)
	}

	addresses := make([]string, 0, len(bindAddrs))
	for _, raw := range bindAddrs {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if (available == "IPv4" && addr.Is4()) || (available == "IPv6" && addr.Is6()) {
			addresses = append(addresses, addr.String())
		}
	}
	sort.Strings(addresses)
	sourceDescription := strings.Join(addresses, ", ")
	if sourceDescription == "" {
		sourceDescription = "the configured bind addresses"
	}

	return fmt.Sprintf(
		"transparent upstream is %s-only; validated %s clients will use canonical header fallback from %s; the backend must trust these FlowGuard source addresses",
		available,
		missing,
		sourceDescription,
	)
}

func ipv4OnlyHeaderFallbackWarning(pairing AddressPairResolution) string {
	var addresses []string
	for _, pair := range pairing.Pairs {
		if pair.IPv6 == "" {
			addresses = append(addresses, pair.IPv4)
		}
	}
	if len(addresses) == 0 {
		return ""
	}

	return fmt.Sprintf(
		"transparent upstream is IPv4-only for %s; validated IPv6 clients on these addresses will use canonical header fallback; the backend must trust these FlowGuard source addresses",
		strings.Join(addresses, ", "),
	)
}
