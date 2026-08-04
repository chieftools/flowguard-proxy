package proxy

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"flowguard/certmanager"
	"flowguard/config"
)

type ResolvedAddressPair struct {
	IPv4       string
	IPv6       string
	Provenance string
}

type AddressPairResolution struct {
	Pairs      []ResolvedAddressPair
	Unresolved []string
	Warnings   []string

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

	settings := cfg.TransparentUpstreamSettings()
	for _, pair := range settings.AddressPairs {
		v4, _ := netip.ParseAddr(pair.IPv4)
		v6, _ := netip.ParseAddr(pair.IPv6)
		if err := addPair(v4.Unmap(), v6.Unmap(), "explicit"); err != nil {
			return resolution, err
		}
	}

	if cfg != nil && cfg.Host != nil && cfg.Host.NginxConfigPath != "" {
		discovered, warnings, err := certmanager.DiscoverNginxAddressPairs(cfg.Host.NginxConfigPath)
		if err != nil {
			resolution.Warnings = append(resolution.Warnings, err.Error())
		} else {
			resolution.Warnings = append(resolution.Warnings, warnings...)
			for _, pair := range discovered {
				v4, _ := netip.ParseAddr(pair.IPv4)
				v6, _ := netip.ParseAddr(pair.IPv6)
				if !bindSet[v4] || !bindSet[v6] {
					continue
				}
				if _, v4Assigned := resolution.counterparts[v4]; v4Assigned {
					continue
				}
				if _, v6Assigned := resolution.counterparts[v6]; v6Assigned {
					continue
				}
				if err := addPair(v4, v6, "nginx"); err != nil {
					resolution.Warnings = append(resolution.Warnings, err.Error())
				}
			}
		}
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
	for _, v4 := range remainingV4 {
		var match netip.Addr
		matches := 0
		for _, v6 := range remainingV6 {
			if ipv6HasDecimalIPv4Suffix(v6, v4) {
				match = v6
				matches++
			}
		}
		if matches != 1 {
			continue
		}
		if err := addPair(v4, match, "ipv4-suffix"); err != nil {
			return resolution, err
		}
		matchedV4[v4] = true
		matchedV6[match] = true
	}
	remainingV4 = filterUnmatchedAddresses(remainingV4, matchedV4)
	remainingV6 = filterUnmatchedAddresses(remainingV6, matchedV6)

	if len(remainingV4) == 1 && len(remainingV6) == 1 {
		if err := addPair(remainingV4[0], remainingV6[0], "single-pair"); err != nil {
			return resolution, err
		}
		remainingV4 = nil
		remainingV6 = nil
	}

	if len(ipv4) > 0 && len(ipv6) > 0 {
		for _, addr := range append(remainingV4, remainingV6...) {
			resolution.Unresolved = append(resolution.Unresolved, addr.String())
		}
	}

	sort.Slice(resolution.Pairs, func(i, j int) bool {
		return resolution.Pairs[i].IPv4 < resolution.Pairs[j].IPv4
	})
	sort.Strings(resolution.Unresolved)
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

func (r AddressPairResolution) counterpart(address string) (string, bool) {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return "", false
	}
	counterpart, ok := r.counterparts[addr.Unmap()]
	if !ok {
		return "", false
	}
	return counterpart.String(), true
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
	available, missing, ok := pairing.singleStackFamily()
	if !ok || !pairing.Complete() {
		return ""
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
