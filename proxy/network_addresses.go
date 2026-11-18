package proxy

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// InterfaceAddress is an address on one of the machine's up, non-loopback
// network interfaces.
type InterfaceAddress struct {
	Address   string
	Interface string
}

// NonPublicAddress is an address on this machine that FlowGuard does not
// listen on and does not treat as public.
type NonPublicAddress struct {
	InterfaceAddress
	// Kind names the address range, such as "private" or "carrier-grade NAT".
	Kind string
	// Hint explains what the address probably belongs to, when the address
	// or interface name suggests it.
	Hint string
}

var (
	// publicInterfaceAddresses and interfaceAddresses are replaced in tests.
	publicInterfaceAddresses = DetectPublicIPAddresses
	interfaceAddresses       = DetectInterfaceAddresses

	// sharedAddressSpace is the carrier-grade NAT range (RFC 6598), which
	// Tailscale also uses for its IPv4 addresses.
	sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")
	// tailscaleIPv6 is the unique local prefix Tailscale assigns from.
	tailscaleIPv6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	// ipv6SiteLocal is the deprecated IPv6 site-local range (RFC 3879).
	ipv6SiteLocal = netip.MustParsePrefix("fec0::/10")
)

// DetectInterfaceAddresses returns every address on the machine's up,
// non-loopback interfaces with the name of the interface that holds it.
func DetectInterfaceAddresses() ([]InterfaceAddress, error) {
	var addresses []InterfaceAddress
	_, err := interfaceIPAddresses(func(net.IP) bool { return true }, func(ip, iface string) {
		addresses = append(addresses, InterfaceAddress{Address: ip, Interface: iface})
	})
	return addresses, err
}

// inspectUnboundAddresses splits the machine's addresses that are not bind
// addresses into public ones, which bypass FlowGuard when the web server
// listens on a wildcard address, and non-public ones, which the internet
// usually cannot reach. Loopback and link-local addresses are left out.
func inspectUnboundAddresses(bindAddrs []string, anchor *ReservedIPAnchor) ([]string, []NonPublicAddress) {
	addresses, err := interfaceAddresses()
	if err != nil {
		return nil, nil
	}

	bound := make(map[netip.Addr]bool, len(bindAddrs))
	for _, raw := range bindAddrs {
		if addr, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
			bound[addr.Unmap()] = true
		}
	}

	var uncovered []string
	var nonPublic []NonPublicAddress
	for _, address := range addresses {
		addr, err := netip.ParseAddr(address.Address)
		if err != nil {
			continue
		}
		addr = addr.Unmap().WithZone("")
		if bound[addr] || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() || addr.IsMulticast() {
			continue
		}
		address.Address = addr.String()
		if kind := nonPublicAddressKind(addr); kind != "" {
			nonPublic = append(nonPublic, NonPublicAddress{
				InterfaceAddress: address,
				Kind:             kind,
				Hint:             nonPublicAddressHint(addr, address.Interface, anchor),
			})
			continue
		}
		uncovered = append(uncovered, address.Address)
	}
	slices.Sort(uncovered)
	return uncovered, nonPublic
}

// nonPublicAddressKind names the range of an address that the internet
// usually cannot reach, or returns "" for a public address.
func nonPublicAddressKind(addr netip.Addr) string {
	switch {
	case sharedAddressSpace.Contains(addr):
		return "carrier-grade NAT"
	case addr.Is4() && addr.IsPrivate():
		return "private"
	case addr.Is6() && addr.IsPrivate():
		return "unique local"
	case ipv6SiteLocal.Contains(addr):
		return "site-local"
	}
	return ""
}

// nonPublicAddressHint guesses what a non-public address belongs to from the
// address and the name of its interface.
func nonPublicAddressHint(addr netip.Addr, iface string, anchor *ReservedIPAnchor) string {
	name := strings.ToLower(iface)
	hasPrefix := func(prefixes ...string) bool {
		return slices.ContainsFunc(prefixes, func(prefix string) bool { return strings.HasPrefix(name, prefix) })
	}

	switch {
	case anchor != nil && addr.String() == anchor.AnchorIP:
		return fmt.Sprintf("receives the internet traffic for %s reserved IP %s", anchor.Provider, anchor.ReservedIP)
	case hasPrefix("tailscale") || tailscaleIPv6.Contains(addr):
		return "looks like Tailscale; reachable from devices on your tailnet"
	case hasPrefix("docker", "br-"):
		return "looks like a Docker network; reachable from containers on this machine"
	case hasPrefix("wg"):
		return "looks like WireGuard; reachable from its VPN peers"
	case hasPrefix("zt"):
		return "looks like ZeroTier; reachable from members of its network"
	case hasPrefix("virbr", "lxdbr", "incusbr"):
		return "looks like a virtual machine or container bridge; reachable from guests on this machine"
	case sharedAddressSpace.Contains(addr):
		return "also used by Tailscale and some providers' internal networks"
	case addr.Is4() && addr.IsPrivate():
		return "reachable from other machines on the same network, such as a cloud VPC"
	}
	return ""
}
