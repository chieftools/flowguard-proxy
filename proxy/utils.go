package proxy

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
)

// isPublicIP checks if an IP address is public (not private, loopback, or link-local)
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check for loopback
	if ip.IsLoopback() {
		return false
	}

	// Check for link-local
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	// Check for private IPv4 ranges
	privateIPv4Ranges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16", // APIPA
	}

	for _, cidr := range privateIPv4Ranges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return false
		}
	}

	// Check for private IPv6 ranges
	if ip.To4() == nil { // IPv6
		// Check for ULA (Unique Local Address) fc00::/7
		if len(ip) >= 1 && (ip[0] == 0xfc || ip[0] == 0xfd) {
			return false
		}
		// Check for site-local (deprecated but still might be used) fec0::/10
		if len(ip) >= 2 && ip[0] == 0xfe && (ip[1]&0xc0) == 0xc0 {
			return false
		}
	}

	return true
}

// getInterfaceForIP finds which network interface an IP address belongs to
func getInterfaceForIP(targetIP string) (string, error) {
	target := net.ParseIP(targetIP)
	if target == nil {
		return "", fmt.Errorf("invalid IP address: %s", targetIP)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			if ip.Equal(target) {
				return iface.Name, nil
			}
		}
	}

	return "", fmt.Errorf("no interface found for IP %s", targetIP)
}

// ErrNoPublicIPAddresses reports that bind address auto-detection found no
// public IP address, which is common on servers behind NAT or a load balancer.
var ErrNoPublicIPAddresses = errors.New("no public IP addresses found on this machine")

// getPublicIPAddresses returns all public IP addresses configured on the machine
func getPublicIPAddresses(verbose bool) ([]string, error) {
	publicIPs, err := interfaceIPAddresses(isPublicIP, func(ip, iface string) {
		if verbose {
			log.Printf("[network] Found public IP: %s on interface %s", ip, iface)
		}
	})
	if err != nil {
		return nil, err
	}

	if len(publicIPs) == 0 {
		return nil, noPublicIPAddressesError()
	}

	return publicIPs, nil
}

// noPublicIPAddressesError wraps ErrNoPublicIPAddresses with a --bind hint
// listing the machine's other addresses.
func noPublicIPAddressesError() error {
	suggested, err := interfaceIPAddresses(func(ip net.IP) bool {
		return !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
	}, nil)
	if err != nil || len(suggested) == 0 {
		return fmt.Errorf("%w; run flowguard setup --bind ADDRESSES with the addresses FlowGuard should listen on", ErrNoPublicIPAddresses)
	}

	return fmt.Errorf("%w; run flowguard setup --bind %s with the addresses FlowGuard should listen on (local addresses: %s)",
		ErrNoPublicIPAddresses, suggested[0], strings.Join(suggested, ", "))
}

// interfaceIPAddresses returns the unique addresses of up, non-loopback
// interfaces that include accepts, in interface order.
func interfaceIPAddresses(include func(net.IP) bool, found func(ip, iface string)) ([]string, error) {
	var ips []string
	seenIPs := make(map[string]bool)

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Skip down interfaces
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Skip loopback interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			log.Printf("[network] Warning: failed to get addresses for interface %s: %v", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			if ip == nil || !include(ip) {
				continue
			}
			ipStr := ip.String()
			// Avoid duplicates
			if !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				ips = append(ips, ipStr)
				if found != nil {
					found(ipStr, iface.Name)
				}
			}
		}
	}

	return ips, nil
}

// DetectInterfaceIPAddresses returns every address on the machine's up,
// non-loopback interfaces, public or not.
func DetectInterfaceIPAddresses() ([]string, error) {
	return interfaceIPAddresses(func(net.IP) bool { return true }, nil)
}

// DetectPublicIPAddresses returns the public addresses FlowGuard would bind by
// default. The returned slice is safe for callers to modify.
func DetectPublicIPAddresses() ([]string, error) {
	addresses, err := getPublicIPAddresses(false)
	return append([]string(nil), addresses...), err
}

// maybeFormatV6Addr formats an IPv6 address by enclosing it in square brackets if necessary
func maybeFormatV6Addr(addr string) string {
	if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
		return fmt.Sprintf("[%s]", addr)
	}

	return addr
}
