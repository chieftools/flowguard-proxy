package proxy

import (
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

// getPublicIPAddresses returns all public IP addresses configured on the machine
func getPublicIPAddresses() ([]string, error) {
	var publicIPs []string
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
			log.Printf("Warning: failed to get addresses for interface %s: %v", iface.Name, err)
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

			// Check if it's a public IP
			if isPublicIP(ip) {
				ipStr := ip.String()
				// Avoid duplicates
				if !seenIPs[ipStr] {
					seenIPs[ipStr] = true
					publicIPs = append(publicIPs, ipStr)
					log.Printf("Found public IP: %s on interface %s", ipStr, iface.Name)
				}
			}
		}
	}

	if len(publicIPs) == 0 {
		return nil, fmt.Errorf("no public IP addresses found on this machine")
	}

	return publicIPs, nil
}

// maybeFormatV6Addr formats an IPv6 address by enclosing it in square brackets if necessary
func maybeFormatV6Addr(addr string) string {
	if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
		return fmt.Sprintf("[%s]", addr)
	}

	return addr
}
