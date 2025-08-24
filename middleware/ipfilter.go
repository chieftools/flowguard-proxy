package middleware

import (
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
)

// IPFilter implements IP-based filtering using ipset
type IPFilter struct {
	ipsetV4Name     string
	ipsetV6Name     string
	trustedProxyMgr *TrustedProxyManager
}

// NewIPFilter creates a new IP filter middleware
func NewIPFilter(ipsetV4Name, ipsetV6Name string) *IPFilter {
	return &IPFilter{
		ipsetV4Name: ipsetV4Name,
		ipsetV6Name: ipsetV6Name,
	}
}

// SetTrustedProxyManager sets the trusted proxy manager
func (m *IPFilter) SetTrustedProxyManager(mgr *TrustedProxyManager) {
	m.trustedProxyMgr = mgr
}

// Process checks if the client IP is allowed
func (m *IPFilter) Process(w http.ResponseWriter, r *http.Request) (bool, int, string) {
	clientIP := m.getClientIP(r)

	if !m.isAllowed(clientIP) {
		log.Printf("[middleware:ipfilter] blocked ip address (%s) accessing %s", clientIP, r.Host)
		return false, http.StatusForbidden, "Forbidden"
	}

	return true, 0, ""
}

func (m *IPFilter) isAllowed(ip string) bool {
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		host = ip
	}

	// Parse the IP to determine if it's IPv4 or IPv6
	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return false
	}

	var ipsetName string
	if parsedIP.To4() != nil {
		ipsetName = m.ipsetV4Name
	} else {
		ipsetName = m.ipsetV6Name
	}

	cmd := exec.Command("ipset", "test", ipsetName, host)
	err = cmd.Run()
	// If IP is in the blocklist (test succeeds), return false (not allowed)
	// If IP is NOT in the blocklist (test fails), return true (allowed)
	return err != nil
}

func (m *IPFilter) getClientIP(r *http.Request) string {
	// Get the immediate remote address
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	// If we have a trusted proxy manager and the remote IP is from a trusted proxy,
	// then we can trust the X-Forwarded-For or X-Real-IP headers
	if m.trustedProxyMgr != nil && m.trustedProxyMgr.IsTrustedProxy(remoteIP) {
		// Check X-Forwarded-For header
		xff := r.Header.Get("X-Forwarded-For")

		if xff != "" {
			// Get the rightmost non-trusted IP from the chain
			ips := strings.Split(xff, ",")

			// Traverse from right to left to find the first non-trusted IP
			for i := len(ips) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(ips[i])
				if !m.trustedProxyMgr.IsTrustedProxy(ip) {
					return ip
				}
			}

			// If all IPs in the chain are trusted, use the leftmost one
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}

		// Check X-Real-IP header
		xri := r.Header.Get("X-Real-IP")
		if xri != "" {
			return xri
		}
	}

	// If not from a trusted proxy, or no headers present, use the remote address
	return remoteIP
}
