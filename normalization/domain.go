package normalization

import (
	"net"

	"golang.org/x/net/publicsuffix"
)

// RegisterableDomain extracts the eTLD+1 (registerable domain) from a host string.
// It strips any port, passes through IP addresses unchanged, and falls back to
// the bare hostname on error (e.g. "localhost").
func RegisterableDomain(host string) string {
	// Strip port if present (also handles [IPv6]:port)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Strip IPv6 brackets (e.g. [::1] without port)
	if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}

	// Pass through IP addresses unchanged
	if net.ParseIP(host) != nil {
		return host
	}

	// Extract eTLD+1
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}

	return domain
}
