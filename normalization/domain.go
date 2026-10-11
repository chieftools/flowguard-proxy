package normalization

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Host normalizes a request host for matching. Hostnames are case-insensitive
// (RFC 3986 section 3.2.2), so the result is lowercased. Any port, IPv6
// brackets and a trailing root dot are stripped, so "Example.COM.:443" and
// "example.com" compare equal.
func Host(host string) string {
	// Strip port if present (also handles [IPv6]:port)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Strip IPv6 brackets (e.g. [::1] without port)
	if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}

	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// RegisterableDomain extracts the eTLD+1 (registerable domain) from a host string.
// It normalizes the host with Host, passes through IP addresses unchanged, and
// falls back to the normalized hostname on error (e.g. "localhost").
func RegisterableDomain(host string) string {
	host = Host(host)

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
