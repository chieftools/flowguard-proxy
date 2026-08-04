package config

import (
	"fmt"
	"net/netip"
)

const (
	UpstreamClientIPModeHeaders     = "headers"
	UpstreamClientIPModeTransparent = "transparent"

	DefaultTransparentFWMark          = uint32(17991)
	DefaultTransparentRouteTable      = uint32(17991)
	DefaultTransparentRulePriority    = uint32(17991)
	DefaultTransparentMaxClientPools  = 4096
	DefaultTransparentPoolIdleSeconds = 90
)

type TransparentUpstreamSettings struct {
	FWMark          uint32
	RouteTable      uint32
	RulePriority    uint32
	MaxClientPools  int
	PoolIdleSeconds int
	AddressPairs    []AddressPair
}

func (c *Config) UpstreamClientIPMode() string {
	if c == nil || c.Server == nil || c.Server.Upstream == nil || c.Server.Upstream.ClientIPMode == "" {
		return UpstreamClientIPModeHeaders
	}
	return c.Server.Upstream.ClientIPMode
}

func (c *Config) TransparentUpstreamSettings() TransparentUpstreamSettings {
	settings := TransparentUpstreamSettings{
		FWMark:          DefaultTransparentFWMark,
		RouteTable:      DefaultTransparentRouteTable,
		RulePriority:    DefaultTransparentRulePriority,
		MaxClientPools:  DefaultTransparentMaxClientPools,
		PoolIdleSeconds: DefaultTransparentPoolIdleSeconds,
	}
	if c == nil || c.Server == nil || c.Server.Upstream == nil || c.Server.Upstream.Transparent == nil {
		return settings
	}

	transparent := c.Server.Upstream.Transparent
	if transparent.FWMark != 0 {
		settings.FWMark = transparent.FWMark
	}
	if transparent.RouteTable != 0 {
		settings.RouteTable = transparent.RouteTable
	}
	if transparent.RulePriority != 0 {
		settings.RulePriority = transparent.RulePriority
	}
	if transparent.MaxClientPools != 0 {
		settings.MaxClientPools = transparent.MaxClientPools
	}
	if transparent.PoolIdleSeconds != 0 {
		settings.PoolIdleSeconds = transparent.PoolIdleSeconds
	}
	settings.AddressPairs = append([]AddressPair(nil), transparent.AddressPairs...)
	return settings
}

func validateUpstreamConfig(cfg *Config) error {
	if cfg == nil || cfg.Server == nil || cfg.Server.Upstream == nil {
		return nil
	}

	upstream := cfg.Server.Upstream
	mode := cfg.UpstreamClientIPMode()
	if mode != UpstreamClientIPModeHeaders && mode != UpstreamClientIPModeTransparent {
		return fmt.Errorf("server.upstream.client_ip_mode must be %q or %q", UpstreamClientIPModeHeaders, UpstreamClientIPModeTransparent)
	}

	transparent := upstream.Transparent
	if transparent == nil {
		return nil
	}
	if transparent.MaxClientPools < 0 {
		return fmt.Errorf("server.upstream.transparent.max_client_pools must be greater than zero")
	}
	if transparent.PoolIdleSeconds < 0 {
		return fmt.Errorf("server.upstream.transparent.pool_idle_seconds must be greater than zero")
	}
	if transparent.RouteTable >= 253 && transparent.RouteTable <= 255 {
		return fmt.Errorf("server.upstream.transparent.route_table must not use a reserved routing table (253-255)")
	}

	seenV4 := make(map[netip.Addr]bool)
	seenV6 := make(map[netip.Addr]bool)
	for i, pair := range transparent.AddressPairs {
		ipv4, err := netip.ParseAddr(pair.IPv4)
		if err != nil || !ipv4.Is4() {
			return fmt.Errorf("server.upstream.transparent.address_pairs[%d].ipv4 must be a valid IPv4 address", i)
		}
		ipv6, err := netip.ParseAddr(pair.IPv6)
		if err != nil || !ipv6.Is6() || ipv6.Is4In6() {
			return fmt.Errorf("server.upstream.transparent.address_pairs[%d].ipv6 must be a valid IPv6 address", i)
		}
		if seenV4[ipv4] {
			return fmt.Errorf("server.upstream.transparent.address_pairs contains duplicate IPv4 address %s", ipv4)
		}
		if seenV6[ipv6] {
			return fmt.Errorf("server.upstream.transparent.address_pairs contains duplicate IPv6 address %s", ipv6)
		}
		seenV4[ipv4] = true
		seenV6[ipv6] = true
	}

	return nil
}
