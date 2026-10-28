package config

import (
	"fmt"
	"net/netip"
)

// BindAddresses returns the configured addresses FlowGuard listens on, or nil
// when FlowGuard should auto-detect the machine's public addresses.
func (c *Config) BindAddresses() []string {
	if c == nil || c.Server == nil {
		return nil
	}

	return append([]string(nil), c.Server.BindAddresses...)
}

func validateBindAddresses(cfg *Config) error {
	seen := make(map[netip.Addr]bool)
	for i, raw := range cfg.BindAddresses() {
		addr, err := netip.ParseAddr(raw)
		if err != nil || addr.Zone() != "" || addr.IsUnspecified() {
			return fmt.Errorf("server.bind_addresses[%d] must be a specific IP address", i)
		}
		addr = addr.Unmap()
		if seen[addr] {
			return fmt.Errorf("server.bind_addresses contains duplicate address %s", addr)
		}
		seen[addr] = true
	}

	return nil
}
