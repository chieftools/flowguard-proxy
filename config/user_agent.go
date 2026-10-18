package config

import (
	"strings"

	"go.chief.tools/flowguard-proxy/instance"
)

// UserAgent identifies managed servers, and the instance of the server that
// sends the request, while preserving the caller's product version.
func (c *Config) UserAgent(base string) string {
	if c == nil || c.Host == nil || c.Host.Key == "" {
		return base
	}

	serverID := strings.TrimPrefix(c.Host.ID, "server_")
	if serverID == "" {
		return base
	}

	for _, character := range serverID {
		if !(character >= 'a' && character <= 'z') &&
			!(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') &&
			character != '_' && character != '-' {
			return base
		}
	}

	return base + " server/" + serverID + " instance/" + instance.ID()
}
