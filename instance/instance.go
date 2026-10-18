// Package instance identifies this FlowGuard process among the instances that
// share a host key, such as the machines of a Fly.io app or the replicas of a
// container deployment.
package instance

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"sync"
)

// Header carries the instance ID on requests to the control panel.
const Header = "FlowGuard-Instance"

const maxLength = 128

var (
	resolveOnce sync.Once
	resolvedID  string
)

// ID returns the instance ID. It is taken from FLOWGUARD_INSTANCE_ID, then
// FLY_MACHINE_ID, then the hostname, and is otherwise random for this process.
// Characters outside [A-Za-z0-9._:-] are replaced, so the ID is safe to use in
// headers and User-Agents.
func ID() string {
	resolveOnce.Do(func() {
		resolvedID = resolve(os.Getenv, os.Hostname)
	})

	return resolvedID
}

// Region returns the region the instance runs in, from FLOWGUARD_REGION or
// FLY_REGION, or an empty string when unknown.
func Region() string {
	return sanitize(firstNonEmpty(os.Getenv("FLOWGUARD_REGION"), os.Getenv("FLY_REGION")))
}

// Hostname returns the hostname of the machine, or an empty string when unknown.
func Hostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}

	return hostname
}

func resolve(getenv func(string) string, hostname func() (string, error)) string {
	for _, candidate := range []string{getenv("FLOWGUARD_INSTANCE_ID"), getenv("FLY_MACHINE_ID")} {
		if id := sanitize(candidate); id != "" {
			return id
		}
	}

	if name, err := hostname(); err == nil {
		if id := sanitize(name); id != "" {
			return id
		}
	}

	random := make([]byte, 8)
	_, _ = rand.Read(random)

	return hex.EncodeToString(random)
}

func sanitize(value string) string {
	value = strings.TrimSpace(value)

	var builder strings.Builder
	for _, character := range value {
		if builder.Len() >= maxLength {
			break
		}

		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == ':' || character == '-' {
			builder.WriteRune(character)
		} else {
			builder.WriteRune('-')
		}
	}

	return strings.Trim(builder.String(), "-")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}

	return ""
}
