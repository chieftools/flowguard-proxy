package instance

import (
	"errors"
	"testing"
)

func TestResolvePrefersConfiguredIDThenFlyMachineThenHostname(t *testing.T) {
	for _, test := range []struct {
		name     string
		env      map[string]string
		hostname string
		want     string
	}{
		{"configured", map[string]string{"FLOWGUARD_INSTANCE_ID": "edge-1", "FLY_MACHINE_ID": "ams:4d89e3"}, "host", "edge-1"},
		{"fly machine", map[string]string{"FLY_MACHINE_ID": "ams:4d89e3"}, "host", "ams:4d89e3"},
		{"hostname", nil, "web-01.example.com", "web-01.example.com"},
		{"sanitized", map[string]string{"FLOWGUARD_INSTANCE_ID": " edge 1/a "}, "host", "edge-1-a"},
		{"blank configured id", map[string]string{"FLOWGUARD_INSTANCE_ID": "  "}, "host", "host"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := resolve(func(key string) string { return test.env[key] }, func() (string, error) { return test.hostname, nil })

			if got != test.want {
				t.Fatalf("resolve() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResolveFallsBackToARandomID(t *testing.T) {
	got := resolve(func(string) string { return "" }, func() (string, error) { return "", errors.New("no hostname") })

	if len(got) != 16 {
		t.Fatalf("resolve() = %q, want 16 random hex characters", got)
	}
}

func TestSanitizeLimitsTheLength(t *testing.T) {
	long := make([]byte, 300)
	for index := range long {
		long[index] = 'a'
	}

	if got := sanitize(string(long)); len(got) != maxLength {
		t.Fatalf("sanitize() length = %d, want %d", len(got), maxLength)
	}
}
