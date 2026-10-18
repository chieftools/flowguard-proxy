package config

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"go.chief.tools/flowguard-proxy/instance"
)

func TestUserAgent(t *testing.T) {
	tests := []struct {
		name          string
		configuration *Config
		want          string
	}{
		{"no configuration", nil, "FlowGuard/99.0.0"},
		{"standalone", &Config{}, "FlowGuard/99.0.0"},
		{"no key", &Config{Host: &HostConfig{ID: "server_synthetic-a"}}, "FlowGuard/99.0.0"},
		{"no id", &Config{Host: &HostConfig{Key: "synthetic-key"}}, "FlowGuard/99.0.0"},
		{"prefixed id", &Config{Host: &HostConfig{ID: "server_synthetic-a", Key: "synthetic-key"}}, "FlowGuard/99.0.0 server/synthetic-a instance/" + instance.ID()},
		{"raw id", &Config{Host: &HostConfig{ID: "synthetic-a", Key: "synthetic-key"}}, "FlowGuard/99.0.0 server/synthetic-a instance/" + instance.ID()},
		{"invalid token", &Config{Host: &HostConfig{ID: "bad id", Key: "synthetic-key"}}, "FlowGuard/99.0.0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.configuration.UserAgent("FlowGuard/99.0.0"); got != test.want {
				t.Fatalf("user agent = %q, want %q", got, test.want)
			}
		})
	}
}

func TestLoadUpdatesManagedRequestIdentity(t *testing.T) {
	requests := make(chan http.Header, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}))
	t.Cleanup(server.Close)
	t.Setenv("API_BASE", server.URL)

	path := writeTestConfig(t, `{"host":{"id":"server_synthetic-a","key":"key-a"}}`)
	manager, err := NewManager(path, "FlowGuard/99.0.0", "99.0.0", t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Stop)

	for _, identity := range []string{"a", "b"} {
		if identity == "b" {
			data := []byte(`{"host":{"id":"server_synthetic-b","key":"key-b"}}`)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := manager.Load(); err != nil {
				t.Fatal(err)
			}
		}

		want := "FlowGuard/99.0.0 server/synthetic-" + identity + " instance/" + instance.ID()
		if manager.GetUserAgent() != want {
			t.Fatalf("manager user agent = %q", manager.GetUserAgent())
		}
		if _, err := manager.GetAPIClient().GetConfig(""); err != nil {
			t.Fatal(err)
		}
		if _, _, err := manager.GetCache().FetchWithCacheForced(server.URL + "/api/v1/ip-list"); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			headers := <-requests
			if headers.Get("User-Agent") != want || headers.Get("Authorization") != "Bearer key-"+identity {
				t.Fatalf("incorrect request identity: %v", headers)
			}
		}
	}
}
