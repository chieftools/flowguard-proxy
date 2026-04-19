package config

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"flowguard/api"
)

func TestShouldReloadConfig(t *testing.T) {
	t.Run("reloads when id changes", func(t *testing.T) {
		configPath := writeTestConfig(t, `{"id":"new-id"}`)
		info, err := os.Stat(configPath)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}

		manager := &Manager{
			configPath:      configPath,
			currentConfigID: "old-id",
			lastModified:    info.ModTime().Add(-time.Second),
		}

		shouldReload, reason := manager.shouldReloadConfig()
		if !shouldReload {
			t.Fatal("expected reload when id changes")
		}
		if !strings.Contains(reason, "old-id") || !strings.Contains(reason, "new-id") {
			t.Fatalf("expected reason to mention ids, got %q", reason)
		}
	})

	t.Run("does not reload when id matches", func(t *testing.T) {
		configPath := writeTestConfig(t, `{"id":"same-id"}`)
		info, err := os.Stat(configPath)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}

		manager := &Manager{
			configPath:      configPath,
			currentConfigID: "same-id",
			lastModified:    info.ModTime().Add(-time.Second),
		}

		shouldReload, _ := manager.shouldReloadConfig()
		if shouldReload {
			t.Fatal("expected matching id not to trigger reload")
		}
	})

	t.Run("falls back to mtime when no id", func(t *testing.T) {
		configPath := writeTestConfig(t, `{"rules":{}}`)
		info, err := os.Stat(configPath)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}

		manager := &Manager{
			configPath:   configPath,
			lastModified: info.ModTime().Add(-time.Second),
		}

		shouldReload, reason := manager.shouldReloadConfig()
		if !shouldReload || !strings.Contains(reason, "no ID in config") {
			t.Fatalf("expected mtime fallback reload, got %v %q", shouldReload, reason)
		}
	})

	t.Run("falls back to mtime when json parse fails", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(configPath, []byte("{invalid"), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		info, err := os.Stat(configPath)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}

		manager := &Manager{
			configPath:   configPath,
			lastModified: info.ModTime().Add(-time.Second),
		}

		shouldReload, reason := manager.shouldReloadConfig()
		if !shouldReload || !strings.Contains(reason, "JSON parse failed") {
			t.Fatalf("expected parse-failure fallback reload, got %v %q", shouldReload, reason)
		}
	})
}

func TestRefreshFromAPI(t *testing.T) {
	t.Run("no host key skips refresh", func(t *testing.T) {
		configPath := writeTestConfig(t, `{"id":"cfg-1"}`)
		manager := &Manager{
			configPath: configPath,
			apiClient:  api.NewClient("", "FlowGuard/test"),
			config:     &Config{},
		}

		if err := manager.RefreshFromAPI(false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("read config: %v", err)
		}
		if string(body) != `{"id":"cfg-1"}` {
			t.Fatalf("expected config file to remain unchanged, got %s", string(body))
		}
	})

	t.Run("not modified returns nil and leaves file unchanged", func(t *testing.T) {
		configPath := writeTestConfig(t, `{"id":"cfg-1"}`)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("If-None-Match"); got != "cfg-1" {
				t.Fatalf("expected etag cfg-1, got %s", got)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer host-key" {
				t.Fatalf("expected bearer auth, got %s", got)
			}
			w.WriteHeader(http.StatusNotModified)
		}))
		defer server.Close()

		t.Setenv("API_BASE", server.URL)
		manager := &Manager{
			configPath:      configPath,
			apiClient:       api.NewClient("host-key", "FlowGuard/test"),
			currentConfigID: "cfg-1",
			config: &Config{
				Host: &HostConfig{Key: "host-key"},
			},
		}

		if err := manager.RefreshFromAPI(false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("read config: %v", err)
		}
		if string(body) != `{"id":"cfg-1"}` {
			t.Fatalf("expected unchanged config, got %s", string(body))
		}
	})

	t.Run("same id skips file update", func(t *testing.T) {
		configPath := writeTestConfig(t, `{"id":"cfg-1"}`)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id":"cfg-1","rules":{},"actions":{}}`))
		}))
		defer server.Close()

		t.Setenv("API_BASE", server.URL)
		manager := &Manager{
			configPath:      configPath,
			apiClient:       api.NewClient("host-key", "FlowGuard/test"),
			currentConfigID: "cfg-1",
			config: &Config{
				Host: &HostConfig{Key: "host-key"},
			},
		}

		if err := manager.RefreshFromAPI(false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("read config: %v", err)
		}
		if string(body) != `{"id":"cfg-1"}` {
			t.Fatalf("expected unchanged config, got %s", string(body))
		}
	})

	t.Run("successful refresh writes new config", func(t *testing.T) {
		configPath := writeTestConfig(t, `{"id":"cfg-1"}`)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id":"cfg-2","rules":{},"actions":{}}`))
		}))
		defer server.Close()

		t.Setenv("API_BASE", server.URL)
		manager := &Manager{
			configPath:      configPath,
			apiClient:       api.NewClient("host-key", "FlowGuard/test"),
			currentConfigID: "cfg-1",
			config: &Config{
				Host: &HostConfig{Key: "host-key"},
			},
		}

		if err := manager.RefreshFromAPI(false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("read config: %v", err)
		}
		if string(body) != `{"id":"cfg-2","rules":{},"actions":{}}` {
			t.Fatalf("expected refreshed config body, got %s", string(body))
		}
	})

	t.Run("write failure is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id":"cfg-2","rules":{},"actions":{}}`))
		}))
		defer server.Close()

		t.Setenv("API_BASE", server.URL)
		manager := &Manager{
			configPath:      filepath.Join(t.TempDir(), "missing", "config.json"),
			apiClient:       api.NewClient("host-key", "FlowGuard/test"),
			currentConfigID: "cfg-1",
			config: &Config{
				Host: &HostConfig{Key: "host-key"},
			},
		}

		err := manager.RefreshFromAPI(false)
		if err == nil || !strings.Contains(err.Error(), "failed to write configuration") {
			t.Fatalf("expected write failure, got %v", err)
		}
	})
}

func TestRuntimeCallbacksAndDebounceHelpers(t *testing.T) {
	t.Run("upgrade callback only fires when unattended upgrades enabled", func(t *testing.T) {
		manager := &Manager{}
		var called atomic.Int32
		manager.OnUpgradeRequest(func(version string) {
			if version != "1.2.3" {
				t.Fatalf("unexpected version %s", version)
			}
			called.Add(1)
		})

		manager.handleUpgradeEvent("1.2.3")
		if called.Load() != 0 {
			t.Fatalf("expected disabled upgrades not to invoke callback, got %d", called.Load())
		}

		manager.config = &Config{Updates: &UpdatesConfig{AllowUnattended: true}}
		manager.handleUpgradeEvent("1.2.3")
		if called.Load() != 1 {
			t.Fatalf("expected enabled upgrades to invoke callback once, got %d", called.Load())
		}
	})

	t.Run("ip list updates are deduped and flushed", func(t *testing.T) {
		manager := &Manager{
			ipListPendingUpdates: make(map[string]struct{}),
		}

		var received []string
		manager.OnIPListUpdate(func(listIDs []string) {
			received = append(received, listIDs...)
		})

		manager.handleIPListUpdateEvent("list-a")
		manager.handleIPListUpdateEvent("list-b")
		manager.handleIPListUpdateEvent("list-a")
		if manager.ipListDebounceTimer != nil {
			manager.ipListDebounceTimer.Stop()
		}
		manager.flushIPListUpdates()

		slices.Sort(received)
		expected := []string{"list-a", "list-b"}
		if !slices.Equal(received, expected) {
			t.Fatalf("expected deduped flushed ids %v, got %v", expected, received)
		}
		if manager.ipListDebounceTimer != nil {
			t.Fatal("expected debounce timer to be cleared after flush")
		}
	})
}
