package config

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flowguard/cache"
)

func TestGetIPDatabaseRefreshInterval(t *testing.T) {
	manager := &Manager{}
	if got := manager.GetIPDatabaseRefreshInterval(); got != 24*time.Hour {
		t.Fatalf("expected default 24h interval, got %v", got)
	}

	manager.config = &Config{
		IPDatabase: &IPDatabaseConfig{RefreshIntervalSeconds: 180},
	}
	if got := manager.GetIPDatabaseRefreshInterval(); got != 180*time.Second {
		t.Fatalf("expected configured interval, got %v", got)
	}
}

func TestGetIPDatabasePathFallbacksAndSuccess(t *testing.T) {
	t.Run("no config and no local file", func(t *testing.T) {
		t.Chdir(t.TempDir())
		manager := &Manager{}

		_, err := manager.GetIPDatabasePath()
		if err == nil || !strings.Contains(err.Error(), "no IP database configured") {
			t.Fatalf("expected no IP database configured error, got %v", err)
		}
	})

	t.Run("local fallback without url", func(t *testing.T) {
		tempDir := t.TempDir()
		t.Chdir(tempDir)
		if err := os.WriteFile("ipinfo_lite.mmdb", []byte("db"), 0o644); err != nil {
			t.Fatalf("write local db: %v", err)
		}

		manager := &Manager{}
		path, err := manager.GetIPDatabasePath()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if path != "ipinfo_lite.mmdb" {
			t.Fatalf("expected local fallback path, got %s", path)
		}
	})

	t.Run("configured url without cache", func(t *testing.T) {
		manager := &Manager{
			config: &Config{
				IPDatabase: &IPDatabaseConfig{URL: "https://example.test/db.mmdb"},
			},
		}

		_, err := manager.GetIPDatabasePath()
		if err == nil || !strings.Contains(err.Error(), "cache not initialized") {
			t.Fatalf("expected cache not initialized error, got %v", err)
		}
	})

	t.Run("fetch failure falls back to local file", func(t *testing.T) {
		tempDir := t.TempDir()
		t.Chdir(tempDir)
		if err := os.WriteFile("ipinfo_lite.mmdb", []byte("db"), 0o644); err != nil {
			t.Fatalf("write local db: %v", err)
		}

		cacheDir := filepath.Join(tempDir, "cache")
		c, err := cache.NewCache(cacheDir, "FlowGuard/test", false)
		if err != nil {
			t.Fatalf("new cache: %v", err)
		}

		manager := &Manager{
			cache: c,
			config: &Config{
				IPDatabase: &IPDatabaseConfig{URL: "http://127.0.0.1:1/db.mmdb"},
			},
		}

		path, err := manager.GetIPDatabasePath()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if path != "ipinfo_lite.mmdb" {
			t.Fatalf("expected local fallback path, got %s", path)
		}
	})

	t.Run("successful fetch returns cached file path", func(t *testing.T) {
		tempDir := t.TempDir()
		t.Chdir(tempDir)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("binary-db"))
		}))
		defer server.Close()

		cacheDir := filepath.Join(tempDir, "cache")
		c, err := cache.NewCache(cacheDir, "FlowGuard/test", false)
		if err != nil {
			t.Fatalf("new cache: %v", err)
		}

		manager := &Manager{
			cache: c,
			config: &Config{
				IPDatabase: &IPDatabaseConfig{
					URL:                    server.URL + "/db.mmdb",
					RefreshIntervalSeconds: 60,
				},
			},
		}

		path, err := manager.GetIPDatabasePath()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected cached file to exist at %s: %v", path, err)
		}
	})
}
