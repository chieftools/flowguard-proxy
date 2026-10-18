package config

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func newBootstrapTestServer(t *testing.T, body string) *atomic.Int32 {
	t.Helper()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer fgsvr_new" {
			http.Error(w, "unexpected key "+got, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	t.Setenv("API_BASE", server.URL)

	return &requests
}

func TestBootstrapFetchesMissingConfig(t *testing.T) {
	requests := newBootstrapTestServer(t, `{"id":"cfg_1","host":{"key":"fgsvr_new"}}`)
	path := filepath.Join(t.TempDir(), "flowguard", "config.json")

	if err := Bootstrap(path, "fgsvr_new", "FlowGuard/test"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(data) != `{"id":"cfg_1","host":{"key":"fgsvr_new"}}` {
		t.Fatalf("unexpected config: %s", data)
	}
	if requests.Load() != 1 {
		t.Fatalf("expected one API request, got %d", requests.Load())
	}
}

func TestBootstrapKeepsConfigForSameKey(t *testing.T) {
	requests := newBootstrapTestServer(t, `{"id":"cfg_2","host":{"key":"fgsvr_new"}}`)
	path := filepath.Join(t.TempDir(), "config.json")
	existing := `{"id":"cfg_1","host":{"key":"fgsvr_new"}}`
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := Bootstrap(path, "fgsvr_new", "FlowGuard/test"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	data, _ := os.ReadFile(path)
	if string(data) != existing {
		t.Fatalf("existing config was replaced: %s", data)
	}
	if requests.Load() != 0 {
		t.Fatalf("expected no API requests, got %d", requests.Load())
	}
}

func TestBootstrapRefetchesForRotatedKey(t *testing.T) {
	requests := newBootstrapTestServer(t, `{"id":"cfg_2","host":{"key":"fgsvr_new"}}`)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"id":"cfg_1","host":{"key":"fgsvr_old"}}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := Bootstrap(path, "fgsvr_new", "FlowGuard/test"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	data, _ := os.ReadFile(path)
	if string(data) != `{"id":"cfg_2","host":{"key":"fgsvr_new"}}` {
		t.Fatalf("config was not refetched: %s", data)
	}
	if requests.Load() != 1 {
		t.Fatalf("expected one API request, got %d", requests.Load())
	}
}

func TestBootstrapFailsWithoutConfigWhenAPIUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	t.Setenv("API_BASE", server.URL)
	path := filepath.Join(t.TempDir(), "config.json")

	if err := Bootstrap(path, "fgsvr_new", "FlowGuard/test"); err == nil {
		t.Fatal("expected bootstrap to fail")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected no config file, stat err = %v", err)
	}
}

func TestBootstrapRejectsInvalidConfig(t *testing.T) {
	newBootstrapTestServer(t, `not json`)
	path := filepath.Join(t.TempDir(), "config.json")

	if err := Bootstrap(path, "fgsvr_new", "FlowGuard/test"); err == nil {
		t.Fatal("expected invalid configuration to be rejected")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected no config file, stat err = %v", err)
	}
}
