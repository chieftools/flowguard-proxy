package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"go.chief.tools/flowguard-proxy/api"
	"go.chief.tools/flowguard-proxy/config"
	"go.chief.tools/flowguard-proxy/logger"
)

func newTestEngine(t *testing.T, cfg config.Config, options Options) *Engine {
	t.Helper()

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	configMgr, err := config.NewManager(configPath, "FlowGuard/test", "test", "", false)
	if err != nil {
		t.Fatalf("new config manager: %v", err)
	}

	e := New(configMgr, options)
	t.Cleanup(e.Stop)
	return e
}

func TestHeartbeatPayloadAddsHostDetails(t *testing.T) {
	e := newTestEngine(t, config.Config{}, Options{
		Version: "1.2.3",
		Heartbeat: func() HeartbeatDetails {
			return HeartbeatDetails{
				Capabilities:  []string{"caddy"},
				Firewall:      api.FirewallHeartbeat{Status: "unmanaged"},
				HostnameCount: 2,
				BindAddresses: []string{"192.0.2.1"},
			}
		},
	})

	payload := e.heartbeatPayload()
	if want := []string{logger.FlowGuardIngestCapability, "caddy"}; !slices.Equal(payload.Capabilities, want) {
		t.Fatalf("capabilities = %v, want %v", payload.Capabilities, want)
	}
	if payload.Version != "1.2.3" || payload.Firewall.Status != "unmanaged" || payload.HostnameCount != 2 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if !slices.Equal(payload.BindAddresses, []string{"192.0.2.1"}) {
		t.Fatalf("bind addresses = %v", payload.BindAddresses)
	}
	if payload.StartedAt != e.StartedAt().Unix() {
		t.Fatalf("started at = %d, want %d", payload.StartedAt, e.StartedAt().Unix())
	}
}

func TestHeartbeatPayloadWithoutHostDetails(t *testing.T) {
	e := newTestEngine(t, config.Config{}, Options{})

	payload := e.heartbeatPayload()
	if want := []string{logger.FlowGuardIngestCapability}; !slices.Equal(payload.Capabilities, want) {
		t.Fatalf("capabilities = %v, want %v", payload.Capabilities, want)
	}
}

func TestIPListConfigChangeAddsAndRemovesManager(t *testing.T) {
	e := newTestEngine(t, config.Config{}, Options{})
	if e.ipListManager != nil {
		t.Fatal("expected no IP list manager without configured lists")
	}

	listPath := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(listPath, []byte("192.0.2.0/24\n"), 0o644); err != nil {
		t.Fatalf("write list: %v", err)
	}
	lists := config.IPListsConfig{"blocklist": {Path: listPath}}

	e.handleIPListConfigChange(&config.Config{IPLists: &lists})
	if e.ipListManager == nil {
		t.Fatal("expected IP list manager after lists were added")
	}

	e.handleIPListConfigChange(&config.Config{})
	if e.ipListManager != nil {
		t.Fatal("expected IP list manager to be removed with the lists")
	}
}

func TestStopIsIdempotent(t *testing.T) {
	e := newTestEngine(t, config.Config{}, Options{})
	e.StopBackground()
	e.StopBackground()
}
