package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.chief.tools/flowguard-proxy/api"
	"go.chief.tools/flowguard-proxy/config"
	"go.chief.tools/flowguard-proxy/instance"
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

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if !strings.Contains(string(data), `"bind_addresses":[]`) {
		t.Fatalf("bind addresses not sent as an empty list: %s", data)
	}
}

func TestStopTellsThePanelTheInstanceStopped(t *testing.T) {
	requests := make(chan *http.Request, 8)
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(panel.Close)
	t.Setenv("API_BASE", panel.URL)
	e := newTestEngine(t, config.Config{Host: &config.HostConfig{ID: "server_synthetic-a", Key: "synthetic-key"}}, Options{})
	e.StartPanel()

	e.StopBackground()

	for {
		select {
		case request := <-requests:
			if request.URL.Path != "/proxy/v1/heartbeat/stop" {
				continue
			}
			if request.Header.Get(instance.Header) != instance.ID() {
				t.Fatalf("stop sent without instance identity: %v", request.Header)
			}
			return
		case <-time.After(5 * time.Second):
			t.Fatal("no stop sent to the panel")
		}
	}
}

func TestStopDoesNotContactThePanelWithoutHeartbeats(t *testing.T) {
	requests := make(chan string, 8)
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.Path
	}))
	t.Cleanup(panel.Close)
	t.Setenv("API_BASE", panel.URL)
	e := newTestEngine(t, config.Config{}, Options{})

	e.StopBackground()

	select {
	case path := <-requests:
		t.Fatalf("unexpected panel request to %s", path)
	default:
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
