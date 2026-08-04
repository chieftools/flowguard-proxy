package config

import (
	"sync/atomic"
	"testing"

	"flowguard/api"
)

func TestRemoveOnChangeStopsCallbackFromRunning(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "id": "cfg-1",
  "rules": {
    "test-rule": {
      "action": "block-action",
      "conditions": {
        "matches": [
          {
            "type": "path",
            "match": "starts-with",
            "value": "/admin"
          }
        ]
      }
    }
  },
  "actions": {
    "block-action": {
      "action": "block",
      "status": 403
    }
  }
}`)

	manager := &Manager{
		configPath: configPath,
		apiClient:  api.NewClient("", "FlowGuard/test"),
	}
	if err := manager.Load(); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	var called atomic.Int32
	callback := func(*Config) {
		called.Add(1)
	}

	manager.OnChange(callback)
	manager.RemoveOnChange(callback)

	configPath = writeTestConfig(t, `{
  "id": "cfg-2",
  "rules": {
    "test-rule": {
      "action": "block-action",
      "conditions": {
        "matches": [
          {
            "type": "path",
            "match": "starts-with",
            "value": "/admin"
          }
        ]
      }
    }
  },
  "actions": {
    "block-action": {
      "action": "block",
      "status": 403
    }
  }
}`)
	manager.configPath = configPath

	if err := manager.Load(); err != nil {
		t.Fatalf("second load: %v", err)
	}

	if called.Load() != 0 {
		t.Fatalf("expected removed callback not to run, got %d calls", called.Load())
	}
}

func TestLoadDoesNotStartRealtimeClient(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "host": {"key": "host-key"},
  "realtime": {
    "key": "app-key",
    "host": "127.0.0.1",
    "port": 1,
    "channel": "private-test",
    "auth_url": "http://127.0.0.1:1/auth"
  }
}`)
	manager := &Manager{
		configPath: configPath,
		apiClient:  api.NewClient("", "FlowGuard/test"),
	}

	if err := manager.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if manager.realtimeClient != nil {
		t.Fatal("configuration loading must not initialize a realtime client")
	}
	if manager.realtimeEnabled {
		t.Fatal("configuration loading must not enable realtime events")
	}
}
