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
