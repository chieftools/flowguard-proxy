package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"flowguard/api"
)

func writeTestConfig(t *testing.T, body string) string {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(body), 0o644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	return configPath
}

func loadTestManager(configPath string) (*Manager, error) {
	manager := &Manager{
		configPath: configPath,
		apiClient:  api.NewClient("", "FlowGuard/test"),
	}

	return manager, manager.Load()
}

func TestManagerLoad_AcceptsSupportedConditionOperators(t *testing.T) {
	tests := []struct {
		name     string
		operator string
	}{
		{name: "AND", operator: "AND"},
		{name: "OR", operator: "OR"},
		{name: "NAND", operator: "NAND"},
		{name: "NOR", operator: "NOR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeTestConfig(t, `{
  "rules": {
    "test-rule": {
      "action": "block-action",
      "conditions": {
        "operator": "`+tt.operator+`",
        "matches": [
          {
            "type": "path",
            "match": "starts-with",
            "value": "/admin"
          }
        ],
        "groups": [
          {
            "matches": [
              {
                "type": "domain",
                "match": "equals",
                "value": "example.com"
              }
            ]
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

			_, err := loadTestManager(configPath)
			if err != nil {
				t.Fatalf("expected operator %s to load: %v", tt.operator, err)
			}
		})
	}
}

func TestManagerLoad_AcceptsEmptyOrMissingOperator(t *testing.T) {
	tests := []struct {
		name       string
		operatorKV string
	}{
		{name: "missing operator", operatorKV: ""},
		{name: "empty operator", operatorKV: `"operator": "",`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeTestConfig(t, `{
  "rules": {
    "test-rule": {
      "action": "block-action",
      "conditions": {
        `+tt.operatorKV+`
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

			_, err := loadTestManager(configPath)
			if err != nil {
				t.Fatalf("expected config to load: %v", err)
			}
		})
	}
}

func TestManagerLoad_RejectsUnsupportedConditionOperators(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "rules": {
    "invalid-rule": {
      "action": "block-action",
      "conditions": {
        "operator": "AND",
        "groups": [
          {
            "operator": "NOT",
            "matches": [
              {
                "type": "domain",
                "match": "equals",
                "value": "example.com"
              }
            ]
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

	_, err := loadTestManager(configPath)
	if err == nil {
		t.Fatal("expected invalid operator to be rejected")
	}

	if !strings.Contains(err.Error(), `invalid operator "NOT"`) {
		t.Fatalf("expected invalid operator in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), `rule "invalid-rule"`) {
		t.Fatalf("expected rule id in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "conditions.groups[0]") {
		t.Fatalf("expected nested path in error, got: %v", err)
	}
}
