package config

import "testing"

func TestComputeSortedRules(t *testing.T) {
	manager := &Manager{}

	sorted := manager.computeSortedRules(map[string]*Rule{
		"z-last":  {ID: "z-last"},
		"a-first": {ID: "a-first", SortOrder: 1},
		"b-next":  {ID: "b-next", SortOrder: 1},
		"c-mid":   {ID: "c-mid", SortOrder: 2},
	})

	if len(sorted) != 4 {
		t.Fatalf("expected 4 sorted rules, got %d", len(sorted))
	}

	got := []string{sorted[0].ID, sorted[1].ID, sorted[2].ID, sorted[3].ID}
	want := []string{"a-first", "b-next", "c-mid", "z-last"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected order %v, got %v", want, got)
		}
	}

	if manager.computeSortedRules(nil) != nil {
		t.Fatal("expected nil rules to return nil")
	}
}

func TestLoadHydratesIDsAndSortsRules(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "id": "cfg-123",
  "rules": {
    "z-rule": {
      "action": "action-z",
      "conditions": {
        "matches": [
          {
            "type": "path",
            "match": "starts-with",
            "value": "/z"
          }
        ]
      }
    },
    "a-rule": {
      "action": "action-a",
      "sort_order": 1,
      "conditions": {
        "matches": [
          {
            "type": "path",
            "match": "starts-with",
            "value": "/a"
          }
        ]
      }
    }
  },
  "actions": {
    "action-z": {
      "action": "block",
      "status": 403
    },
    "action-a": {
      "action": "block",
      "status": 429
    }
  }
}`)

	manager, err := loadTestManager(configPath)
	if err != nil {
		t.Fatalf("load manager: %v", err)
	}

	if manager.currentConfigID != "cfg-123" {
		t.Fatalf("expected current config id cfg-123, got %s", manager.currentConfigID)
	}

	if manager.config.Rules["a-rule"].ID != "a-rule" || manager.config.Rules["z-rule"].ID != "z-rule" {
		t.Fatal("expected rule IDs to be hydrated from map keys")
	}

	if manager.config.Actions["action-a"].ID != "action-a" || manager.config.Actions["action-z"].ID != "action-z" {
		t.Fatal("expected action IDs to be hydrated from map keys")
	}

	if len(manager.sortedRules) != 2 {
		t.Fatalf("expected 2 sorted rules, got %d", len(manager.sortedRules))
	}
	if manager.sortedRules[0].ID != "a-rule" || manager.sortedRules[1].ID != "z-rule" {
		t.Fatalf("unexpected sorted rule order: %s, %s", manager.sortedRules[0].ID, manager.sortedRules[1].ID)
	}
}
