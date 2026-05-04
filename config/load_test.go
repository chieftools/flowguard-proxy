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

func TestLoadRejectsAllProtocolsDisabled(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "server": {
    "protocols": {
      "http1": false,
      "http2": false,
      "http3": false
    }
  }
}`)

	_, err := loadTestManager(configPath)
	if err == nil {
		t.Fatal("expected all protocols disabled to be rejected")
	}
	if err.Error() != "server.protocols must enable at least one protocol" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadAcceptsChallengeAction(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "challenges": {
    "cookie_name": "fg_clearance",
    "min_page_time_ms": 1500,
    "bind_ip": false,
    "bind_user_agent": false,
    "pow": {
      "difficulty_bits": 1,
      "challenge_ttl_seconds": 120,
      "algorithm": "pbkdf2-sha256",
      "pbkdf2_iterations": 1
    }
  },
  "rules": {
    "challenge-admin": {
      "action": "pow-action",
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
    "pow-action": {
      "action": "challenge",
      "challenge": {
        "type": "pow",
        "clearance_scope": "rule",
        "ttl_seconds": 60,
        "min_page_time_ms": 1500,
        "difficulty_bits": 1,
        "pbkdf2_iterations": 1
      }
    }
  }
}`)

	manager, err := loadTestManager(configPath)
	if err != nil {
		t.Fatalf("load manager: %v", err)
	}

	action := manager.config.Actions["pow-action"]
	if action == nil || action.Challenge == nil {
		t.Fatal("expected challenge action to load")
	}
	if action.Challenge.ClearanceScope != "rule" {
		t.Fatalf("expected rule clearance scope, got %q", action.Challenge.ClearanceScope)
	}
}

func TestLoadRejectsInvalidChallengeMinPageTime(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "challenges": {
    "min_page_time_ms": 60001
  }
}`)

	_, err := loadTestManager(configPath)
	if err == nil {
		t.Fatal("expected invalid challenge minimum page time to be rejected")
	}
	if err.Error() != "challenges.min_page_time_ms must be between 0 and 60000" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsInvalidChallengeScope(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "actions": {
    "pow-action": {
      "action": "challenge",
      "challenge": {
        "clearance_scope": "session"
      }
    }
  }
}`)

	_, err := loadTestManager(configPath)
	if err == nil {
		t.Fatal("expected invalid challenge scope to be rejected")
	}
	if err.Error() != `invalid challenge.clearance_scope "session" in action "pow-action"` {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsInvalidNestedPoWDifficulty(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "challenges": {
    "pow": {
      "difficulty_bits": 31
    }
  }
}`)

	_, err := loadTestManager(configPath)
	if err == nil {
		t.Fatal("expected invalid nested PoW difficulty to be rejected")
	}
	if err.Error() != "challenges.pow.difficulty_bits must be between 1 and 30" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsInvalidNestedPoWAlgorithm(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "challenges": {
    "pow": {
      "algorithm": "md5"
    }
  }
}`)

	_, err := loadTestManager(configPath)
	if err == nil {
		t.Fatal("expected invalid nested PoW algorithm to be rejected")
	}
	if err.Error() != `challenges.pow.algorithm must be "pbkdf2-sha256" or "sha256"` {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsInvalidNestedPoWEffortMode(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "challenges": {
    "pow": {
      "effort_mode": "instant"
    }
  }
}`)

	_, err := loadTestManager(configPath)
	if err == nil {
		t.Fatal("expected invalid nested PoW effort mode to be rejected")
	}
	if err.Error() != `challenges.pow.effort_mode must be "calibrated" or "probabilistic"` {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsInvalidNestedPoWWorkUnits(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "challenges": {
    "pow": {
      "work_units": 100001
    }
  }
}`)

	_, err := loadTestManager(configPath)
	if err == nil {
		t.Fatal("expected invalid nested PoW work units to be rejected")
	}
	if err.Error() != "challenges.pow.work_units must be between 1 and 100000" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsZeroChallengeTokenTTL(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "challenges": {
    "pow": {
      "challenge_ttl_seconds": 0
    }
  }
}`)

	_, err := loadTestManager(configPath)
	if err == nil {
		t.Fatal("expected zero challenge token TTL to be rejected")
	}
	if err.Error() != "challenges.pow.challenge_ttl_seconds must be greater than 0" {
		t.Fatalf("unexpected error: %v", err)
	}
}
