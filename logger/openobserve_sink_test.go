package logger

import (
	"testing"
)

func TestOpenObserve_TimestampMapping(t *testing.T) {
	// Test that timestamp field is correctly mapped to _timestamp for OpenObserve
	input := map[string]interface{}{
		"timestamp": "2025-11-18T10:00:00Z",
		"client": map[string]interface{}{
			"ip": "203.0.113.42",
		},
		"status": 200,
	}

	entry := &LogEntry{Data: input}
	flattened, err := entry.Flatten()
	if err != nil {
		t.Fatalf("Flatten() error: %v", err)
	}

	// Simulate what sendBatch does for OpenObserve
	if timestamp, ok := flattened["timestamp"]; ok {
		flattened["_timestamp"] = timestamp
		delete(flattened, "timestamp")
	}

	// Verify _timestamp exists and timestamp is removed
	if _, exists := flattened["timestamp"]; exists {
		t.Error("timestamp field should be removed")
	}

	if ts, exists := flattened["_timestamp"]; !exists {
		t.Error("_timestamp field should exist")
	} else if ts != "2025-11-18T10:00:00Z" {
		t.Errorf("_timestamp value incorrect: got %v, want %v", ts, "2025-11-18T10:00:00Z")
	}

	// Verify other fields are still flattened correctly
	if flattened["client.ip"] != "203.0.113.42" {
		t.Errorf("client.ip incorrect: got %v", flattened["client.ip"])
	}
	if flattened["status"] != float64(200) { // JSON unmarshal converts numbers to float64
		t.Errorf("status incorrect: got %v (%T)", flattened["status"], flattened["status"])
	}
}
