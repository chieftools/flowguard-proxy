package logger

import (
	"testing"
)

func TestNewLokiSink(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]interface{}
		expectError bool
	}{
		{
			name: "valid minimal config",
			config: map[string]interface{}{
				"type": "loki",
				"url":  "http://localhost:3100/loki/api/v1/push",
			},
			expectError: false,
		},
		{
			name: "valid config with labels",
			config: map[string]interface{}{
				"type": "loki",
				"url":  "http://localhost:3100/loki/api/v1/push",
				"labels": map[string]interface{}{
					"job":         "flowguard",
					"environment": "test",
				},
			},
			expectError: false,
		},
		{
			name: "valid config with auth",
			config: map[string]interface{}{
				"type":     "loki",
				"url":      "http://localhost:3100/loki/api/v1/push",
				"username": "user",
				"password": "pass",
			},
			expectError: false,
		},
		{
			name: "missing url",
			config: map[string]interface{}{
				"type": "loki",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, err := NewLokiSink("test_sink", tt.config, "FlowGuard/test")

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if sink == nil {
				t.Errorf("expected sink but got nil")
				return
			}

			// Verify sink properties
			lokiSink := sink.(*LokiSink)
			if lokiSink.Name() != "test_sink" {
				t.Errorf("expected name 'test_sink' but got '%s'", lokiSink.Name())
			}

			if lokiSink.url == "" {
				t.Errorf("expected url to be set")
			}

			if lokiSink.ConfigHash() == "" {
				t.Errorf("expected config hash to be set")
			}

			// Verify default label is set
			if job, ok := lokiSink.labels["job"]; !ok || job == "" {
				t.Errorf("expected default 'job' label to be set")
			}

			// Clean up
			if err := sink.Close(); err != nil {
				t.Errorf("error closing sink: %v", err)
			}
		})
	}
}

func TestLokiSinkWrite(t *testing.T) {
	config := map[string]interface{}{
		"type": "loki",
		"url":  "http://localhost:3100/loki/api/v1/push",
	}

	sink, err := NewLokiSink("test_sink", config, "FlowGuard/test")
	if err != nil {
		t.Fatalf("failed to create sink: %v", err)
	}
	defer sink.Close()

	// Create test log entry
	entry := &LogEntry{
		Data: map[string]interface{}{
			"message":   "test log message",
			"level":     "info",
			"timestamp": "2024-01-01T00:00:00Z",
		},
	}

	// Write should not error (even though it might not actually send to Loki)
	// This just tests that the Write method works without panicking
	if err := sink.Write(entry); err != nil {
		// It's okay if we get a channel full error in tests
		if err.Error() != "channel full, event dropped" {
			t.Errorf("unexpected error writing entry: %v", err)
		}
	}
}

func TestLokiSinkClose(t *testing.T) {
	config := map[string]interface{}{
		"type": "loki",
		"url":  "http://localhost:3100/loki/api/v1/push",
	}

	sink, err := NewLokiSink("test_sink", config, "FlowGuard/test")
	if err != nil {
		t.Fatalf("failed to create sink: %v", err)
	}

	// Close the sink
	if err := sink.Close(); err != nil {
		t.Errorf("error closing sink: %v", err)
	}

	// Verify sink is closed
	lokiSink := sink.(*LokiSink)
	if lokiSink.channel != nil {
		t.Errorf("expected channel to be nil after close")
	}

	// Writing after close should error
	entry := &LogEntry{
		Data: map[string]interface{}{
			"message": "test",
		},
	}
	if err := sink.Write(entry); err == nil {
		t.Errorf("expected error writing to closed sink")
	}
}
