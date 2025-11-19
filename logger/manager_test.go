package logger

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManagerBasicUsage(t *testing.T) {
	manager := NewManager("FlowGuard/test")
	defer manager.Close()

	// Create temporary directory for log files
	tmpDir, err := os.MkdirTemp("", "flowguard-logger-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logFile := filepath.Join(tmpDir, "test.log")

	// Configure a file sink
	sinks := map[string]map[string]interface{}{
		"test_file": {
			"type": "file",
			"path": logFile,
		},
	}

	err = manager.UpdateSinks(sinks)
	if err != nil {
		t.Fatalf("Failed to update sinks: %v", err)
	}

	// Verify sink was created
	if !manager.HasSinks() {
		t.Error("Manager should have sinks")
	}

	if manager.SinkCount() != 1 {
		t.Errorf("Expected 1 sink, got %d", manager.SinkCount())
	}

	// Write a log entry
	entry := &LogEntry{
		Data: map[string]interface{}{
			"message": "test message",
			"level":   "info",
		},
	}

	manager.Write(entry)

	// Give it a moment to write
	time.Sleep(100 * time.Millisecond)

	// Verify log file was created and has content
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	if len(content) == 0 {
		t.Error("Log file is empty")
	}

	if string(content) == "" {
		t.Error("Log file has no content")
	}
}

func TestManagerMultipleSinks(t *testing.T) {
	manager := NewManager("FlowGuard/test")
	defer manager.Close()

	// Create temporary directory for log files
	tmpDir, err := os.MkdirTemp("", "flowguard-logger-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logFile1 := filepath.Join(tmpDir, "test1.log")
	logFile2 := filepath.Join(tmpDir, "test2.log")

	// Configure multiple file sinks
	sinks := map[string]map[string]interface{}{
		"file1": {
			"type": "file",
			"path": logFile1,
		},
		"file2": {
			"type": "file",
			"path": logFile2,
		},
	}

	err = manager.UpdateSinks(sinks)
	if err != nil {
		t.Fatalf("Failed to update sinks: %v", err)
	}

	// Verify both sinks were created
	if manager.SinkCount() != 2 {
		t.Errorf("Expected 2 sinks, got %d", manager.SinkCount())
	}

	// Write a log entry
	entry := &LogEntry{
		Data: map[string]interface{}{
			"message": "test message",
		},
	}

	manager.Write(entry)

	// Give it a moment to write
	time.Sleep(100 * time.Millisecond)

	// Verify both log files were created and have content
	for _, logFile := range []string{logFile1, logFile2} {
		content, err := os.ReadFile(logFile)
		if err != nil {
			t.Errorf("Failed to read log file %s: %v", logFile, err)
		}

		if len(content) == 0 {
			t.Errorf("Log file %s is empty", logFile)
		}
	}
}

func TestManagerConfigChangeDetection(t *testing.T) {
	manager := NewManager("FlowGuard/test")
	defer manager.Close()

	// Create temporary directory for log files
	tmpDir, err := os.MkdirTemp("", "flowguard-logger-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logFile := filepath.Join(tmpDir, "test.log")

	// Configure a file sink
	sinks := map[string]map[string]interface{}{
		"test_file": {
			"type": "file",
			"path": logFile,
		},
	}

	// First update
	err = manager.UpdateSinks(sinks)
	if err != nil {
		t.Fatalf("Failed to update sinks: %v", err)
	}

	// Get the original sink
	manager.mu.RLock()
	originalSink := manager.sinks["test_file"]
	manager.mu.RUnlock()

	// Second update with identical config - should not recreate sink
	err = manager.UpdateSinks(sinks)
	if err != nil {
		t.Fatalf("Failed to update sinks (2nd time): %v", err)
	}

	// Get the sink again
	manager.mu.RLock()
	newSink := manager.sinks["test_file"]
	manager.mu.RUnlock()

	// Compare pointers - should be the same sink instance
	if originalSink != newSink {
		t.Error("Sink was recreated even though config didn't change")
	}
}

func TestManagerConfigChange(t *testing.T) {
	manager := NewManager("FlowGuard/test")
	defer manager.Close()

	// Create temporary directory for log files
	tmpDir, err := os.MkdirTemp("", "flowguard-logger-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logFile1 := filepath.Join(tmpDir, "test1.log")
	logFile2 := filepath.Join(tmpDir, "test2.log")

	// Configure first sink
	sinks := map[string]map[string]interface{}{
		"test_file": {
			"type": "file",
			"path": logFile1,
		},
	}

	err = manager.UpdateSinks(sinks)
	if err != nil {
		t.Fatalf("Failed to update sinks: %v", err)
	}

	// Get the original sink
	manager.mu.RLock()
	originalSink := manager.sinks["test_file"]
	manager.mu.RUnlock()

	// Change the config (different path)
	sinks["test_file"]["path"] = logFile2

	err = manager.UpdateSinks(sinks)
	if err != nil {
		t.Fatalf("Failed to update sinks (2nd time): %v", err)
	}

	// Get the sink again
	manager.mu.RLock()
	newSink := manager.sinks["test_file"]
	manager.mu.RUnlock()

	// Compare pointers - should be different sink instances
	if originalSink == newSink {
		t.Error("Sink was not recreated even though config changed")
	}
}

func TestManagerSinkRemoval(t *testing.T) {
	manager := NewManager("FlowGuard/test")
	defer manager.Close()

	// Create temporary directory for log files
	tmpDir, err := os.MkdirTemp("", "flowguard-logger-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logFile := filepath.Join(tmpDir, "test.log")

	// Configure a file sink
	sinks := map[string]map[string]interface{}{
		"test_file": {
			"type": "file",
			"path": logFile,
		},
	}

	err = manager.UpdateSinks(sinks)
	if err != nil {
		t.Fatalf("Failed to update sinks: %v", err)
	}

	if manager.SinkCount() != 1 {
		t.Errorf("Expected 1 sink, got %d", manager.SinkCount())
	}

	// Remove the sink by updating with empty config
	err = manager.UpdateSinks(map[string]map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to update sinks (remove): %v", err)
	}

	if manager.SinkCount() != 0 {
		t.Errorf("Expected 0 sinks, got %d", manager.SinkCount())
	}

	if manager.HasSinks() {
		t.Error("Manager should not have sinks after removal")
	}
}
