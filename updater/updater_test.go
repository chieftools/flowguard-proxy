package updater

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockPackageManager is a test double for PackageManager.
type mockPackageManager struct {
	name             string
	checkErr         error
	installErr       error
	downgradeErr     error
	installCalled    atomic.Int32
	downgradeCalled  atomic.Int32
	lastInstallVer   string
	lastDowngradeVer string
	mu               sync.Mutex
}

func (m *mockPackageManager) Name() string { return m.name }

func (m *mockPackageManager) CheckAvailable(pkg, version string) error {
	return m.checkErr
}

func (m *mockPackageManager) Install(pkg, version string) error {
	m.installCalled.Add(1)
	m.mu.Lock()
	m.lastInstallVer = version
	m.mu.Unlock()
	return m.installErr
}

func (m *mockPackageManager) Downgrade(pkg, version string) error {
	m.downgradeCalled.Add(1)
	m.mu.Lock()
	m.lastDowngradeVer = version
	m.mu.Unlock()
	return m.downgradeErr
}

func TestUpgrade_InvalidVersion(t *testing.T) {
	u := newWithPackageManager("1.0.0", t.TempDir(), false, &mockPackageManager{name: "test"})

	tests := []string{"", "abc", "1.2", "v1.2.3", "1.2.3.4", "1.2.3-beta"}
	for _, v := range tests {
		err := u.Upgrade(UpgradeRequest{Version: v})
		if err == nil {
			t.Errorf("expected error for version %q, got nil", v)
		}
	}
}

func TestUpgrade_ValidVersion(t *testing.T) {
	u := newWithPackageManager("1.0.0", t.TempDir(), false, &mockPackageManager{name: "test"})

	tests := []string{"1.2.3", "0.0.1", "10.20.30"}
	for _, v := range tests {
		// These will call Install which returns nil, so no error expected
		err := u.Upgrade(UpgradeRequest{Version: v})
		if err != nil {
			t.Errorf("unexpected error for version %q: %v", v, err)
		}
	}
}

func TestUpgrade_SameVersionSkip(t *testing.T) {
	mock := &mockPackageManager{name: "test"}
	u := newWithPackageManager("1.2.3", t.TempDir(), false, mock)

	err := u.Upgrade(UpgradeRequest{Version: "1.2.3"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.installCalled.Load() != 0 {
		t.Error("Install should not have been called for same version")
	}
}

func TestUpgrade_PreflightCheckFails(t *testing.T) {
	mock := &mockPackageManager{
		name:     "test",
		checkErr: fmt.Errorf("version not found"),
	}
	u := newWithPackageManager("1.0.0", t.TempDir(), false, mock)

	err := u.Upgrade(UpgradeRequest{Version: "2.0.0"})
	if err == nil {
		t.Fatal("expected error when pre-flight check fails")
	}

	if mock.installCalled.Load() != 0 {
		t.Error("Install should not have been called when pre-flight check fails")
	}
}

func TestUpgrade_InstallFails(t *testing.T) {
	mock := &mockPackageManager{
		name:       "test",
		installErr: fmt.Errorf("install failed"),
	}
	stateDir := t.TempDir()
	u := newWithPackageManager("1.0.0", stateDir, false, mock)

	err := u.Upgrade(UpgradeRequest{Version: "2.0.0"})
	if err == nil {
		t.Fatal("expected error when install fails")
	}

	// State file should show "failed"
	state, err := readState(stateDir)
	if err != nil {
		t.Fatalf("failed to read state: %v", err)
	}
	if state == nil {
		t.Fatal("expected state file to exist after failed install")
	}
	if state.Status != StatusFailed {
		t.Errorf("expected status %q, got %q", StatusFailed, state.Status)
	}
}

func TestUpgrade_WritesStateFile(t *testing.T) {
	mock := &mockPackageManager{name: "test"}
	stateDir := t.TempDir()
	u := newWithPackageManager("1.0.0", stateDir, false, mock)

	// Install succeeds (simulating package manager didn't restart service)
	err := u.Upgrade(UpgradeRequest{Version: "2.0.0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// State file should exist with in_progress (the new process would clear it)
	state, err := readState(stateDir)
	if err != nil {
		t.Fatalf("failed to read state: %v", err)
	}
	if state == nil {
		t.Fatal("expected state file to exist")
	}
	if state.PreviousVersion != "1.0.0" {
		t.Errorf("expected previous_version %q, got %q", "1.0.0", state.PreviousVersion)
	}
	if state.TargetVersion != "2.0.0" {
		t.Errorf("expected target_version %q, got %q", "2.0.0", state.TargetVersion)
	}
	if state.Status != StatusInProgress {
		t.Errorf("expected status %q, got %q", StatusInProgress, state.Status)
	}
}

func TestCheckPostUpgrade_NoState(t *testing.T) {
	u := newWithPackageManager("1.0.0", t.TempDir(), false, &mockPackageManager{name: "test"})

	err := u.CheckPostUpgrade()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckPostUpgrade_SuccessfulUpgrade(t *testing.T) {
	stateDir := t.TempDir()

	// Write state as if upgrade was in progress
	state := &UpgradeState{
		PreviousVersion: "1.0.0",
		TargetVersion:   "2.0.0",
		StartedAt:       time.Now().Add(-10 * time.Second),
		Status:          StatusInProgress,
	}
	if err := writeState(stateDir, state); err != nil {
		t.Fatalf("failed to write state: %v", err)
	}

	// Running as the new version
	u := newWithPackageManager("2.0.0", stateDir, false, &mockPackageManager{name: "test"})

	err := u.CheckPostUpgrade()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// State file should be cleared
	s, err := readState(stateDir)
	if err != nil {
		t.Fatalf("failed to read state: %v", err)
	}
	if s != nil {
		t.Error("expected state file to be cleared after successful upgrade")
	}
}

func TestCheckPostUpgrade_VersionMismatchTriggersRollback(t *testing.T) {
	stateDir := t.TempDir()
	mock := &mockPackageManager{name: "test"}

	// Write state as if upgrade was in progress
	state := &UpgradeState{
		PreviousVersion: "1.0.0",
		TargetVersion:   "2.0.0",
		StartedAt:       time.Now().Add(-10 * time.Second),
		Status:          StatusInProgress,
	}
	if err := writeState(stateDir, state); err != nil {
		t.Fatalf("failed to write state: %v", err)
	}

	// Running as the OLD version (upgrade didn't stick)
	u := newWithPackageManager("1.0.0", stateDir, false, mock)

	err := u.CheckPostUpgrade()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Downgrade should have been called with the previous version
	if mock.downgradeCalled.Load() != 1 {
		t.Error("expected Downgrade to be called")
	}
	mock.mu.Lock()
	lastVer := mock.lastDowngradeVer
	mock.mu.Unlock()
	if lastVer != "1.0.0" {
		t.Errorf("expected downgrade to version %q, got %q", "1.0.0", lastVer)
	}

	// State should show rolled_back
	s, err := readState(stateDir)
	if err != nil {
		t.Fatalf("failed to read state: %v", err)
	}
	if s == nil {
		t.Fatal("expected state file to exist")
	}
	if s.Status != StatusRolledBack {
		t.Errorf("expected status %q, got %q", StatusRolledBack, s.Status)
	}
}

func TestCheckPostUpgrade_RollbackFailureMarksStateFailed(t *testing.T) {
	stateDir := t.TempDir()
	mock := &mockPackageManager{
		name:         "test",
		downgradeErr: fmt.Errorf("downgrade failed"),
	}

	state := &UpgradeState{
		PreviousVersion: "1.0.0",
		TargetVersion:   "2.0.0",
		StartedAt:       time.Now().Add(-10 * time.Second),
		Status:          StatusInProgress,
	}
	if err := writeState(stateDir, state); err != nil {
		t.Fatalf("failed to write state: %v", err)
	}

	u := newWithPackageManager("1.0.0", stateDir, false, mock)

	err := u.CheckPostUpgrade()
	if err == nil {
		t.Fatal("expected error when rollback fails")
	}

	// State should show failed (not in_progress or rolled_back)
	s, readErr := readState(stateDir)
	if readErr != nil {
		t.Fatalf("failed to read state: %v", readErr)
	}
	if s == nil {
		t.Fatal("expected state file to exist")
	}
	if s.Status != StatusFailed {
		t.Errorf("expected status %q, got %q", StatusFailed, s.Status)
	}
}

func TestCheckPostUpgrade_StaleStateCleanup(t *testing.T) {
	stateDir := t.TempDir()

	// Write state that started over 5 minutes ago
	state := &UpgradeState{
		PreviousVersion: "1.0.0",
		TargetVersion:   "2.0.0",
		StartedAt:       time.Now().Add(-10 * time.Minute),
		Status:          StatusInProgress,
	}
	if err := writeState(stateDir, state); err != nil {
		t.Fatalf("failed to write state: %v", err)
	}

	mock := &mockPackageManager{name: "test"}
	u := newWithPackageManager("1.0.0", stateDir, false, mock)

	err := u.CheckPostUpgrade()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should clean up stale state without attempting rollback
	if mock.downgradeCalled.Load() != 0 {
		t.Error("Downgrade should not be called for stale state")
	}

	s, err := readState(stateDir)
	if err != nil {
		t.Fatalf("failed to read state: %v", err)
	}
	if s != nil {
		t.Error("expected stale state file to be cleared")
	}
}

func TestCheckPostUpgrade_TerminalStateCleansUp(t *testing.T) {
	for _, status := range []UpgradeStatus{StatusCompleted, StatusFailed, StatusRolledBack} {
		t.Run(string(status), func(t *testing.T) {
			stateDir := t.TempDir()
			state := &UpgradeState{
				PreviousVersion: "1.0.0",
				TargetVersion:   "2.0.0",
				StartedAt:       time.Now().Add(-10 * time.Second),
				Status:          status,
			}
			if err := writeState(stateDir, state); err != nil {
				t.Fatalf("failed to write state: %v", err)
			}

			u := newWithPackageManager("1.0.0", stateDir, false, &mockPackageManager{name: "test"})
			if err := u.CheckPostUpgrade(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			s, _ := readState(stateDir)
			if s != nil {
				t.Error("expected terminal state file to be cleared")
			}
		})
	}
}

func TestUpgrade_ConcurrentSerialization(t *testing.T) {
	mock := &mockPackageManager{name: "test"}
	u := newWithPackageManager("1.0.0", t.TempDir(), false, mock)

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			u.Upgrade(UpgradeRequest{Version: fmt.Sprintf("2.0.%d", v)})
		}(i)
	}
	wg.Wait()

	// All 5 should have called install (they run sequentially due to mutex)
	if mock.installCalled.Load() != 5 {
		t.Errorf("expected 5 install calls, got %d", mock.installCalled.Load())
	}
}

func TestStateFile_AtomicWrite(t *testing.T) {
	stateDir := t.TempDir()

	state := &UpgradeState{
		PreviousVersion: "1.0.0",
		TargetVersion:   "2.0.0",
		StartedAt:       time.Now(),
		Status:          StatusInProgress,
	}

	if err := writeState(stateDir, state); err != nil {
		t.Fatalf("failed to write state: %v", err)
	}

	// Verify the file contains valid JSON
	data, err := os.ReadFile(filepath.Join(stateDir, stateFileName))
	if err != nil {
		t.Fatalf("failed to read state file: %v", err)
	}

	var parsed UpgradeState
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("state file contains invalid JSON: %v", err)
	}

	if parsed.PreviousVersion != "1.0.0" {
		t.Errorf("expected previous_version %q, got %q", "1.0.0", parsed.PreviousVersion)
	}
	if parsed.TargetVersion != "2.0.0" {
		t.Errorf("expected target_version %q, got %q", "2.0.0", parsed.TargetVersion)
	}
	if parsed.Status != StatusInProgress {
		t.Errorf("expected status %q, got %q", StatusInProgress, parsed.Status)
	}

	// No temp file should remain
	tmpPath := filepath.Join(stateDir, stateFileName+".tmp")
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("temp file should not exist after successful write")
	}
}

func TestStateFile_ClearNonExistent(t *testing.T) {
	// Clearing a non-existent state file should not error
	err := clearState(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error clearing non-existent state: %v", err)
	}
}

func TestStateFile_ReadNonExistent(t *testing.T) {
	state, err := readState(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != nil {
		t.Error("expected nil state for non-existent file")
	}
}
