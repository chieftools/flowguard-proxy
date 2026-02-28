package updater

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const stateFileName = "upgrade.state.json"

// UpgradeStatus represents the current status of an upgrade.
type UpgradeStatus string

const (
	StatusInProgress UpgradeStatus = "in_progress"
	StatusCompleted  UpgradeStatus = "completed"
	StatusFailed     UpgradeStatus = "failed"
	StatusRolledBack UpgradeStatus = "rolled_back"
)

// UpgradeState tracks the state of an in-progress or recently completed upgrade.
type UpgradeState struct {
	PreviousVersion string        `json:"previous_version"`
	TargetVersion   string        `json:"target_version"`
	StartedAt       time.Time     `json:"started_at"`
	Status          UpgradeStatus `json:"status"`
}

// stateFilePath returns the full path to the state file.
func stateFilePath(stateDir string) string {
	return filepath.Join(stateDir, stateFileName)
}

// readState reads the upgrade state from disk.
// Returns nil if the state file does not exist.
func readState(stateDir string) (*UpgradeState, error) {
	path := stateFilePath(stateDir)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	var state UpgradeState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse state file: %w", err)
	}

	return &state, nil
}

// writeState atomically writes the upgrade state to disk.
func writeState(stateDir string, state *UpgradeState) error {
	data, err := json.MarshalIndent(state, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	path := stateFilePath(stateDir)
	tmpPath := path + ".tmp"

	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename state file: %w", err)
	}

	return nil
}

// clearState removes the state file.
func clearState(stateDir string) error {
	path := stateFilePath(stateDir)
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove state file: %w", err)
	}
	return nil
}
