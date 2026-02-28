package updater

import (
	"fmt"
	"log"
	"regexp"
	"sync"
	"time"
)

const (
	packageName = "flowguard"

	// staleUpgradeThreshold is the maximum age of an in_progress state
	// before it is considered stale and cleaned up.
	staleUpgradeThreshold = 5 * time.Minute
)

// semverPattern validates version strings (e.g., "1.2.3", "0.1.0").
var semverPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// UpgradeRequest is the payload received from the WebSocket event.
type UpgradeRequest struct {
	Version string `json:"version"`
}

// Updater orchestrates package upgrades with state tracking and rollback support.
type Updater struct {
	version    string
	verbose    bool
	stateDir   string
	pkgManager PackageManager
	mu         sync.Mutex
}

// New creates an Updater by detecting the system package manager.
// Returns an error if no supported package manager is found.
func New(version, stateDir string, verbose bool) (*Updater, error) {
	pm, err := detectPackageManager()
	if err != nil {
		return nil, err
	}

	log.Printf("[updater] Initialized with package manager: %s (current version: %s)", pm.Name(), version)

	return &Updater{
		version:    version,
		verbose:    verbose,
		stateDir:   stateDir,
		pkgManager: pm,
	}, nil
}

// newWithPackageManager creates an Updater with a specific PackageManager (for testing).
func newWithPackageManager(version, stateDir string, verbose bool, pm PackageManager) *Updater {
	return &Updater{
		version:    version,
		verbose:    verbose,
		stateDir:   stateDir,
		pkgManager: pm,
	}
}

// Upgrade validates and executes a package upgrade to the requested version.
// On success, the service will be restarted by the package manager's post-install
// script, so this method may not return.
func (u *Updater) Upgrade(req UpgradeRequest) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	version := req.Version

	// Validate version format
	if !semverPattern.MatchString(version) {
		return fmt.Errorf("invalid version format: %q (expected semver like 1.2.3)", version)
	}

	// Skip if already running the target version
	if version == u.version {
		log.Printf("[updater] Already running version %s, skipping upgrade", version)
		return nil
	}

	log.Printf("[updater] Starting upgrade from %s to %s", u.version, version)

	// Pre-flight: check that the target version is available in the repository
	if err := u.pkgManager.CheckAvailable(packageName, version); err != nil {
		return fmt.Errorf("pre-flight check failed: %w", err)
	}

	if u.verbose {
		log.Printf("[updater] Version %s is available in %s repository", version, u.pkgManager.Name())
	}

	// Write state file before starting the upgrade
	state := &UpgradeState{
		PreviousVersion: u.version,
		TargetVersion:   version,
		StartedAt:       time.Now(),
		Status:          StatusInProgress,
	}
	if err := writeState(u.stateDir, state); err != nil {
		return fmt.Errorf("failed to write upgrade state: %w", err)
	}

	// Execute the install. On success, the post-install script restarts the service,
	// which sends SIGTERM to this process. We won't reach the code after this call
	// in the happy path.
	log.Printf("[updater] Installing %s version %s via %s...", packageName, version, u.pkgManager.Name())
	if err := u.pkgManager.Install(packageName, version); err != nil {
		// Install failed — update state and return error
		state.Status = StatusFailed
		if writeErr := writeState(u.stateDir, state); writeErr != nil {
			log.Printf("[updater] Failed to update state after install failure: %v", writeErr)
		}
		return fmt.Errorf("install failed: %w", err)
	}

	// If we reach here, the install completed without restarting the service.
	// This is unexpected but not an error — the new version will take effect
	// on the next restart.
	log.Printf("[updater] Install completed (service was not restarted by package manager)")
	return nil
}

// CheckPostUpgrade checks for a pending upgrade state on startup.
// If the previous process was upgrading:
//   - If current version matches target: mark completed and clear state
//   - If version doesn't match and upgrade was recent: trigger rollback
//   - If state is stale (>5 min): clean up
func (u *Updater) CheckPostUpgrade() error {
	state, err := readState(u.stateDir)
	if err != nil {
		return fmt.Errorf("failed to read upgrade state: %w", err)
	}

	if state == nil {
		return nil
	}

	// Only process in_progress states
	if state.Status != StatusInProgress {
		// Terminal states — clean up the state file
		if u.verbose {
			log.Printf("[updater] Found terminal upgrade state (%s), cleaning up", state.Status)
		}
		return clearState(u.stateDir)
	}

	age := time.Since(state.StartedAt)

	// Check for stale state (upgrade started more than 5 minutes ago)
	if age > staleUpgradeThreshold {
		log.Printf("[updater] Found stale upgrade state (started %v ago), cleaning up", age.Round(time.Second))
		return clearState(u.stateDir)
	}

	// Check if the upgrade succeeded
	if u.version == state.TargetVersion {
		log.Printf("[updater] Upgrade to %s completed successfully (previous: %s)", state.TargetVersion, state.PreviousVersion)
		return clearState(u.stateDir)
	}

	// Version mismatch — the upgrade may have failed silently
	log.Printf("[updater] Version mismatch after upgrade: running %s, expected %s (previous: %s). Attempting rollback...",
		u.version, state.TargetVersion, state.PreviousVersion)

	// Attempt to downgrade to the previous version.
	// On success, the package manager restarts the service (killing this process).
	// On failure, mark as failed so a subsequent restart doesn't retry indefinitely
	// (the stale threshold would also prevent this, but an explicit status is clearer).
	if err := u.pkgManager.Downgrade(packageName, state.PreviousVersion); err != nil {
		state.Status = StatusFailed
		if writeErr := writeState(u.stateDir, state); writeErr != nil {
			log.Printf("[updater] Failed to update state after rollback failure: %v", writeErr)
		}
		return fmt.Errorf("rollback to %s failed: %w", state.PreviousVersion, err)
	}

	// If we reach here, the downgrade completed without restarting the service.
	state.Status = StatusRolledBack
	if err := writeState(u.stateDir, state); err != nil {
		log.Printf("[updater] Failed to update state after rollback: %v", err)
	}

	log.Printf("[updater] Rollback to %s initiated", state.PreviousVersion)
	return nil
}
