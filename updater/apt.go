package updater

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

const aptTimeout = 5 * time.Minute

// aptEnvironment keeps apt and dpkg from prompting and needrestart from
// restarting services on its own.
var aptEnvironment = []string{"DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none", "NEEDRESTART_SUSPEND=1"}

// aptCommand runs name with aptEnvironment added to the process environment.
func aptCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), aptEnvironment...)
	return cmd
}

type aptManager struct{}

func (a *aptManager) Name() string {
	return "apt"
}

func (a *aptManager) CheckAvailable(pkg, version string) error {
	// Refresh the local package cache so newly published versions are visible
	updateCtx, updateCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer updateCancel()

	if output, err := aptCommand(updateCtx, "apt-get", "update").CombinedOutput(); err != nil {
		// Don't fail on apt-get update errors — unrelated broken repos (e.g. expired
		// nodesource) cause a non-zero exit even when the flowguard repo updates fine.
		// The apt-cache policy check below will catch it if the version is truly missing.
		log.Printf("[updater] apt-get update returned an error (continuing anyway): %v\nOutput: %s", err, string(output))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "apt-cache", "policy", pkg)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apt-cache policy failed: %w", err)
	}

	// Check if the target version appears in the output
	if !strings.Contains(string(output), version) {
		return fmt.Errorf("version %s not found in apt repository for package %s", version, pkg)
	}

	return nil
}

func (a *aptManager) Install(pkg, version string) error {
	ctx, cancel := context.WithTimeout(context.Background(), aptTimeout)
	defer cancel()

	// Run via systemd-run --scope so apt-get/dpkg live in a separate cgroup.
	// Without this, the post-install script's "systemctl restart flowguard"
	// causes systemd to kill apt-get/dpkg (same cgroup), leaving dpkg broken.
	cmd := aptCommand(ctx, "systemd-run", "--scope", "--description=FlowGuard package upgrade", "--",
		"apt-get", "install", "-y", "--allow-downgrades", fmt.Sprintf("%s=%s", pkg, version))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apt-get install failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

func (a *aptManager) Downgrade(pkg, version string) error {
	// APT treats downgrade as installing an older version with --allow-downgrades
	return a.Install(pkg, version)
}
