package updater

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const aptTimeout = 5 * time.Minute

type aptManager struct{}

func (a *aptManager) Name() string {
	return "apt"
}

func (a *aptManager) CheckAvailable(pkg, version string) error {
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

	// apt-get install -y --allow-downgrades flowguard=<version>
	cmd := exec.CommandContext(ctx, "apt-get", "install", "-y", "--allow-downgrades", fmt.Sprintf("%s=%s", pkg, version))
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
