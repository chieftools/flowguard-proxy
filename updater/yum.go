package updater

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

const yumTimeout = 5 * time.Minute

type yumManager struct {
	binary string // Path to dnf or yum binary
	name   string // "dnf" or "yum"
}

func (y *yumManager) Name() string {
	return y.name
}

func (y *yumManager) CheckAvailable(pkg, version string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check if the specific version is available
	cmd := exec.CommandContext(ctx, y.binary, "list", "available", fmt.Sprintf("%s-%s*", pkg, version))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("version %s not found in %s repository for package %s: %w\nOutput: %s", version, y.name, pkg, err, string(output))
	}

	return nil
}

func (y *yumManager) Install(pkg, version string) error {
	ctx, cancel := context.WithTimeout(context.Background(), yumTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, y.binary, "install", "-y", fmt.Sprintf("%s-%s", pkg, version))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s install failed: %w\nOutput: %s", y.name, err, string(output))
	}

	return nil
}

func (y *yumManager) Downgrade(pkg, version string) error {
	ctx, cancel := context.WithTimeout(context.Background(), yumTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, y.binary, "downgrade", "-y", fmt.Sprintf("%s-%s", pkg, version))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s downgrade failed: %w\nOutput: %s", y.name, err, string(output))
	}

	return nil
}
