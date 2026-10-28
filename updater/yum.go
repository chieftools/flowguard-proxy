package updater

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

const yumTimeout = 5 * time.Minute

// yumRepoArgs limits a dnf or yum subcommand to the FlowGuard repository, so a
// broken or slow third-party repository cannot fail an upgrade.
func yumRepoArgs(args ...string) []string {
	return append([]string{"--disablerepo=*", "--enablerepo=flowguard"}, args...)
}

// yumChangeArgs installs or downgrades to the version from the FlowGuard
// repository.
func yumChangeArgs(binary, action, pkg, version string) []string {
	return append([]string{binary}, yumRepoArgs(action, "-y", fmt.Sprintf("%s-%s", pkg, version))...)
}

type yumManager struct {
	binary string // Path to dnf or yum binary
	name   string // "dnf" or "yum"
}

func (y *yumManager) Name() string {
	return y.name
}

func (y *yumManager) CheckAvailable(pkg, version string) error {
	// Refresh the local package cache so newly published versions are visible
	updateCtx, updateCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer updateCancel()

	if output, err := exec.CommandContext(updateCtx, y.binary, yumRepoArgs("clean", "expire-cache")...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s clean expire-cache failed: %w\nOutput: %s", y.name, err, string(output))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check if the specific version is available
	cmd := exec.CommandContext(ctx, y.binary, yumRepoArgs("list", "available", fmt.Sprintf("%s-%s*", pkg, version))...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("version %s not found in %s repository for package %s: %w\nOutput: %s", version, y.name, pkg, err, string(output))
	}

	return nil
}

func (y *yumManager) Install(pkg, version string) error {
	ctx, cancel := context.WithTimeout(context.Background(), yumTimeout)
	defer cancel()

	// Run via systemd-run --scope so the package manager lives in a separate cgroup.
	// Without this, the post-install script's "systemctl restart flowguard"
	// causes systemd to kill the package manager (same cgroup), leaving it broken.
	args := append([]string{"--scope", "--description=FlowGuard package upgrade", "--"}, yumChangeArgs(y.binary, "install", pkg, version)...)
	cmd := exec.CommandContext(ctx, "systemd-run", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s install failed: %w\nOutput: %s", y.name, err, string(output))
	}

	return nil
}

func (y *yumManager) Downgrade(pkg, version string) error {
	ctx, cancel := context.WithTimeout(context.Background(), yumTimeout)
	defer cancel()

	args := append([]string{"--scope", "--description=FlowGuard package downgrade", "--"}, yumChangeArgs(y.binary, "downgrade", pkg, version)...)
	cmd := exec.CommandContext(ctx, "systemd-run", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s downgrade failed: %w\nOutput: %s", y.name, err, string(output))
	}

	return nil
}
