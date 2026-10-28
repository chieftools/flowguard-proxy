package updater

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
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

type aptManager struct {
	logPath string // Package manager output without systemd
}

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

	output, err := runPackageChange(ctx, "FlowGuard package upgrade", aptInstallArgs(pkg, version, aptAllowsDowngrades(ctx)), append(os.Environ(), aptEnvironment...), a.logPath)
	if err != nil {
		return fmt.Errorf("apt-get install failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// aptInstallArgs installs the version without prompting. dpkg asks what to do
// with a locally changed config.json when the package ships a new default,
// which nobody can answer here, so the local file is kept and an unchanged
// one is replaced. apt before 1.1 has no --allow-downgrades; its --force-yes
// allows downgrades as well.
func aptInstallArgs(pkg, version string, allowDowngrades bool) []string {
	downgrades := "--allow-downgrades"
	if !allowDowngrades {
		downgrades = "--force-yes"
	}

	return []string{"apt-get", "install", "-y", downgrades,
		"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
		fmt.Sprintf("%s=%s", pkg, version)}
}

// aptAllowsDowngrades reports whether apt-get knows --allow-downgrades, added
// in apt 1.1. Ubuntu 14.04 and Debian 8 ship apt 1.0.
func aptAllowsDowngrades(ctx context.Context) bool {
	output, err := exec.CommandContext(ctx, "apt-get", "--version").Output()
	if err != nil {
		return true
	}

	return !aptVersionBefore11(string(output))
}

// aptVersionBefore11 parses the first line of apt-get --version, such as
// "apt 1.0.1ubuntu2.24 for amd64 compiled on ..." or "apt 2.8.3 (amd64)".
func aptVersionBefore11(output string) bool {
	fields := strings.Fields(output)
	if len(fields) < 2 || fields[0] != "apt" {
		return false
	}

	parts := strings.SplitN(fields[1], ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(strings.TrimRightFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
	if majorErr != nil || minorErr != nil {
		return false
	}

	return major < 1 || (major == 1 && minor < 1)
}

func (a *aptManager) Downgrade(pkg, version string) error {
	// APT treats downgrade as installing an older version with --allow-downgrades
	return a.Install(pkg, version)
}
