package updater

import (
	"context"
	"io"
	"os"
	"os/exec"

	"go.chief.tools/flowguard-proxy/initsys"
)

// maximumChangeOutput bounds the package manager output kept for an error.
const maximumChangeOutput = 64 << 10

// runPackageChange installs or downgrades the package with argv so that the
// package manager survives the service restart its maintainer scripts do.
func runPackageChange(ctx context.Context, description string, argv, env []string, logPath string) ([]byte, error) {
	if initsys.DetectSystem() == initsys.Systemd {
		// Run via systemd-run --scope so the package manager lives in a separate cgroup.
		// Without this, the post-install script's "systemctl try-restart flowguard"
		// causes systemd to kill the package manager (same cgroup), leaving it broken.
		cmd := exec.CommandContext(ctx, "systemd-run", append([]string{"--scope", "--description=" + description, "--"}, argv...)...)
		cmd.Env = env
		return cmd.CombinedOutput()
	}

	return runDetached(ctx, argv, env, logPath)
}

// runDetached runs argv in its own session with its output appended to
// logPath. Without systemd the init script restarts FlowGuard by its PID, so
// the package manager must not depend on this process: a pipe to it would
// break halfway through the maintainer scripts.
func runDetached(ctx context.Context, argv, env []string, logPath string) ([]byte, error) {
	file, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	offset, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		_ = file.Close()
		return nil, err
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Dir = "/"
	cmd.Stdout = file
	cmd.Stderr = file
	cmd.SysProcAttr = detachedProcessAttributes()

	runErr := cmd.Run()
	_ = file.Close()

	return readOutputSince(logPath, offset), runErr
}

// readOutputSince returns what was appended to path from offset on, at most
// the last maximumChangeOutput bytes.
func readOutputSince(path string, offset int64) []byte {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil
	}
	if info.Size()-offset > maximumChangeOutput {
		offset = info.Size() - maximumChangeOutput
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil
	}

	output, _ := io.ReadAll(file)
	return output
}
