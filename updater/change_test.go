package updater

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDetachedReturnsItsOwnOutputAndExitStatus(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "upgrade.log")
	if err := os.WriteFile(logPath, []byte("an earlier upgrade\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	output, err := runDetached(context.Background(), []string{"sh", "-c", "echo installing; echo broken >&2; exit 3"}, nil, logPath)

	if err == nil || !strings.Contains(err.Error(), "exit status 3") {
		t.Fatalf("expected exit status 3, got %v", err)
	}
	if string(output) != "installing\nbroken\n" {
		t.Fatalf("output = %q, want only this run's output", output)
	}
	if log, _ := os.ReadFile(logPath); string(log) != "an earlier upgrade\ninstalling\nbroken\n" {
		t.Fatalf("log = %q, want the output appended", log)
	}
}

func TestRunDetachedStartsANewSession(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("needs /proc")
	}

	output, err := runDetached(context.Background(), []string{"sh", "-c", `set -- $(cat /proc/$$/stat); [ "$1" = "$6" ] && echo leader`}, nil, filepath.Join(t.TempDir(), "upgrade.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(output)) != "leader" {
		t.Fatalf("expected the package manager to lead its own session, got %q", output)
	}
}

func TestReadOutputSinceKeepsTheEnd(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "upgrade.log")
	if err := os.WriteFile(logPath, []byte(strings.Repeat("a", maximumChangeOutput)+"tail"), 0o600); err != nil {
		t.Fatal(err)
	}

	output := readOutputSince(logPath, 0)

	if len(output) != maximumChangeOutput || !strings.HasSuffix(string(output), "tail") {
		t.Fatalf("got %d bytes ending in %q", len(output), output[len(output)-4:])
	}
}
