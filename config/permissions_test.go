package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s has mode %o, want %o", path, got, want)
	}
}

func TestWriteFileIsOnlyReadableByOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flowguard", "config.json")

	if err := WriteFile(path, []byte(`{}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	assertMode(t, path, 0o600)
}

func TestWriteFileTightensReadableConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A temporary file left by an interrupted write keeps its mode when
	// os.WriteFile reuses it.
	if err := os.WriteFile(path+".tmp", []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteFile(path, []byte(`{"id":"next"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	assertMode(t, path, 0o600)
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected the temporary file to be renamed away, got %v", err)
	}
}

func TestLoadExplainsUnreadableConfiguration(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read files regardless of their mode")
	}

	configPath := writeTestConfig(t, `{}`)
	if err := os.Chmod(configPath, 0o000); err != nil {
		t.Fatal(err)
	}

	_, err := loadTestManager(configPath)
	if err == nil || !strings.Contains(err.Error(), "run flowguard as root") {
		t.Fatalf("expected a hint to run as root, got %v", err)
	}
}
