package logfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestRotatingFileRotatesAndKeepsBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log", "flowguard.log")
	writer, err := OpenRotatingFile(path, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	for _, line := range []string{"first-\n", "second\n", "third-\n", "fourth\n"} {
		if _, err := writer.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if got := readFile(t, path); got != "fourth\n" {
		t.Errorf("active = %q", got)
	}
	if got := readFile(t, path+".1"); got != "third-\n" {
		t.Errorf("backup 1 = %q", got)
	}
	if got := readFile(t, path+".2"); got != "second\n" {
		t.Errorf("backup 2 = %q", got)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Errorf("backup 3 exists: %v", err)
	}
}

func TestRotatingFileAppendsToExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flowguard.log")
	if err := os.WriteFile(path, []byte("12345678"), 0o640); err != nil {
		t.Fatal(err)
	}
	writer, err := OpenRotatingFile(path, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path+".1"); got != "12345678" {
		t.Errorf("existing content was not rotated: %q", got)
	}
}

func TestRotatingFileOversizedRecordAndNoBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flowguard.log")
	writer, err := OpenRotatingFile(path, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	long := strings.Repeat("x", 20)
	if _, err := writer.Write([]byte(long)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != "y" {
		t.Errorf("active = %q", got)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Errorf("backup written with backups=0")
	}
}

func TestRotatingFileReopen(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "flowguard.log")
	writer, err := OpenRotatingFile(path, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Write([]byte("before\n")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(directory, "moved.log")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Reopen(); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("after\n")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != "after\n" {
		t.Errorf("reopened file = %q", got)
	}
}
