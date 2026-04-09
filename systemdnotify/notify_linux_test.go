//go:build linux

package systemdnotify

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNotifyReadyWritesDatagram(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "notify.sock")

	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socketPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen unixgram: %v", err)
	}
	defer listener.Close()

	if err := os.Setenv("NOTIFY_SOCKET", socketPath); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	defer os.Unsetenv("NOTIFY_SOCKET")

	if err := listener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if err := NotifyReady("ready"); err != nil {
		t.Fatalf("notify ready: %v", err)
	}

	buf := make([]byte, 256)
	n, _, err := listener.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("read notify payload: %v", err)
	}

	payload := string(buf[:n])
	if payload != "READY=1\nSTATUS=ready" {
		t.Fatalf("unexpected payload: %q", payload)
	}
}
