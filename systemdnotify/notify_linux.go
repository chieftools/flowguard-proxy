//go:build linux

package systemdnotify

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func NotifyReady(status string) error {
	return notify(buildState("READY=1", status))
}

func NotifyStopping(status string) error {
	return notify(buildState("STOPPING=1", status))
}

func NotifyStatus(status string) error {
	return notify(buildState("", status))
}

func buildState(prefix string, status string) string {
	parts := make([]string, 0, 2)
	if prefix != "" {
		parts = append(parts, prefix)
	}
	if status != "" {
		parts = append(parts, fmt.Sprintf("STATUS=%s", status))
	}
	return strings.Join(parts, "\n")
}

func notify(state string) error {
	if state == "" {
		return nil
	}

	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}

	addr := &unix.SockaddrUnix{Name: socket}
	if strings.HasPrefix(socket, "@") {
		addr.Name = "\x00" + socket[1:]
	}

	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	if err := unix.Connect(fd, addr); err != nil {
		return err
	}

	_, err = unix.Write(fd, []byte(state))
	return err
}
