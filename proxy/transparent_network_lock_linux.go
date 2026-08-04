//go:build linux

package proxy

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockTransparentNetworkFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func unlockTransparentNetworkFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
