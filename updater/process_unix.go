//go:build unix

package updater

import "syscall"

// detachedProcessAttributes starts the process in a session of its own.
func detachedProcessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
