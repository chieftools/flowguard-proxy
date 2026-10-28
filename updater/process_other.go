//go:build !unix

package updater

import "syscall"

func detachedProcessAttributes() *syscall.SysProcAttr {
	return nil
}
