// Package initsys detects the init system that runs FlowGuard, so commands
// can explain how to manage the service and the updater can install packages
// without systemd.
package initsys

import (
	"io/fs"
	"os"
	"strings"
)

// Kind identifies an init system.
type Kind string

const (
	Systemd Kind = "systemd"
	Upstart Kind = "upstart"
	SysV    Kind = "sysv"
	Unknown Kind = "unknown"
)

// Detect inspects a file system rooted at "/" and reports the running init
// system. It follows sd_booted(3): systemd is running when
// /run/systemd/system exists. Upstart is recognised by its control tool and
// job directory, and anything else with /etc/init.d is SysV.
func Detect(fsys fs.FS) Kind {
	if isDir(fsys, "run/systemd/system") {
		return Systemd
	}
	if comm := readTrimmed(fsys, "proc/1/comm"); comm == "systemd" {
		return Systemd
	}
	if exists(fsys, "sbin/initctl") && isDir(fsys, "etc/init") && upstartInit(fsys) {
		return Upstart
	}
	if isDir(fsys, "etc/init.d") || isDir(fsys, "etc/rc.d/init.d") {
		return SysV
	}
	return Unknown
}

// DetectSystem detects the init system of the running machine.
func DetectSystem() Kind {
	return Detect(os.DirFS("/"))
}

// upstartInit separates Upstart from SysV hosts that merely ship a
// compatibility initctl.
func upstartInit(fsys fs.FS) bool {
	if target, err := fs.ReadLink(fsys, "proc/1/exe"); err == nil && strings.Contains(target, "upstart") {
		return true
	}
	if target, err := fs.ReadLink(fsys, "sbin/init"); err == nil && strings.Contains(target, "upstart") {
		return true
	}
	return exists(fsys, "usr/share/upstart") || exists(fsys, "etc/init/rc-sysinit.conf")
}

func exists(fsys fs.FS, name string) bool {
	_, err := fs.Stat(fsys, name)
	return err == nil
}

func isDir(fsys fs.FS, name string) bool {
	info, err := fs.Stat(fsys, name)
	return err == nil && info.IsDir()
}

func readTrimmed(fsys fs.FS, name string) string {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
