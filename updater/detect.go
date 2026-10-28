package updater

import (
	"fmt"
	"os/exec"
)

// detectPackageManager returns the appropriate PackageManager for the system.
// It checks for dnf first (newer Fedora/RHEL), then yum, then apt-get. Without
// systemd, package changes append their output to logPath.
func detectPackageManager(logPath string) (PackageManager, error) {
	if path, err := exec.LookPath("dnf"); err == nil {
		return &yumManager{binary: path, name: "dnf", logPath: logPath}, nil
	}

	if path, err := exec.LookPath("yum"); err == nil {
		return &yumManager{binary: path, name: "yum", logPath: logPath}, nil
	}

	if _, err := exec.LookPath("apt-get"); err == nil {
		return &aptManager{logPath: logPath}, nil
	}

	return nil, fmt.Errorf("no supported package manager found (checked dnf, yum, apt-get)")
}
