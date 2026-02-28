package updater

import (
	"fmt"
	"os/exec"
)

// detectPackageManager returns the appropriate PackageManager for the system.
// It checks for dnf first (newer Fedora/RHEL), then yum, then apt-get.
func detectPackageManager() (PackageManager, error) {
	if path, err := exec.LookPath("dnf"); err == nil {
		return &yumManager{binary: path, name: "dnf"}, nil
	}

	if path, err := exec.LookPath("yum"); err == nil {
		return &yumManager{binary: path, name: "yum"}, nil
	}

	if _, err := exec.LookPath("apt-get"); err == nil {
		return &aptManager{}, nil
	}

	return nil, fmt.Errorf("no supported package manager found (checked dnf, yum, apt-get)")
}
