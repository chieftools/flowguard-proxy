package updater

// PackageManager abstracts system package manager operations.
type PackageManager interface {
	// Name returns the package manager name (e.g., "apt", "yum", "dnf").
	Name() string

	// CheckAvailable verifies that the given package version exists in the repository.
	CheckAvailable(pkg, version string) error

	// Install installs the specified version of a package.
	// On success, the package's post-install script typically restarts the service,
	// which means this call may not return if the current process is terminated.
	Install(pkg, version string) error

	// Downgrade installs an older version of a package for rollback purposes.
	Downgrade(pkg, version string) error
}
