package main

import (
	"os"

	"flowguard/cmd"
)

var Version string

func main() {
	// Set version in cmd package
	cmd.Version = Version

	// Execute the root command
	// Cobra handles error display, we just need to exit with appropriate code
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
