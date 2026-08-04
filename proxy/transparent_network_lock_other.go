//go:build !linux

package proxy

import (
	"fmt"
	"os"
)

func lockTransparentNetworkFile(*os.File) error {
	return fmt.Errorf("transparent upstream networking is supported only on Linux")
}

func unlockTransparentNetworkFile(*os.File) error {
	return nil
}
