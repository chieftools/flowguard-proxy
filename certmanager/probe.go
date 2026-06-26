package certmanager

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ProbeCertificateDirectory reports whether path contains at least one usable
// combined certificate/private-key PEM file for a valid hostname.
func ProbeCertificateDirectory(path string) error {
	if path == "" {
		return fmt.Errorf("certificate directory path is required")
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("certificate directory is not readable: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("certificate path is not a directory: %s", path)
	}

	files, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("failed to read certificate directory: %w", err)
	}

	cm := &Manager{}
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		certFile := filepath.Join(path, file.Name())
		pemData, err := os.ReadFile(certFile)
		if err != nil {
			continue
		}

		cert, err := cm.parseCombinedPEM(pemData)
		if err != nil || cert.Leaf == nil {
			continue
		}

		if time.Now().After(cert.Leaf.NotAfter) {
			continue
		}

		if len(cm.getCertificateHostnames(cert.Leaf)) == 0 {
			continue
		}

		return nil
	}

	return fmt.Errorf("no valid certificates found in %s", path)
}

// ProbeNginxConfig reports whether path can be read and parsed as an NGINX
// config. It does not require certificate directives to be present.
func ProbeNginxConfig(path string) error {
	if path == "" {
		return fmt.Errorf("nginx config path is required")
	}

	if _, _, err := parseNginxConfig(path, false); err != nil {
		return fmt.Errorf("nginx config is not readable: %w", err)
	}

	return nil
}
