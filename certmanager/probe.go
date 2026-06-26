package certmanager

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ProbeSummary describes usable certificates discovered in a certificate source.
type ProbeSummary struct {
	Path             string
	CertificateCount int
	HostnameCount    int
	ConfigFileCount  int
}

// ProbeCertificateDirectory reports whether path contains at least one usable
// combined certificate/private-key PEM file for a valid hostname.
func ProbeCertificateDirectory(path string) error {
	_, err := ProbeCertificateDirectorySummary(path)
	return err
}

// ProbeCertificateDirectorySummary validates and summarizes a certificate directory.
func ProbeCertificateDirectorySummary(path string) (ProbeSummary, error) {
	summary := ProbeSummary{Path: path}

	if path == "" {
		return summary, fmt.Errorf("certificate directory path is required")
	}

	info, err := os.Stat(path)
	if err != nil {
		return summary, fmt.Errorf("certificate directory is not readable: %w", err)
	}
	if !info.IsDir() {
		return summary, fmt.Errorf("certificate path is not a directory: %s", path)
	}

	files, err := os.ReadDir(path)
	if err != nil {
		return summary, fmt.Errorf("failed to read certificate directory: %w", err)
	}

	cm := &Manager{}
	hostnames := make(map[string]bool)
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		certFile := filepath.Join(path, file.Name())
		pemData, err := os.ReadFile(certFile)
		if err != nil {
			continue
		}

		certHostnames, ok := probeCertificateHostnames(cm, pemData)
		if !ok {
			continue
		}

		summary.CertificateCount++
		for _, hostname := range certHostnames {
			hostnames[hostname] = true
		}
	}

	summary.HostnameCount = len(hostnames)
	if summary.CertificateCount == 0 {
		return summary, fmt.Errorf("no valid certificates found in %s", path)
	}

	return summary, nil
}

// ProbeNginxConfig reports whether path can be read and parsed as an NGINX
// config. It does not require certificate directives to be present.
func ProbeNginxConfig(path string) error {
	_, err := ProbeNginxConfigSummary(path)
	return err
}

// ProbeNginxConfigSummary validates and summarizes certificates from an NGINX config.
func ProbeNginxConfigSummary(path string) (ProbeSummary, error) {
	summary := ProbeSummary{Path: path}

	if path == "" {
		return summary, fmt.Errorf("nginx config path is required")
	}

	pairs, configFiles, err := parseNginxConfig(path, false)
	if err != nil {
		return summary, fmt.Errorf("nginx config is not readable: %w", err)
	}
	summary.ConfigFileCount = len(configFiles)

	cm := &Manager{}
	hostnames := make(map[string]bool)
	for _, pair := range pairs {
		certPEM, err := os.ReadFile(pair.CertPath)
		if err != nil {
			continue
		}

		keyPEM, err := os.ReadFile(pair.KeyPath)
		if err != nil {
			continue
		}

		combinedPEM := certPEM
		if len(certPEM) > 0 && certPEM[len(certPEM)-1] != '\n' {
			combinedPEM = append(combinedPEM, '\n')
		}
		combinedPEM = append(combinedPEM, keyPEM...)

		certHostnames, ok := probeCertificateHostnames(cm, combinedPEM)
		if !ok {
			continue
		}

		summary.CertificateCount++
		for _, hostname := range certHostnames {
			hostnames[hostname] = true
		}
	}
	summary.HostnameCount = len(hostnames)

	return summary, nil
}

func probeCertificateHostnames(cm *Manager, pemData []byte) ([]string, bool) {
	cert, err := cm.parseCombinedPEM(pemData)
	if err != nil || cert.Leaf == nil {
		return nil, false
	}

	if time.Now().After(cert.Leaf.NotAfter) {
		return nil, false
	}

	hostnames := cm.getCertificateHostnames(cert.Leaf)
	if len(hostnames) == 0 {
		return nil, false
	}

	return hostnames, true
}
