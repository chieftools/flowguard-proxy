package certmanager

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Manager handles SSL/TLS certificate loading and management
type Manager struct {
	certPath      string
	certCache     map[string]*tls.Certificate // Maps certificate file path to certificate
	hostnameCache map[string]*tls.Certificate // Maps hostname to certificate
	cacheMutex    sync.RWMutex
	reloadTime    time.Duration
}

// New creates a new certificate manager
func New(certPath string) *Manager {
	cm := &Manager{
		certPath:      certPath,
		certCache:     make(map[string]*tls.Certificate),
		hostnameCache: make(map[string]*tls.Certificate),
		reloadTime:    5 * time.Minute,
	}

	cm.loadAllCertificates(true)
	go cm.periodicReload()

	return cm
}

func (cm *Manager) parseCombinedPEM(pemData []byte) (*tls.Certificate, error) {
	var certPEMBlocks [][]byte
	var keyPEMBlock []byte

	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			certPEMBlocks = append(certPEMBlocks, pem.EncodeToMemory(block))
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if keyPEMBlock == nil {
				keyPEMBlock = pem.EncodeToMemory(block)
			}
		case "CERTIFICATE REQUEST":
			// Skip CSR blocks
		}

		pemData = rest
	}

	if len(certPEMBlocks) == 0 || keyPEMBlock == nil {
		return nil, fmt.Errorf("missing certificate or private key")
	}

	// Combine all certificate blocks
	certPEM := append([]byte{}, certPEMBlocks[0]...)
	for i := 1; i < len(certPEMBlocks); i++ {
		certPEM = append(certPEM, certPEMBlocks[i]...)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEMBlock)
	if err != nil {
		return nil, err
	}

	// Parse the leaf certificate
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}

	return &cert, nil
}

func (cm *Manager) loadAllCertificates(verbose bool) {
	// Load into temporary maps
	tempCertCache := make(map[string]*tls.Certificate)
	tempHostnameCache := make(map[string]*tls.Certificate)

	files, err := ioutil.ReadDir(cm.certPath)
	if err != nil {
		log.Printf("[certmanager] Error reading certificate directory %s: %v", cm.certPath, err)
		return
	}

	successCount := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		certFile := filepath.Join(cm.certPath, file.Name())
		pemData, err := ioutil.ReadFile(certFile)
		if err != nil {
			if verbose {
				log.Printf("[certmanager] Failed to read certificate file %s: %v", certFile, err)
			}
			continue
		}

		cert, err := cm.parseCombinedPEM(pemData)
		if err != nil {
			if verbose {
				log.Printf("[certmanager] Failed to parse certificate %s: %v", certFile, err)
			}
			continue
		}

		tempCertCache[certFile] = cert
		successCount++

		// Map the certificate to all its valid hostnames
		if cert.Leaf != nil {
			for _, name := range cm.getCertificateHostnames(cert.Leaf) {
				tempHostnameCache[name] = cert
			}
		}
	}

	// Atomically swap the caches
	cm.cacheMutex.Lock()
	cm.certCache = tempCertCache
	cm.hostnameCache = tempHostnameCache
	cm.cacheMutex.Unlock()

	log.Printf("[certmanager] Loaded %d certificates from %s covering %d hostnames", successCount, cm.certPath, len(tempHostnameCache))
}

// TestCertificates validates all certificates and displays their status
func (cm *Manager) TestCertificates() {
	files, err := ioutil.ReadDir(cm.certPath)
	if err != nil {
		log.Fatalf("Error reading certificate directory %s: %v", cm.certPath, err)
	}

	log.Printf("Testing certificates in %s...\n", cm.certPath)

	successCount := 0
	failCount := 0

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		certFile := filepath.Join(cm.certPath, file.Name())
		pemData, err := ioutil.ReadFile(certFile)
		if err != nil {
			log.Printf("✗ %s: Failed to read file: %v", file.Name(), err)
			failCount++
			continue
		}

		cert, err := cm.parseCombinedPEM(pemData)
		if err != nil {
			log.Printf("✗ %s: Failed to parse: %v", file.Name(), err)
			failCount++
			continue
		}

		if cert.Leaf != nil {
			hostnames := cm.getCertificateHostnames(cert.Leaf)
			notAfter := cert.Leaf.NotAfter.Format("2006-01-02")

			if time.Now().After(cert.Leaf.NotAfter) {
				log.Printf("✗ %s: EXPIRED (expired %s) - Hosts: %v", file.Name(), notAfter, hostnames)
				failCount++
			} else if time.Now().Add(30 * 24 * time.Hour).After(cert.Leaf.NotAfter) {
				log.Printf("⚠ %s: EXPIRING SOON (expires %s) - Hosts: %v", file.Name(), notAfter, hostnames)
				successCount++
			} else {
				log.Printf("✓ %s: Valid until %s - Hosts: %v", file.Name(), notAfter, hostnames)
				successCount++
			}
		} else {
			log.Printf("✓ %s: Loaded successfully", file.Name())
			successCount++
		}
	}

	log.Printf("\nCertificate test complete: %d successful, %d failed", successCount, failCount)

	if len(cm.hostnameCache) > 0 {
		log.Printf("Total hostnames covered: %d", len(cm.hostnameCache))

		// Show sample of covered hostnames
		count := 0
		for hostname := range cm.hostnameCache {
			if count < 10 {
				log.Printf("  - %s", hostname)
				count++
			} else {
				log.Printf("  ... and %d more", len(cm.hostnameCache)-10)
				break
			}
		}
	}
}

func (cm *Manager) getCertificateHostnames(cert *x509.Certificate) []string {
	var hostnames []string

	// Add CN if present
	if cert.Subject.CommonName != "" {
		hostnames = append(hostnames, cert.Subject.CommonName)
	}

	// Add all SANs
	hostnames = append(hostnames, cert.DNSNames...)

	return hostnames
}

func (cm *Manager) matchesWildcard(pattern, hostname string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == hostname
	}

	// For wildcard certificates like *.example.com
	suffix := pattern[1:] // .example.com
	if !strings.HasSuffix(hostname, suffix) {
		return false
	}

	// Check that there's exactly one more domain component
	prefix := strings.TrimSuffix(hostname, suffix)
	return !strings.Contains(prefix, ".")
}

func (cm *Manager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.cacheMutex.RLock()
	defer cm.cacheMutex.RUnlock()

	// First, try exact hostname match
	if cert, exists := cm.hostnameCache[hello.ServerName]; exists {
		return cert, nil
	}

	// Then, try wildcard match
	for hostname, cert := range cm.hostnameCache {
		if strings.HasPrefix(hostname, "*.") && cm.matchesWildcard(hostname, hello.ServerName) {
			return cert, nil
		}
	}

	// Finally, try to find any default certificate in cache
	if cert, exists := cm.hostnameCache["*.alboweb.nl"]; exists {
		return cert, nil
	}

	return nil, fmt.Errorf("no certificate found for %s", hello.ServerName)
}

// GetTlsConfig returns the tls configuration for use in servers
func (cm *Manager) GetTlsConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: cm.getCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

func (cm *Manager) periodicReload() {
	ticker := time.NewTicker(cm.reloadTime)
	defer ticker.Stop()

	for range ticker.C {
		cm.loadAllCertificates(false)
	}
}
