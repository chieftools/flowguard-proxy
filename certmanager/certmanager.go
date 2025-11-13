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

	"github.com/fsnotify/fsnotify"
)

// Manager handles SSL/TLS certificate loading and management
type Manager struct {
	certPath         string
	nginxConfigPath  string
	defaultHostname  string
	verbose          bool
	certCache        map[string]*tls.Certificate // Maps certificate file path to certificate
	hostnameCache    map[string]*tls.Certificate // Maps hostname to certificate
	cacheMutex       sync.RWMutex
	watcher          *fsnotify.Watcher
	stopChan         chan struct{}
	nginxConfigFiles []string // List of NGINX config files to watch
}

// New creates a new certificate manager
// Both certPath and nginxConfigPath are optional - at least one should be provided
func New(certPath, nginxConfigPath, defaultHostname string, verbose bool) *Manager {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("[cert_manager] Warning: Failed to create file watcher: %v. Certificate updates will not be automatic.", err)
	}

	cm := &Manager{
		certPath:         certPath,
		nginxConfigPath:  nginxConfigPath,
		defaultHostname:  defaultHostname,
		verbose:          verbose,
		certCache:        make(map[string]*tls.Certificate),
		hostnameCache:    make(map[string]*tls.Certificate),
		watcher:          watcher,
		stopChan:         make(chan struct{}),
		nginxConfigFiles: make([]string, 0),
	}

	cm.loadAllCertificates(false)

	// Watch certificate directory if provided
	if watcher != nil && certPath != "" {
		err = watcher.Add(certPath)
		if err != nil {
			log.Printf("[cert_manager] Warning: Failed to watch certificate directory %s: %v", certPath, err)
		} else {
			if verbose {
				log.Printf("[cert_manager] Watching certificate directory %s for changes", certPath)
			}
		}
	}

	// Watch NGINX config files if provided
	if watcher != nil && nginxConfigPath != "" {
		// Track which directories we've already added to avoid duplicates
		watchedDirs := make(map[string]bool)

		for _, configFile := range cm.nginxConfigFiles {
			// Watch the directory containing each config file
			configDir := filepath.Dir(configFile)

			// Skip if we've already added this directory
			if watchedDirs[configDir] {
				continue
			}

			err = watcher.Add(configDir)
			if err != nil {
				log.Printf("[cert_manager] Warning: Failed to watch NGINX config directory %s: %v", configDir, err)
			} else {
				watchedDirs[configDir] = true
				if verbose {
					log.Printf("[cert_manager] Watching NGINX config directory %s for changes", configDir)
				}
			}
		}
	}

	// Start watching if we have any paths to watch
	if watcher != nil && (certPath != "" || nginxConfigPath != "") {
		go cm.watchCertificates()
	} else if watcher != nil {
		// No paths to watch, close the watcher
		watcher.Close()
		cm.watcher = nil
	}

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

	successCount := 0
	fromDir := 0
	fromNginx := 0

	// Load from certificate directory if provided
	if cm.certPath != "" {
		files, err := ioutil.ReadDir(cm.certPath)
		if err != nil {
			log.Printf("[cert_manager] Error reading certificate directory %s: %v", cm.certPath, err)
		} else {
			for _, file := range files {
				if file.IsDir() {
					continue
				}

				certFile := filepath.Join(cm.certPath, file.Name())
				pemData, err := ioutil.ReadFile(certFile)
				if err != nil {
					if verbose {
						log.Printf("[cert_manager] Failed to read certificate file %s: %v", certFile, err)
					}
					continue
				}

				cert, err := cm.parseCombinedPEM(pemData)
				if err != nil {
					if verbose {
						log.Printf("[cert_manager] Failed to parse certificate %s: %v", certFile, err)
					}
					continue
				}

				// Check if certificate is expired
				if cert.Leaf != nil && time.Now().After(cert.Leaf.NotAfter) {
					if verbose {
						log.Printf("[cert_manager] Skipping expired certificate %s (expired %s)", certFile, cert.Leaf.NotAfter.Format("2006-01-02"))
					}
					continue
				}

				tempCertCache[certFile] = cert
				successCount++
				fromDir++

				// Map the certificate to all its valid hostnames
				if cert.Leaf != nil {
					for _, name := range cm.getCertificateHostnames(cert.Leaf) {
						tempHostnameCache[name] = cert
					}
				}
			}
		}
	}

	// Load from NGINX config if provided
	if cm.nginxConfigPath != "" {
		pairs, configFiles, err := parseNginxConfig(cm.nginxConfigPath, verbose)
		if err != nil {
			log.Printf("[cert_manager] Error parsing NGINX config %s: %v", cm.nginxConfigPath, err)
		} else {
			// Store the list of config files for watching
			cm.nginxConfigFiles = configFiles

			for _, pair := range pairs {
				// Read cert and key files separately
				certPEM, err := ioutil.ReadFile(pair.CertPath)
				if err != nil {
					if verbose {
						log.Printf("[cert_manager] Failed to read certificate file %s: %v", pair.CertPath, err)
					}
					continue
				}

				keyPEM, err := ioutil.ReadFile(pair.KeyPath)
				if err != nil {
					if verbose {
						log.Printf("[cert_manager] Failed to read key file %s: %v", pair.KeyPath, err)
					}
					continue
				}

				// Combine cert and key
				// Ensure there's a newline between cert and key
				combinedPEM := certPEM
				if len(certPEM) > 0 && certPEM[len(certPEM)-1] != '\n' {
					combinedPEM = append(combinedPEM, '\n')
				}
				combinedPEM = append(combinedPEM, keyPEM...)

				cert, err := cm.parseCombinedPEM(combinedPEM)
				if err != nil {
					if verbose {
						log.Printf("[cert_manager] Failed to parse certificate pair %s + %s: %v", pair.CertPath, pair.KeyPath, err)
					}
					continue
				}

				// Check if certificate is expired
				if cert.Leaf != nil && time.Now().After(cert.Leaf.NotAfter) {
					if verbose {
						log.Printf("[cert_manager] Skipping expired certificate %s (expired %s)", pair.CertPath, cert.Leaf.NotAfter.Format("2006-01-02"))
					}
					continue
				}

				// Use cert path as cache key
				tempCertCache[pair.CertPath] = cert
				successCount++
				fromNginx++

				// Map the certificate to all its valid hostnames
				if cert.Leaf != nil {
					for _, name := range cm.getCertificateHostnames(cert.Leaf) {
						tempHostnameCache[name] = cert
					}
				}
			}
		}
	}

	// Atomically swap the caches
	cm.cacheMutex.Lock()
	cm.certCache = tempCertCache
	cm.hostnameCache = tempHostnameCache
	cm.cacheMutex.Unlock()

	// Build status message
	var sources []string
	if fromDir > 0 {
		sources = append(sources, fmt.Sprintf("%d from directory", fromDir))
	}
	if fromNginx > 0 {
		sources = append(sources, fmt.Sprintf("%d from NGINX config", fromNginx))
	}
	sourceMsg := strings.Join(sources, ", ")
	if sourceMsg == "" {
		sourceMsg = "0 certificates"
	}

	log.Printf("[cert_manager] Loaded %d certificates (%s) covering %d hostnames", successCount, sourceMsg, len(tempHostnameCache))
}

// TestCertificates validates all certificates and displays their status
func (cm *Manager) TestCertificates() {
	successCount := 0
	failCount := 0

	// Test certificates from directory if provided
	if cm.certPath != "" {
		files, err := ioutil.ReadDir(cm.certPath)
		if err != nil {
			log.Printf("Warning: Error reading certificate directory %s: %v", cm.certPath, err)
		} else {
			log.Printf("Testing certificates in directory %s...\n", cm.certPath)

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
		}
	}

	// Test certificates from NGINX config if provided
	if cm.nginxConfigPath != "" {
		pairs, _, err := parseNginxConfig(cm.nginxConfigPath, cm.verbose)
		if err != nil {
			log.Printf("Warning: Error parsing NGINX config %s: %v", cm.nginxConfigPath, err)
		} else {
			log.Printf("\nTesting certificates from NGINX config %s...\n", cm.nginxConfigPath)

			for _, pair := range pairs {
				// Read cert and key files
				certPEM, err := ioutil.ReadFile(pair.CertPath)
				if err != nil {
					log.Printf("✗ %s: Failed to read certificate: %v", pair.CertPath, err)
					failCount++
					continue
				}

				keyPEM, err := ioutil.ReadFile(pair.KeyPath)
				if err != nil {
					log.Printf("✗ %s: Failed to read key: %v", pair.KeyPath, err)
					failCount++
					continue
				}

				// Combine and parse
				// Ensure there's a newline between cert and key
				combinedPEM := certPEM
				if len(certPEM) > 0 && certPEM[len(certPEM)-1] != '\n' {
					combinedPEM = append(combinedPEM, '\n')
				}
				combinedPEM = append(combinedPEM, keyPEM...)
				cert, err := cm.parseCombinedPEM(combinedPEM)
				if err != nil {
					log.Printf("✗ %s + %s: Failed to parse: %v", pair.CertPath, pair.KeyPath, err)
					failCount++
					continue
				}

				if cert.Leaf != nil {
					hostnames := cm.getCertificateHostnames(cert.Leaf)
					notAfter := cert.Leaf.NotAfter.Format("2006-01-02")

					if time.Now().After(cert.Leaf.NotAfter) {
						log.Printf("✗ %s: EXPIRED (expired %s) - Hosts: %v", pair.CertPath, notAfter, hostnames)
						failCount++
					} else if time.Now().Add(30 * 24 * time.Hour).After(cert.Leaf.NotAfter) {
						log.Printf("⚠ %s: EXPIRING SOON (expires %s) - Hosts: %v", pair.CertPath, notAfter, hostnames)
						successCount++
					} else {
						log.Printf("✓ %s: Valid until %s - Hosts: %v", pair.CertPath, notAfter, hostnames)
						successCount++
					}
				} else {
					log.Printf("✓ %s: Loaded successfully", pair.CertPath)
					successCount++
				}
			}
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

	// Add CN if present and valid
	if cert.Subject.CommonName != "" && cm.isValidHostname(cert.Subject.CommonName) {
		hostnames = append(hostnames, cert.Subject.CommonName)
	}

	// Add all SANs (already validated by x509 parser, but filter just in case)
	for _, san := range cert.DNSNames {
		if cm.isValidHostname(san) {
			hostnames = append(hostnames, san)
		}
	}

	return hostnames
}

// isValidHostname checks if a string is a valid hostname for SNI matching
func (cm *Manager) isValidHostname(hostname string) bool {
	// Must not be empty
	if hostname == "" {
		return false
	}

	// Must not contain spaces (catches "CloudFlare Origin Certificate" etc.)
	if strings.Contains(hostname, " ") {
		return false
	}

	// Must not be too long (DNS limit)
	if len(hostname) > 253 {
		return false
	}

	// Wildcard certificates are valid
	if strings.HasPrefix(hostname, "*.") {
		hostname = hostname[2:] // Remove wildcard for validation
	}

	// Must contain at least one character
	if len(hostname) == 0 {
		return false
	}

	// Basic validation: must contain valid DNS characters
	// Allow: letters, numbers, dots, hyphens
	for _, ch := range hostname {
		if !((ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '.' || ch == '-') {
			return false
		}
	}

	// Must contain at least one dot (for proper domains) or be localhost
	// This filters out things like single words
	if hostname != "localhost" && !strings.Contains(hostname, ".") {
		return false
	}

	// Must not start or end with dot or hyphen
	if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") ||
		strings.HasPrefix(hostname, "-") || strings.HasSuffix(hostname, "-") {
		return false
	}

	return true
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

	// First, try to find an exact hostname match
	if cert, exists := cm.hostnameCache[hello.ServerName]; exists {
		return cert, nil
	}

	// Then, try to find a wildcard match
	for hostname, cert := range cm.hostnameCache {
		if strings.HasPrefix(hostname, "*.") && cm.matchesWildcard(hostname, hello.ServerName) {
			return cert, nil
		}
	}

	// Finally, try to find any default certificate in cache if we were given a default hostname
	if cm.defaultHostname != "" {
		if cert, exists := cm.hostnameCache[cm.defaultHostname]; exists {
			return cert, nil
		}
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

func (cm *Manager) watchCertificates() {
	if cm.watcher == nil {
		return
	}

	debounce := time.NewTimer(0)
	<-debounce.C // Drain the initial timer
	var pendingReload bool

	for {
		select {
		case event, ok := <-cm.watcher.Events:
			if !ok {
				return
			}

			// Check if event is for a certificate file
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0 {
				fileName := filepath.Base(event.Name)

				// Ignore temporary files and directories
				if strings.HasPrefix(fileName, ".") || strings.HasSuffix(fileName, "~") {
					continue
				}

				log.Printf("[cert_manager] Detected change in certificate file: %s (%v)", fileName, event.Op)

				// Use debouncing to avoid multiple reloads for rapid changes
				if !pendingReload {
					pendingReload = true
					debounce.Reset(100 * time.Millisecond)
				}
			}

		case err, ok := <-cm.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[cert_manager] File watcher error: %v", err)

		case <-debounce.C:
			if pendingReload {
				pendingReload = false
				cm.loadAllCertificates(false)
			}

		case <-cm.stopChan:
			return
		}
	}
}

// Stop gracefully shuts down the certificate manager
func (cm *Manager) Stop() {
	if cm.watcher != nil {
		cm.watcher.Close()
	}
	close(cm.stopChan)
}
