package certmanager

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Config holds configuration for the certificate manager
type Config struct {
	Verbose         bool
	CertPath        string
	NginxConfigPath string
	DefaultHostname string
}

// certificateWithMetadata wraps a TLS certificate with selection metadata
type certificateWithMetadata struct {
	cert       *tls.Certificate
	keyType    string // "ECDSA" or "RSA"
	filePath   string // For debugging/logging
	notBefore  time.Time
	notAfter   time.Time
	isWildcard bool
	isTrusted  bool
}

// Manager handles SSL/TLS certificate loading and management
type Manager struct {
	config           Config
	hostnameCache    map[string][]*certificateWithMetadata // Maps hostname to array of certificates
	cacheMutex       sync.RWMutex
	watcher          *fsnotify.Watcher
	stopChan         chan struct{}
	nginxConfigFiles []string        // List of NGINX config files to watch
	nginxCertFiles   []string        // List of certificate files referenced in NGINX config
	watchedDirs      map[string]bool // Track which directories we're watching
}

// New creates a new certificate manager
func New(config Config) *Manager {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("[cert_manager] Warning: Failed to create file watcher: %v. Certificate updates will not be automatic.", err)
	}

	cm := &Manager{
		config:           config,
		hostnameCache:    make(map[string][]*certificateWithMetadata),
		watcher:          watcher,
		stopChan:         make(chan struct{}),
		nginxConfigFiles: make([]string, 0),
		nginxCertFiles:   make([]string, 0),
		watchedDirs:      make(map[string]bool),
	}

	cm.loadAllCertificates(false)

	// Setup file watches
	if watcher != nil {
		cm.setupWatches()

		// Start watching if we have any paths to watch
		if len(cm.watchedDirs) > 0 {
			go cm.watchCertificates()
		} else {
			// No paths to watch, close the watcher
			watcher.Close()
			cm.watcher = nil
		}
	}

	return cm
}

// GetTlsConfig returns the tls configuration for use in servers
func (cm *Manager) GetTlsConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: cm.getCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

// GetCertificateForHostname retrieves the best matching certificate for a given hostname
func (cm *Manager) GetCertificateForHostname(hostname string) *tls.Certificate {
	cm.cacheMutex.RLock()
	defer cm.cacheMutex.RUnlock()

	// Gather all matching certificates from both exact and wildcard matches
	var allCandidates []*certificateWithMetadata
	seenPaths := make(map[string]bool)

	// Check for exact hostname match
	if candidates, exists := cm.hostnameCache[hostname]; exists {
		for _, candidate := range candidates {
			if !seenPaths[candidate.filePath] {
				allCandidates = append(allCandidates, candidate)
				seenPaths[candidate.filePath] = true
			}
		}
	}

	// Check for wildcard matches by iterating through all wildcard patterns in cache
	// For example, if hostname is "www.example.com", check if "*.example.com" matches
	for cachedHostname, candidates := range cm.hostnameCache {
		if strings.HasPrefix(cachedHostname, "*.") && cm.matchesWildcard(cachedHostname, hostname) {
			for _, candidate := range candidates {
				if !seenPaths[candidate.filePath] {
					allCandidates = append(allCandidates, candidate)
					seenPaths[candidate.filePath] = true
				}
			}
		}
	}

	// If we have candidates, select the best one
	if len(allCandidates) > 0 {
		return selectBestCertificate(allCandidates)
	}

	// Finally, try to find any default certificate in cache if we were given a default hostname
	if cm.config.DefaultHostname != "" {
		if candidates, exists := cm.hostnameCache[cm.config.DefaultHostname]; exists {
			if cert := selectBestCertificate(candidates); cert != nil {
				return cert
			}
		}
	}

	return nil
}

// ShowCertificatesForHostname displays all certificates for a hostname and which will be served
func (cm *Manager) ShowCertificatesForHostname(hostname string) {
	cm.cacheMutex.RLock()
	defer cm.cacheMutex.RUnlock()

	// Find all matching certificates (exact and wildcard)
	// Use a map to deduplicate by file path
	type candidateWithMatch struct {
		meta      *certificateWithMetadata
		matchType string
	}
	uniqueCandidates := make(map[string]*candidateWithMatch)

	// Check for exact match
	if candidates, exists := cm.hostnameCache[hostname]; exists {
		for _, meta := range candidates {
			if _, exists := uniqueCandidates[meta.filePath]; !exists {
				uniqueCandidates[meta.filePath] = &candidateWithMatch{
					meta:      meta,
					matchType: "exact",
				}
			}
		}
	}

	// Check for wildcard matches - iterate through all cached hostnames
	for cachedHostname, candidates := range cm.hostnameCache {
		if strings.HasPrefix(cachedHostname, "*.") && cm.matchesWildcard(cachedHostname, hostname) {
			for _, meta := range candidates {
				if _, exists := uniqueCandidates[meta.filePath]; !exists {
					uniqueCandidates[meta.filePath] = &candidateWithMatch{
						meta:      meta,
						matchType: "wildcard",
					}
				}
			}
		}
	}

	if len(uniqueCandidates) == 0 {
		fmt.Printf("No certificates found for hostname: %s\n\n", hostname)

		// Check if we would fall back to default hostname
		if cm.config.DefaultHostname != "" {
			defaultCert := cm.GetCertificateForHostname(cm.config.DefaultHostname)
			if defaultCert != nil {
				fmt.Printf("→ Will fall back to default hostname certificate: %s\n", cm.config.DefaultHostname)

				// Show the default certificate info
				if defaultCandidates, exists := cm.hostnameCache[cm.config.DefaultHostname]; exists && len(defaultCandidates) > 0 {
					fmt.Printf("\nDefault Certificate:\n")
					meta := defaultCandidates[0]
					fmt.Printf("  File Path:   %s\n", meta.filePath)
					fmt.Printf("  Key Type:    %s\n", meta.keyType)
					fmt.Printf("  Trusted:     %v\n", meta.isTrusted)
					fmt.Printf("  Valid Until: %s\n", meta.notAfter.Format("2006-01-02 15:04:05"))

					now := time.Now()
					if meta.notAfter.Before(now) {
						daysExpired := int(now.Sub(meta.notAfter).Hours() / 24)
						fmt.Printf("  Status:      ✗ EXPIRED (%d days ago)\n", daysExpired)
					} else {
						daysRemaining := int(meta.notAfter.Sub(now).Hours() / 24)
						fmt.Printf("  Status:      ✓ Valid (%d days remaining)\n", daysRemaining)
					}
				}
			} else {
				fmt.Printf("⚠ WARNING: Default hostname '%s' also has no valid certificate\n", cm.config.DefaultHostname)
			}
		}
		fmt.Println()
		return
	}

	// Convert map to slice for ordered display
	var allCandidates []*certificateWithMetadata
	var matchTypes []string
	for _, candidate := range uniqueCandidates {
		allCandidates = append(allCandidates, candidate.meta)
		matchTypes = append(matchTypes, candidate.matchType)
	}

	// Determine which certificate will be served
	selectedCert := cm.GetCertificateForHostname(hostname)

	fmt.Printf("Certificates for hostname: %s\n\n", hostname)
	fmt.Printf("Found %d certificate(s):\n\n", len(allCandidates))

	for i, meta := range allCandidates {
		isSelected := selectedCert != nil && meta.cert == selectedCert

		if isSelected {
			fmt.Printf("  [%d] ✓ WILL BE SERVED\n", i+1)
		} else {
			fmt.Printf("  [%d]\n", i+1)
		}

		fmt.Printf("      File Path:   %s\n", meta.filePath)
		fmt.Printf("      Match Type:  %s\n", matchTypes[i])
		fmt.Printf("      Key Type:    %s\n", meta.keyType)
		fmt.Printf("      Trusted:     %v\n", meta.isTrusted)
		fmt.Printf("      Wildcard:    %v\n", meta.isWildcard)
		fmt.Printf("      Valid From:  %s\n", meta.notBefore.Format("2006-01-02 15:04:05"))
		fmt.Printf("      Valid Until: %s\n", meta.notAfter.Format("2006-01-02 15:04:05"))

		// Check expiry status
		now := time.Now()
		if meta.notAfter.Before(now) {
			daysExpired := int(now.Sub(meta.notAfter).Hours() / 24)
			fmt.Printf("      Status:      ✗ EXPIRED (%d days ago)\n", daysExpired)
		} else if meta.notAfter.Before(now.Add(30 * 24 * time.Hour)) {
			daysRemaining := int(meta.notAfter.Sub(now).Hours() / 24)
			fmt.Printf("      Status:      ⚠ EXPIRING SOON (%d days remaining)\n", daysRemaining)
		} else {
			daysRemaining := int(meta.notAfter.Sub(now).Hours() / 24)
			fmt.Printf("      Status:      ✓ Valid (%d days remaining)\n", daysRemaining)
		}

		// Show hostnames covered by this cert
		if meta.cert.Leaf != nil {
			hostnames := cm.getCertificateHostnames(meta.cert.Leaf)
			if len(hostnames) > 0 {
				fmt.Printf("      Hostnames:   %v\n", hostnames)
			}
		}

		fmt.Println()
	}

	if selectedCert == nil {
		fmt.Printf("⚠ WARNING: No valid certificate will be served (all may be expired)\n\n")

		// Try default hostname
		if cm.config.DefaultHostname != "" {
			defaultCert := cm.GetCertificateForHostname(cm.config.DefaultHostname)
			if defaultCert != nil {
				fmt.Printf("→ Will fall back to default hostname certificate: %s\n\n", cm.config.DefaultHostname)
			}
		}
	} else {
		fmt.Printf("Selection Priority:\n")
		fmt.Printf("  1. Non-expired certificates\n")
		fmt.Printf("  2. Trusted (CA-signed) over self-signed\n")
		fmt.Printf("  3. Wildcard over exact match\n")
		fmt.Printf("  4. ECDSA over RSA\n")
		fmt.Printf("  5. Longer validity period\n")
		fmt.Println()
	}
}

// TestCertificates validates all certificates and displays their status
func (cm *Manager) TestCertificates() {
	successCount := 0
	failCount := 0

	// Test certificates from directory if provided
	if cm.config.CertPath != "" {
		files, err := os.ReadDir(cm.config.CertPath)
		if err != nil {
			log.Printf("Warning: Error reading certificate directory %s: %v", cm.config.CertPath, err)
		} else {
			log.Printf("Testing certificates in directory %s...\n", cm.config.CertPath)

			for _, file := range files {
				if file.IsDir() {
					continue
				}

				certFile := filepath.Join(cm.config.CertPath, file.Name())
				pemData, err := os.ReadFile(certFile)
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
	if cm.config.NginxConfigPath != "" {
		pairs, _, err := parseNginxConfig(cm.config.NginxConfigPath, cm.config.Verbose)
		if err != nil {
			log.Printf("Warning: Error parsing NGINX config %s: %v", cm.config.NginxConfigPath, err)
		} else {
			log.Printf("\nTesting certificates from NGINX config %s...\n", cm.config.NginxConfigPath)

			for _, pair := range pairs {
				// Read cert and key files
				certPEM, err := os.ReadFile(pair.CertPath)
				if err != nil {
					log.Printf("✗ %s: Failed to read certificate: %v", pair.CertPath, err)
					failCount++
					continue
				}

				keyPEM, err := os.ReadFile(pair.KeyPath)
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

// Stop gracefully shuts down the certificate manager
func (cm *Manager) Stop() {
	if cm.watcher != nil {
		cm.watcher.Close()
	}
	close(cm.stopChan)
}

// setupWatches configures file system watches for certificate and config directories
func (cm *Manager) setupWatches() {
	if cm.watcher == nil {
		return
	}

	// Watch certificate directory if provided
	if cm.config.CertPath != "" {
		if !cm.watchedDirs[cm.config.CertPath] {
			err := cm.watcher.Add(cm.config.CertPath)
			if err != nil {
				log.Printf("[cert_manager] Warning: Failed to watch certificate directory %s: %v", cm.config.CertPath, err)
			} else {
				cm.watchedDirs[cm.config.CertPath] = true
				if cm.config.Verbose {
					log.Printf("[cert_manager] Watching certificate directory %s for changes", cm.config.CertPath)
				}
			}
		}
	}

	// Watch NGINX config file directories
	for _, configFile := range cm.nginxConfigFiles {
		configDir := filepath.Dir(configFile)
		if !cm.watchedDirs[configDir] {
			err := cm.watcher.Add(configDir)
			if err != nil {
				log.Printf("[cert_manager] Warning: Failed to watch NGINX config directory %s: %v", configDir, err)
			} else {
				cm.watchedDirs[configDir] = true
				if cm.config.Verbose {
					log.Printf("[cert_manager] Watching NGINX config directory %s for changes", configDir)
				}
			}
		}
	}

	// Watch directories containing certificate files referenced in NGINX config
	for _, certFile := range cm.nginxCertFiles {
		certDir := filepath.Dir(certFile)
		if !cm.watchedDirs[certDir] {
			err := cm.watcher.Add(certDir)
			if err != nil {
				log.Printf("[cert_manager] Warning: Failed to watch certificate directory %s: %v", certDir, err)
			} else {
				cm.watchedDirs[certDir] = true
				if cm.config.Verbose {
					log.Printf("[cert_manager] Watching certificate directory %s for changes", certDir)
				}
			}
		}
	}
}

// extractCertificateMetadata creates a metadata wrapper for a certificate
func (cm *Manager) extractCertificateMetadata(cert *tls.Certificate, filePath string, hostnames []string) *certificateWithMetadata {
	if cert.Leaf == nil {
		return nil
	}

	// Check if this is a wildcard certificate
	isWildcard := false
	for _, hostname := range hostnames {
		if strings.HasPrefix(hostname, "*.") {
			isWildcard = true
			break
		}
	}

	return &certificateWithMetadata{
		cert:       cert,
		keyType:    getKeyType(cert),
		filePath:   filePath,
		notBefore:  cert.Leaf.NotBefore,
		notAfter:   cert.Leaf.NotAfter,
		isTrusted:  isTrustedCertificate(cert.Leaf),
		isWildcard: isWildcard,
	}
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
	// Load into temporary map
	tempHostnameCache := make(map[string][]*certificateWithMetadata)

	successCount := 0
	fromDir := 0
	fromNginx := 0

	// Load from certificate directory if provided
	if cm.config.CertPath != "" {
		files, err := os.ReadDir(cm.config.CertPath)
		if err != nil {
			log.Printf("[cert_manager] Error reading certificate directory %s: %v", cm.config.CertPath, err)
		} else {
			for _, file := range files {
				if file.IsDir() {
					continue
				}

				certFile := filepath.Join(cm.config.CertPath, file.Name())
				pemData, err := os.ReadFile(certFile)
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

				// Map the certificate to all its valid hostnames
				if cert.Leaf != nil {
					hostnames := cm.getCertificateHostnames(cert.Leaf)
					if len(hostnames) > 0 {
						metadata := cm.extractCertificateMetadata(cert, certFile, hostnames)
						if metadata != nil {
							for _, name := range hostnames {
								tempHostnameCache[name] = append(tempHostnameCache[name], metadata)
							}
							successCount++
							fromDir++
						}
					}
				}
			}
		}
	}

	// Load from NGINX config if provided
	if cm.config.NginxConfigPath != "" {
		pairs, configFiles, err := parseNginxConfig(cm.config.NginxConfigPath, verbose)
		if err != nil {
			log.Printf("[cert_manager] Error parsing NGINX config %s: %v", cm.config.NginxConfigPath, err)
		} else {
			// Store the list of config files for watching
			cm.nginxConfigFiles = configFiles

			// Collect all certificate file paths for watching
			var certFiles []string
			for _, pair := range pairs {
				certFiles = append(certFiles, pair.CertPath)
				if pair.KeyPath != pair.CertPath {
					certFiles = append(certFiles, pair.KeyPath)
				}
			}
			cm.nginxCertFiles = certFiles

			for _, pair := range pairs {
				// Read cert and key files separately
				certPEM, err := os.ReadFile(pair.CertPath)
				if err != nil {
					if verbose {
						log.Printf("[cert_manager] Failed to read certificate file %s: %v", pair.CertPath, err)
					}
					continue
				}

				keyPEM, err := os.ReadFile(pair.KeyPath)
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

				// Map the certificate to all its valid hostnames
				if cert.Leaf != nil {
					hostnames := cm.getCertificateHostnames(cert.Leaf)
					if len(hostnames) > 0 {
						metadata := cm.extractCertificateMetadata(cert, pair.CertPath, hostnames)
						if metadata != nil {
							for _, name := range hostnames {
								tempHostnameCache[name] = append(tempHostnameCache[name], metadata)
							}
							successCount++
							fromNginx++
						}
					}
				}
			}
		}
	}

	// Atomically swap the cache
	cm.cacheMutex.Lock()
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

func (cm *Manager) getCertificateHostnames(cert *x509.Certificate) []string {
	// Use a map to deduplicate hostnames
	hostnameMap := make(map[string]bool)

	// Add CN if present and valid
	if cert.Subject.CommonName != "" && cm.isValidHostname(cert.Subject.CommonName) {
		hostnameMap[cert.Subject.CommonName] = true
	}

	// Add all SANs (already validated by x509 parser, but filter just in case)
	for _, san := range cert.DNSNames {
		if cm.isValidHostname(san) {
			hostnameMap[san] = true
		}
	}

	// Convert map to slice
	var hostnames []string
	for hostname := range hostnameMap {
		hostnames = append(hostnames, hostname)
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
	certificate := cm.GetCertificateForHostname(hello.ServerName)
	if certificate != nil {
		return certificate, nil
	}

	return nil, fmt.Errorf("no certificate found for %s", hello.ServerName)
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
				// Update watches in case new certificate files were added
				cm.setupWatches()
			}

		case <-cm.stopChan:
			return
		}
	}
}

// getKeyType returns the public key type (ECDSA or RSA)
func getKeyType(cert *tls.Certificate) string {
	if cert.Leaf == nil {
		return "UNKNOWN"
	}

	switch cert.Leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA"
	case *rsa.PublicKey:
		return "RSA"
	default:
		return "OTHER"
	}
}

// isTrustedCertificate checks if a certificate is trusted (publicly CA-signed, not self-signed or origin cert)
func isTrustedCertificate(cert *x509.Certificate) bool {
	// First check if it's self-signed
	if cert.Issuer.String() == cert.Subject.String() {
		return false // Self-signed, not trusted
	}

	// Check for known origin/private CA patterns that shouldn't be preferred
	issuer := cert.Issuer.String()
	subject := cert.Subject.String()

	// Cloudflare Origin Certificates
	if strings.Contains(issuer, "CloudFlare Origin") || strings.Contains(issuer, "Cloudflare Origin") {
		return false
	}
	if strings.Contains(subject, "CloudFlare Origin") || strings.Contains(subject, "Cloudflare Origin") {
		return false
	}

	// Other common origin certificate patterns
	if strings.Contains(issuer, "Origin Certificate") || strings.Contains(issuer, "Origin CA") {
		return false
	}

	// Very long validity periods (>5 years) are typically origin certs or self-signed
	// Let's Encrypt and other public CAs issue certs with max 90-397 days
	validityDays := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24
	if validityDays > 365*5 {
		return false
	}

	// If it passes all checks, consider it trusted (CA-signed by a public CA)
	return true
}

// selectBestCertificate selects the best certificate from candidates based on priority
// Order: non-expired > CA-signed > wildcard > ECDSA > longer validity
func selectBestCertificate(candidates []*certificateWithMetadata) *tls.Certificate {
	if len(candidates) == 0 {
		return nil
	}

	// Filter out expired certificates
	now := time.Now()
	var valid []*certificateWithMetadata
	for _, candidate := range candidates {
		if candidate.notAfter.After(now) {
			valid = append(valid, candidate)
		}
	}

	// If all certificates are expired, return nil
	if len(valid) == 0 {
		return nil
	}

	// If only one valid certificate, return it immediately
	if len(valid) == 1 {
		return valid[0].cert
	}

	// Sort by priority (highest priority first)
	sort.Slice(valid, func(i, j int) bool {
		a, b := valid[i], valid[j]

		// 1. Prefer trusted (CA-signed) over self-signed
		if a.isTrusted != b.isTrusted {
			return a.isTrusted // true (trusted) comes before false (self-signed)
		}

		// 2. Prefer wildcard over exact match
		if a.isWildcard != b.isWildcard {
			return a.isWildcard // true (wildcard) comes before false (exact)
		}

		// 3. Prefer ECDSA over RSA
		if a.keyType != b.keyType {
			if a.keyType == "ECDSA" {
				return true
			}
			if b.keyType == "ECDSA" {
				return false
			}
		}

		// 4. Prefer longer validity period (later expiration)
		return a.notAfter.After(b.notAfter)
	})

	return valid[0].cert
}
