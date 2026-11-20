package certmanager

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
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
	ACMEPath        string
	TLSNextProtos   []string
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
	config            Config
	watcher           *fsnotify.Watcher
	stopChan          chan struct{}
	cacheMutex        sync.RWMutex
	watchedDirs       map[string]bool                       // Track which directories we're watching
	hostnameCache     map[string][]*certificateWithMetadata // Maps hostname to array of certificates
	acmeCertificates  []*certificateWithMetadata            // Last successfully parsed Traefik ACME certificates
	nginxCertFiles    []string                              // List of certificate files referenced in NGINX config
	nginxConfigFiles  []string                              // List of NGINX config files to watch
	nginxConfigLoaded bool                                  // True when the configured NGINX config was read successfully

	// parsedCertificates holds the certificates parsed by the last load, by
	// the SHA-256 of their PEM data, so a reload parses only changed files.
	parsedCertificates map[[sha256.Size]byte]*tls.Certificate
}

// New creates a new certificate manager
func New(config Config) *Manager {
	config.DefaultHostname = normalizeHostname(config.DefaultHostname)

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

// HostnameCount returns the number of hostnames with loaded certificates
func (cm *Manager) HostnameCount() int {
	cm.cacheMutex.RLock()
	defer cm.cacheMutex.RUnlock()
	return len(cm.hostnameCache)
}

// NginxConfigLoaded reports whether the configured NGINX config was read successfully.
func (cm *Manager) NginxConfigLoaded() bool {
	cm.cacheMutex.RLock()
	defer cm.cacheMutex.RUnlock()
	return cm.nginxConfigLoaded
}

// GetTlsConfig returns the tls configuration for use in servers
func (cm *Manager) GetTlsConfig() *tls.Config {
	config := &tls.Config{
		GetCertificate: cm.getCertificate,
		MinVersion:     tls.VersionTLS12,
		// NCSC TLS Security Guidelines 2025-05 classify CBC as phase out and
		// SHA-1 as insufficient. TLS 1.3 cipher suites remain managed by Go.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		NextProtos: cm.nextProtos(),
	}
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		return cm.configForClient(config, hello)
	}
	return config
}

func (cm *Manager) nextProtos() []string {
	if cm.config.TLSNextProtos != nil {
		return slices.Clone(cm.config.TLSNextProtos)
	}

	return []string{"h2", "http/1.1"}
}

// GetCertificateForHostname retrieves the best matching certificate for a given hostname
func (cm *Manager) GetCertificateForHostname(hostname string) *tls.Certificate {
	hostname = normalizeHostname(hostname)

	cm.cacheMutex.RLock()
	defer cm.cacheMutex.RUnlock()

	if cert := cm.matchingCertificateLocked(hostname); cert != nil {
		return cert
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

// hasCertificateForHostname reports whether a valid certificate names
// hostname, exactly or by wildcard, not counting the default certificate.
func (cm *Manager) hasCertificateForHostname(hostname string) bool {
	hostname = normalizeHostname(hostname)

	cm.cacheMutex.RLock()
	defer cm.cacheMutex.RUnlock()
	return cm.matchingCertificateLocked(hostname) != nil
}

// matchingCertificateLocked returns the best valid certificate that names
// hostname exactly or by wildcard. The caller holds cacheMutex.
func (cm *Manager) matchingCertificateLocked(hostname string) *tls.Certificate {
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

	// Check for a wildcard match, such as "*.example.com" for "www.example.com"
	if pattern, ok := wildcardHostname(hostname); ok {
		for _, candidate := range cm.hostnameCache[pattern] {
			if !seenPaths[candidate.filePath] {
				allCandidates = append(allCandidates, candidate)
				seenPaths[candidate.filePath] = true
			}
		}
	}

	// Select the best valid candidate; nil when every one has expired
	return selectBestCertificate(allCandidates)
}

// ShowCertificatesForHostname displays all certificates for a hostname and which will be served
func (cm *Manager) ShowCertificatesForHostname(hostname string) {
	hostname = normalizeHostname(hostname)

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

	// Check for a wildcard match
	if pattern, ok := wildcardHostname(hostname); ok {
		for _, meta := range cm.hostnameCache[pattern] {
			if _, exists := uniqueCandidates[meta.filePath]; !exists {
				uniqueCandidates[meta.filePath] = &candidateWithMatch{
					meta:      meta,
					matchType: "wildcard",
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

	// Test certificates from a DirectAdmin installation, a certbot config
	// directory or a certificate directory if provided
	if cm.config.CertPath != "" && IsDirectAdminRoot(cm.config.CertPath) {
		log.Printf("Testing certificates from DirectAdmin installation %s...\n", cm.config.CertPath)

		success, fail := cm.testCertificatePairs(directAdminCertificates(cm.config.CertPath))
		successCount += success
		failCount += fail
	} else if cm.config.CertPath != "" && IsCertbotRoot(cm.config.CertPath) {
		log.Printf("Testing certificates from certbot config directory %s...\n", cm.config.CertPath)

		success, fail := cm.testCertificatePairs(certbotCertificates(cm.config.CertPath))
		successCount += success
		failCount += fail
	} else if cm.config.CertPath != "" {
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

	// Test certificates from Traefik ACME storage if provided.
	if cm.config.ACMEPath != "" {
		log.Printf("\nTesting certificates from Traefik ACME storage %s...\n", cm.config.ACMEPath)

		data, err := os.ReadFile(cm.config.ACMEPath)
		if err != nil {
			log.Printf("✗ %s: Failed to read ACME storage: %v", cm.config.ACMEPath, err)
			failCount++
		} else {
			entries, err := parseTraefikACME(data)
			if err != nil {
				log.Printf("✗ %s: Failed to parse ACME storage: %v", cm.config.ACMEPath, err)
				failCount++
			} else {
				for _, entry := range entries {
					sourceID := traefikACMESourceID(cm.config.ACMEPath, entry)
					if entry.DecodeError != nil {
						log.Printf("✗ %s: Failed to decode: %v", sourceID, entry.DecodeError)
						failCount++
						continue
					}
					cert, err := parseACMECertificateBundle(entry.Certificate, entry.Key)
					if err != nil {
						log.Printf("✗ %s: Failed to parse: %v", sourceID, err)
						failCount++
						continue
					}

					hostnames := cm.getCertificateHostnames(cert.Leaf)
					notAfter := cert.Leaf.NotAfter.Format("2006-01-02")
					switch {
					case time.Now().After(cert.Leaf.NotAfter):
						log.Printf("✗ %s: EXPIRED (expired %s) - Hosts: %v", sourceID, notAfter, hostnames)
						failCount++
					case len(hostnames) == 0:
						log.Printf("✗ %s: No valid hostnames", sourceID)
						failCount++
					case time.Now().Add(30 * 24 * time.Hour).After(cert.Leaf.NotAfter):
						log.Printf("⚠ %s: EXPIRING SOON (expires %s) - Hosts: %v", sourceID, notAfter, hostnames)
						successCount++
					default:
						log.Printf("✓ %s: Valid until %s - Hosts: %v", sourceID, notAfter, hostnames)
						successCount++
					}
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

			success, fail := cm.testCertificatePairs(pairs)
			successCount += success
			failCount += fail
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

// testCertificatePairs logs the status of each certificate pair and returns
// the number of usable and failed pairs.
func (cm *Manager) testCertificatePairs(pairs []Certificate) (successCount, failCount int) {
	for _, pair := range pairs {
		combinedPEM, err := readCertificatePair(pair)
		if err != nil {
			log.Printf("✗ %s: Failed to read: %v", pair.CertPath, err)
			failCount++
			continue
		}

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

	return successCount, failCount
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

	// Watch the parent directory so both in-place writes and file replacement
	// used by certificate renewal are detected.
	if cm.config.ACMEPath != "" {
		acmeDir := filepath.Dir(cm.config.ACMEPath)
		if !cm.watchedDirs[acmeDir] {
			err := cm.watcher.Add(acmeDir)
			if err != nil {
				log.Printf("[cert_manager] Warning: Failed to watch Traefik ACME directory %s: %v", acmeDir, err)
			} else {
				cm.watchedDirs[acmeDir] = true
				if cm.config.Verbose {
					log.Printf("[cert_manager] Watching Traefik ACME directory %s for changes", acmeDir)
				}
			}
		}
	}

	// Watch a DirectAdmin installation's or certbot config directory's
	// certificate directories, or the certificate directory, if provided
	if cm.config.CertPath != "" && IsDirectAdminRoot(cm.config.CertPath) {
		for _, dir := range directAdminWatchDirs(cm.config.CertPath) {
			if cm.watchedDirs[dir] {
				continue
			}
			err := cm.watcher.Add(dir)
			if err != nil {
				log.Printf("[cert_manager] Warning: Failed to watch DirectAdmin directory %s: %v", dir, err)
			} else {
				cm.watchedDirs[dir] = true
				if cm.config.Verbose {
					log.Printf("[cert_manager] Watching DirectAdmin directory %s for changes", dir)
				}
			}
		}
	} else if cm.config.CertPath != "" && IsCertbotRoot(cm.config.CertPath) {
		for _, dir := range certbotWatchDirs(cm.config.CertPath) {
			if cm.watchedDirs[dir] {
				continue
			}
			err := cm.watcher.Add(dir)
			if err != nil {
				log.Printf("[cert_manager] Warning: Failed to watch certbot directory %s: %v", dir, err)
			} else {
				cm.watchedDirs[dir] = true
				if cm.config.Verbose {
					log.Printf("[cert_manager] Watching certbot directory %s for changes", dir)
				}
			}
		}
	} else if cm.config.CertPath != "" {
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
	parser := certificateParser{
		manager:  cm,
		previous: cm.parsedCertificates,
		current:  make(map[[sha256.Size]byte]*tls.Certificate),
	}

	successCount := 0
	fromDir := 0
	fromACME := 0
	fromNginx := 0
	fromDirectAdmin := 0
	fromCertbot := 0
	nginxConfigLoaded := false

	// Load from a DirectAdmin installation, a certbot config directory or a
	// certificate directory if provided
	if cm.config.CertPath != "" && IsDirectAdminRoot(cm.config.CertPath) {
		for _, pair := range directAdminCertificates(cm.config.CertPath) {
			metadata, hostnames := cm.loadCertificatePair(&parser, pair, verbose)
			if metadata == nil {
				continue
			}
			for _, name := range hostnames {
				tempHostnameCache[name] = append(tempHostnameCache[name], metadata)
			}
			successCount++
			fromDirectAdmin++
		}
	} else if cm.config.CertPath != "" && IsCertbotRoot(cm.config.CertPath) {
		for _, pair := range certbotCertificates(cm.config.CertPath) {
			metadata, hostnames := cm.loadCertificatePair(&parser, pair, verbose)
			if metadata == nil {
				continue
			}
			for _, name := range hostnames {
				tempHostnameCache[name] = append(tempHostnameCache[name], metadata)
			}
			successCount++
			fromCertbot++
		}
	} else if cm.config.CertPath != "" {
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

				cert, err := parser.parse(pemData)
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

	// Load certificates embedded in a Traefik v2/v3 acme.json file. A
	// transient file read or JSON error retains the last known-good entries.
	var acmeCertificates []*certificateWithMetadata
	if cm.config.ACMEPath != "" {
		loaded, err := cm.loadTraefikACMECertificatesWithRetry(cm.config.ACMEPath, verbose)
		if err != nil {
			log.Printf("[cert_manager] Error reading Traefik ACME storage %s: %v; retaining last known-good certificates", cm.config.ACMEPath, err)
			cm.cacheMutex.RLock()
			acmeCertificates = slices.Clone(cm.acmeCertificates)
			cm.cacheMutex.RUnlock()
		} else {
			acmeCertificates = loaded
		}

		for _, metadata := range acmeCertificates {
			if metadata == nil || metadata.cert == nil || metadata.cert.Leaf == nil {
				continue
			}
			for _, name := range cm.getCertificateHostnames(metadata.cert.Leaf) {
				tempHostnameCache[name] = append(tempHostnameCache[name], metadata)
			}
			successCount++
			fromACME++
		}
	}

	// Load from NGINX config if provided
	if cm.config.NginxConfigPath != "" {
		pairs, configFiles, err := parseNginxConfig(cm.config.NginxConfigPath, verbose)
		if err != nil {
			log.Printf("[cert_manager] Error parsing NGINX config %s: %v", cm.config.NginxConfigPath, err)
		} else {
			nginxConfigLoaded = true

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
				metadata, hostnames := cm.loadCertificatePair(&parser, pair, verbose)
				if metadata == nil {
					continue
				}
				for _, name := range hostnames {
					tempHostnameCache[name] = append(tempHostnameCache[name], metadata)
				}
				successCount++
				fromNginx++
			}
		}
	}

	// Atomically swap the cache
	cm.cacheMutex.Lock()
	cm.hostnameCache = tempHostnameCache
	cm.acmeCertificates = acmeCertificates
	cm.nginxConfigLoaded = nginxConfigLoaded
	cm.cacheMutex.Unlock()
	cm.parsedCertificates = parser.current

	// Build status message
	var sources []string
	if fromDir > 0 {
		sources = append(sources, fmt.Sprintf("%d from directory", fromDir))
	}
	if fromDirectAdmin > 0 {
		sources = append(sources, fmt.Sprintf("%d from DirectAdmin", fromDirectAdmin))
	}
	if fromCertbot > 0 {
		sources = append(sources, fmt.Sprintf("%d from certbot", fromCertbot))
	}
	if fromACME > 0 {
		sources = append(sources, fmt.Sprintf("%d from Traefik ACME storage", fromACME))
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

// loadCertificatePair reads and parses a certificate pair. It returns nil when
// the pair cannot be read or parsed, is expired, or names no valid hostname.
func (cm *Manager) loadCertificatePair(parser *certificateParser, pair Certificate, verbose bool) (*certificateWithMetadata, []string) {
	combinedPEM, err := readCertificatePair(pair)
	if err != nil {
		if verbose {
			log.Printf("[cert_manager] Failed to read certificate pair %s + %s: %v", pair.CertPath, pair.KeyPath, err)
		}
		return nil, nil
	}

	cert, err := parser.parse(combinedPEM)
	if err != nil {
		if verbose {
			log.Printf("[cert_manager] Failed to parse certificate pair %s + %s: %v", pair.CertPath, pair.KeyPath, err)
		}
		return nil, nil
	}
	if cert.Leaf == nil {
		return nil, nil
	}

	if time.Now().After(cert.Leaf.NotAfter) {
		if verbose {
			log.Printf("[cert_manager] Skipping expired certificate %s (expired %s)", pair.CertPath, cert.Leaf.NotAfter.Format("2006-01-02"))
		}
		return nil, nil
	}

	hostnames := cm.getCertificateHostnames(cert.Leaf)
	if len(hostnames) == 0 {
		return nil, nil
	}

	return cm.extractCertificateMetadata(cert, pair.CertPath, hostnames), hostnames
}

// certificateParser parses certificates for one load, reusing the result of
// the previous load for PEM data that did not change.
type certificateParser struct {
	manager  *Manager
	previous map[[sha256.Size]byte]*tls.Certificate
	current  map[[sha256.Size]byte]*tls.Certificate
}

func (p *certificateParser) parse(pemData []byte) (*tls.Certificate, error) {
	key := sha256.Sum256(pemData)
	if cert, ok := p.current[key]; ok {
		return cert, nil
	}
	cert, ok := p.previous[key]
	if !ok {
		var err error
		if cert, err = p.manager.parseCombinedPEM(pemData); err != nil {
			return nil, err
		}
	}
	p.current[key] = cert
	return cert, nil
}

func (cm *Manager) getCertificateHostnames(cert *x509.Certificate) []string {
	// Use a map to deduplicate hostnames
	hostnameMap := make(map[string]bool)

	// Add CN if present and valid
	if cert.Subject.CommonName != "" && cm.isValidHostname(cert.Subject.CommonName) {
		hostnameMap[normalizeHostname(cert.Subject.CommonName)] = true
	}

	// Add all SANs (already validated by x509 parser, but filter just in case)
	for _, san := range cert.DNSNames {
		if cm.isValidHostname(san) {
			hostnameMap[normalizeHostname(san)] = true
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

// normalizeHostname lowercases a hostname and strips a trailing dot, since
// DNS names (and so SNI values and certificate names) are case-insensitive.
func normalizeHostname(hostname string) string {
	return strings.ToLower(strings.TrimSuffix(hostname, "."))
}

// wildcardHostname returns the only wildcard name that can cover hostname,
// such as "*.example.com" for "www.example.com". A wildcard covers exactly one
// label, so hostnames without a dot have none.
func wildcardHostname(hostname string) (string, bool) {
	_, parent, found := strings.Cut(hostname, ".")
	if !found {
		return "", false
	}

	return "*." + parent, true
}

func (cm *Manager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certificate := cm.GetCertificateForHostname(hello.ServerName)
	if certificate != nil {
		return certificate, nil
	}

	return nil, fmt.Errorf("no certificate found for %s", hello.ServerName)
}

// configForClient runs before session resumption, which skips
// GetCertificate, so a client cannot resume a session for a hostname whose
// certificate has since been removed. Without any certificate to serve, the
// handshake fails. A hostname served the default certificate gets a full
// handshake with it instead of resuming a session made with its own.
func (cm *Manager) configForClient(config *tls.Config, hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if hello.ServerName != "" && cm.hasCertificateForHostname(hello.ServerName) {
		return nil, nil
	}
	if cm.GetCertificateForHostname(hello.ServerName) == nil {
		return nil, fmt.Errorf("no certificate found for %s", hello.ServerName)
	}
	if hello.ServerName == "" {
		return nil, nil
	}

	withoutResumption := config.Clone()
	withoutResumption.GetConfigForClient = nil
	withoutResumption.SessionTicketsDisabled = true
	return withoutResumption, nil
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

				// A removed directory loses its watch, so forget it to watch
				// it again if it is recreated, such as a certbot lineage
				if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 && cm.watchedDirs[event.Name] {
					delete(cm.watchedDirs, event.Name)
				}

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
