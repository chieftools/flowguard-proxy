package certmanager

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Certificate represents a certificate and key file pair from NGINX config
type Certificate struct {
	CertPath string
	KeyPath  string
}

// parser parses NGINX configuration files to extract SSL certificate information
type parser struct {
	verbose          bool
	visitedFiles     map[string]bool         // Track files we've already parsed
	certKeyPairs     map[string]*Certificate // Map cert path to pair (to match with key)
	lastUnpairedCert string                  // Track the last cert without a key for sequential matching
	nginxBaseDir     string                  // Base directory of main nginx.conf for resolving relative paths
}

// Regular expressions for parsing NGINX config
var (
	sslCertRegex = regexp.MustCompile(`^\s*ssl_certificate\s+(.+?);`)
	sslKeyRegex  = regexp.MustCompile(`^\s*ssl_certificate_key\s+(.+?);`)
	includeRegex = regexp.MustCompile(`^\s*include\s+(.+?);`)
	commentRegex = regexp.MustCompile(`#.*$`)
)

// parseNginxConfig parses an NGINX config file and returns all certificate/key pairs
func parseNginxConfig(configPath string, verbose bool) ([]Certificate, []string, error) {
	// Get absolute path for main config
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, nil, err
	}

	parser := &parser{
		verbose:      verbose,
		visitedFiles: make(map[string]bool),
		certKeyPairs: make(map[string]*Certificate),
		nginxBaseDir: filepath.Dir(absConfigPath), // Store base directory for relative path resolution
	}

	// Parse the main config and all included files
	allConfigFiles := []string{absConfigPath}
	if err := parser.parseFile(configPath); err != nil {
		return nil, nil, err
	}

	// Collect all visited files for watching
	for file := range parser.visitedFiles {
		if file != configPath {
			allConfigFiles = append(allConfigFiles, file)
		}
	}

	// Convert map to slice
	var pairs []Certificate
	for _, pair := range parser.certKeyPairs {
		// Only include pairs that have both cert and key
		if pair.CertPath != "" && pair.KeyPath != "" {
			pairs = append(pairs, *pair)
		}
	}

	return pairs, allConfigFiles, nil
}

// parseFile recursively parses a config file and any included files
func (p *parser) parseFile(path string) error {
	// Resolve to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	// Skip if already visited
	if p.visitedFiles[absPath] {
		return nil
	}
	p.visitedFiles[absPath] = true

	// Open file
	file, err := os.Open(absPath)
	if err != nil {
		if p.verbose {
			log.Printf("[nginx_parser] Warning: Failed to open %s: %v", absPath, err)
		}
		return nil // Don't fail on missing includes
	}
	defer file.Close()

	// Scan line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Remove comments
		line = commentRegex.ReplaceAllString(line, "")
		line = strings.TrimSpace(line)

		// Skip empty lines
		if line == "" {
			continue
		}

		// Check for ssl_certificate directive
		if matches := sslCertRegex.FindStringSubmatch(line); len(matches) > 1 {
			certPath := p.cleanPath(matches[1])
			certPath = p.resolvePath(certPath)

			// Create new pair for this cert
			pair := &Certificate{CertPath: certPath}
			p.certKeyPairs[certPath] = pair
			p.lastUnpairedCert = certPath

			if p.verbose {
				log.Printf("[nginx_parser] Found ssl_certificate: %s", certPath)
			}
		}

		// Check for ssl_certificate_key directive
		if matches := sslKeyRegex.FindStringSubmatch(line); len(matches) > 1 {
			keyPath := p.cleanPath(matches[1])
			keyPath = p.resolvePath(keyPath)

			// Match with the most recent unpaired cert (sequential matching)
			// In NGINX config, ssl_certificate_key typically comes right after ssl_certificate
			if p.lastUnpairedCert != "" {
				if pair, exists := p.certKeyPairs[p.lastUnpairedCert]; exists && pair.KeyPath == "" {
					pair.KeyPath = keyPath
					p.lastUnpairedCert = "" // Mark as paired
				}
			} else {
				// Try to match with any existing cert without a key
				matched := false
				for _, pair := range p.certKeyPairs {
					if pair.KeyPath == "" {
						pair.KeyPath = keyPath
						matched = true
						break
					}
				}

				// If no match, log a warning
				if !matched && p.verbose {
					log.Printf("[nginx_parser] Warning: Found ssl_certificate_key without matching ssl_certificate: %s", keyPath)
				}
			}

			if p.verbose {
				log.Printf("[nginx_parser] Found ssl_certificate_key: %s", keyPath)
			}
		}

		// Check for include directive
		if matches := includeRegex.FindStringSubmatch(line); len(matches) > 1 {
			includePath := p.cleanPath(matches[1])
			includePath = p.resolvePath(includePath)

			// Handle glob patterns
			if strings.ContainsAny(includePath, "*?[]") {
				matches, err := filepath.Glob(includePath)
				if err != nil {
					if p.verbose {
						log.Printf("[nginx_parser] Warning: Failed to expand glob %s: %v", includePath, err)
					}
					continue
				}
				for _, match := range matches {
					if err := p.parseFile(match); err != nil {
						if p.verbose {
							log.Printf("[nginx_parser] Warning: Failed to parse included file %s: %v", match, err)
						}
					}
				}
			} else {
				if err := p.parseFile(includePath); err != nil {
					if p.verbose {
						log.Printf("[nginx_parser] Warning: Failed to parse included file %s: %v", includePath, err)
					}
				}
			}
		}
	}

	return scanner.Err()
}

// cleanPath removes quotes and extra whitespace from a path
func (p *parser) cleanPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, `"'`)
	return path
}

// resolvePath converts a potentially relative path to absolute based on nginx base directory
func (p *parser) resolvePath(path string) string {
	// If already absolute, return as-is
	if filepath.IsAbs(path) {
		return path
	}

	// Resolve relative paths relative to the main nginx.conf directory
	// This matches NGINX behavior where relative paths in include directives
	// are resolved relative to the nginx prefix directory (not the current file)
	return filepath.Join(p.nginxBaseDir, path)
}
