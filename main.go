package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"flowguard/certmanager"
	"flowguard/proxy"
)

var Version string

func main() {
	if Version == "" {
		Version = "dev"
	}

	// Check for setup subcommand first
	if len(os.Args) >= 2 && os.Args[1] == "setup" {
		if len(os.Args) < 3 {
			log.Fatal("Usage: flowguard setup <host-key>")
		}
		hostKey := os.Args[2]

		// Parse remaining flags for setup command
		setupFlag := flag.NewFlagSet("setup", flag.ExitOnError)
		configFile := setupFlag.String("config", "/etc/flowguard/config.json", "Path to the configuration file")

		err := setupFlag.Parse(os.Args[3:])
		if err != nil {
			log.Printf("[ERROR] Failed to parse flags: %v", err)
			os.Exit(1)
		}

		if err := setupHost(hostKey, *configFile); err != nil {
			log.Printf("[ERROR] Failed to setup host: %v", err)
			os.Exit(1)
		}

		log.Printf("[SUCCESS] Host configured successfully. Configuration saved to %s", *configFile)
		os.Exit(0)
	}

	var (
		// Proxy configuration
		bindAddrs  = flag.String("bind", "", "Comma-separated list of IP addresses to bind to (default: auto-detect public IPs)")
		httpPort   = flag.String("http-port", "11080", "Port for HTTP proxy server")
		httpsPort  = flag.String("https-port", "11443", "Port for HTTPS proxy server")
		noRedirect = flag.Bool("no-redirect", false, "Skip iptables port redirection setup")

		// Certificate configuration
		certPath  = flag.String("cert-path", "/opt/psa/var/certificates", "Path to combined certificate files")
		testCerts = flag.Bool("test-certs", false, "Test loading all certificates and exit")

		// Behavior configuration
		verbose    = flag.Bool("verbose", false, "Enable more verbose output")
		cacheDir   = flag.String("cache-dir", "/var/cache/flowguard", "Directory for caching external data")
		configFile = flag.String("config", "/etc/flowguard/config.json", "Path to the configuration file")
	)
	flag.Parse()

	// Load config file first to get defaults
	cfg, err := loadConfigDefaults(*configFile)
	if err != nil {
		log.Printf("Failed to load configuration from %s: %v", *configFile, err)
	}

	// Override config with CLI flags if provided
	if *cacheDir != "/var/cache/flowguard" {
		cfg.CacheDir = *cacheDir
	} else if cfg.CacheDir == "" {
		cfg.CacheDir = *cacheDir
	}

	if *certPath != "/opt/psa/var/certificates" {
		cfg.CertPath = *certPath
	} else if cfg.CertPath == "" {
		cfg.CertPath = *certPath
	}

	// Certificate test mode
	if *testCerts {
		cm := certmanager.New(cfg.CertPath, "")
		cm.TestCertificates()
		os.Exit(0)
	}

	// Apply remaining CLI flags
	cfg.Verbose = *verbose
	cfg.HTTPPort = *httpPort
	cfg.HTTPSPort = *httpsPort
	cfg.BindAddrs = parseBindAddrsList(*bindAddrs)
	cfg.UserAgent = fmt.Sprintf("FlowGuard/%s", Version)
	cfg.NoRedirect = *noRedirect
	cfg.ConfigFile = *configFile

	proxyManager := proxy.NewManager(cfg)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if err := proxyManager.Start(); err != nil {
		// If we fail to start, attempt to shut down any started servers
		if shutdownErr := proxyManager.Shutdown(); shutdownErr != nil {
			log.Printf("Shutdown error: %v", shutdownErr)
		}

		log.Fatalf("[FATAL] Failed to start proxy: %v", err)
	}

	log.Println("HTTP Security Proxy is running...")
	<-sigChan

	if err := proxyManager.Shutdown(); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
}

func parseBindAddrsList(list string) []string {
	if list == "" {
		return nil
	}

	addrs := strings.Split(list, ",")
	for i, addr := range addrs {
		addrs[i] = strings.TrimSpace(addr)
	}

	return addrs
}

// loadConfigDefaults loads configuration defaults from config file
func loadConfigDefaults(configFile string) (*proxy.Config, error) {
	type ConfigDefaults struct {
		CacheDir string `json:"cache_dir,omitempty"`
		CertPath string `json:"cert_path,omitempty"`
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return &proxy.Config{}, err
	}

	var defaults ConfigDefaults
	if err := json.Unmarshal(data, &defaults); err != nil {
		return &proxy.Config{}, err
	}

	return &proxy.Config{
		CacheDir: defaults.CacheDir,
		CertPath: defaults.CertPath,
	}, nil
}

// setupHost downloads the host configuration from the FlowGuard API
func setupHost(hostKey, configFile string) error {
	const apiURL = "https://flowguard.network/api/v1/config"

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create request with authorization header
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+hostKey)
	req.Header.Set("User-Agent", fmt.Sprintf("FlowGuard/%s", Version))

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch configuration: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(configFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write to temporary file first for atomic update
	tmpFile := configFile + ".tmp"
	if err := os.WriteFile(tmpFile, body, 0644); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}

	// Atomically rename to final location
	if err := os.Rename(tmpFile, configFile); err != nil {
		// Clean up temp file if rename fails
		os.Remove(tmpFile)
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	return nil
}
