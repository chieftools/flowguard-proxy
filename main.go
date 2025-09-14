package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"flowguard/certmanager"
	"flowguard/proxy"
)

var Version string

func main() {
	if Version == "" {
		Version = "dev"
	}

	var (
		// Proxy configuration
		bindAddrs       = flag.String("bind", "", "Comma-separated list of IP addresses to bind to (default: auto-detect public IPs)")
		httpPort        = flag.String("http-port", "11080", "Port for HTTP proxy server")
		httpsPort       = flag.String("https-port", "11443", "Port for HTTPS proxy server")
		noRedirect      = flag.Bool("no-redirect", false, "Skip iptables port redirection setup")
		defaultHostname = flag.String("default-hostname", "", "The default hostname to use when a certificate is not found")

		// Certificate configuration
		certPath  = flag.String("cert-path", "/opt/psa/var/certificates", "Path to combined certificate files")
		testCerts = flag.Bool("test-certs", false, "Test loading all certificates and exit")

		// Behavior configuration
		verbose    = flag.Bool("verbose", false, "Enable more verbose output")
		cacheDir   = flag.String("cache-dir", "/var/cache/flowguard", "Directory for caching external data")
		configFile = flag.String("config", "config.json", "Path to the configuration file")
	)
	flag.Parse()

	// Load config file first to get defaults
	cfg, err := loadConfigDefaults(*configFile)
	if err != nil {
		log.Printf("Failed to load configuration from %s: %v", *configFile, err)
		os.Exit(1)
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

	if *defaultHostname != "" {
		cfg.DefaultHostname = *defaultHostname
	}

	// Certificate test mode
	if *testCerts {
		cm := certmanager.New(cfg.CertPath, cfg.DefaultHostname)
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
		CacheDir        string `json:"cache_dir,omitempty"`
		CertPath        string `json:"cert_path,omitempty"`
		DefaultHostname string `json:"default_hostname,omitempty"`
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var defaults ConfigDefaults
	if err := json.Unmarshal(data, &defaults); err != nil {
		return nil, err
	}

	return &proxy.Config{
		CacheDir:        defaults.CacheDir,
		CertPath:        defaults.CertPath,
		DefaultHostname: defaults.DefaultHostname,
	}, nil
}
