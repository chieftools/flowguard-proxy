package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"flowguard/api"
	"flowguard/cache"
	"flowguard/certmanager"
	"flowguard/config"
	"flowguard/iplist"
	"flowguard/proxy"
)

var Version string

func main() {
	if Version == "" {
		Version = "dev"
	}

	log.Printf("FlowGuard version %s", Version)

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

	// Check for iplist subcommand
	if len(os.Args) >= 2 && os.Args[1] == "iplist" {
		// Parse flags for iplist command
		iplistFlag := flag.NewFlagSet("iplist", flag.ExitOnError)
		configFile := iplistFlag.String("config", "/etc/flowguard/config.json", "Path to the configuration file")
		cacheDir := iplistFlag.String("cache-dir", "/var/cache/flowguard", "Directory for caching external data")
		verbose := iplistFlag.Bool("verbose", false, "Enable verbose output")

		// Parse flags from os.Args[2:] to get config/cache-dir if provided
		// We need to find where the actual command args start
		args := os.Args[2:]
		nonFlagArgs := []string{}
		for i := 0; i < len(args); i++ {
			if strings.HasPrefix(args[i], "-") {
				// This is a flag, skip it and its value
				i++
			} else {
				nonFlagArgs = append(nonFlagArgs, args[i])
			}
		}

		err := iplistFlag.Parse(os.Args[2:])
		if err != nil {
			log.Printf("[ERROR] Failed to parse flags: %v", err)
			os.Exit(1)
		}

		// Re-parse non-flag args after flag parsing
		nonFlagArgs = iplistFlag.Args()

		if err := handleIPListCommand(nonFlagArgs, *configFile, *cacheDir, *verbose); err != nil {
			log.Printf("[ERROR] %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	var (
		// Proxy configuration
		bindAddrs  = flag.String("bind", "", "Comma-separated list of IP addresses to bind to (default: auto-detect public IPs)")
		httpPort   = flag.String("http-port", "11080", "Port for HTTP proxy server")
		httpsPort  = flag.String("https-port", "11443", "Port for HTTPS proxy server")
		noRedirect = flag.Bool("no-redirect", false, "Skip iptables port redirection setup")

		// Certificate configuration
		certPath    = flag.String("cert-path", "", "Path to combined certificate files")
		nginxConfig = flag.String("nginx-config", "", "Path to the Nginx configuration file")
		testCerts   = flag.Bool("test-certs", false, "Test loading all certificates and exit")

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

	// Apply CLI certificate paths if provided (needed for --test-certs)
	if *certPath != "" {
		cfg.CertPath = *certPath
	}
	if *nginxConfig != "" {
		cfg.NginxConfigPath = *nginxConfig
	}

	// Certificate test mode
	if *testCerts {
		cm := certmanager.New(cfg.CertPath, cfg.NginxConfigPath, "", *verbose)
		cm.TestCertificates()
		os.Exit(0)
	}

	// Apply remaining CLI flags
	cfg.Verbose = *verbose
	cfg.Version = Version
	cfg.CertPath = *certPath
	cfg.HTTPPort = *httpPort
	cfg.HTTPSPort = *httpsPort
	cfg.BindAddrs = parseBindAddrsList(*bindAddrs)
	cfg.UserAgent = fmt.Sprintf("FlowGuard/%s", Version)
	cfg.NoRedirect = *noRedirect
	cfg.ConfigFile = *configFile
	cfg.NginxConfigPath = *nginxConfig

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

	log.Println("FlowGuard is running and ready for requests...")
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
		NginxConfigPath string `json:"nginx_config_path,omitempty"`
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
		CacheDir:        defaults.CacheDir,
		CertPath:        defaults.CertPath,
		NginxConfigPath: defaults.NginxConfigPath,
	}, nil
}

// setupHost downloads the host configuration from the FlowGuard API and saves it to disk
func setupHost(hostKey, configFile string) error {
	// Create API client
	client := api.NewClient(hostKey, fmt.Sprintf("FlowGuard/%s", Version))

	// Show which API endpoint we're using (helpful for debugging)
	log.Printf("Using API base: %s", client.GetBaseURL())

	// Fetch configuration from API
	body, err := client.GetConfig()
	if err != nil {
		return err
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

// handleIPListCommand handles the iplist subcommand
func handleIPListCommand(args []string, configFile, cacheDir string, verbose bool) error {
	// Load configuration to get IP lists
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Case 1: No args - list all configured IP lists
	if len(args) == 0 {
		if cfg.IPLists == nil || len(*cfg.IPLists) == 0 {
			fmt.Println("No IP lists configured in", configFile)
			return nil
		}

		fmt.Printf("Configured IP lists in %s:\n\n", configFile)
		for name, listCfg := range *cfg.IPLists {
			fmt.Printf("  %s:\n", name)
			if listCfg.URL != "" {
				fmt.Printf("    Source: %s\n", listCfg.URL)
				if listCfg.RefreshIntervalSeconds > 0 {
					fmt.Printf("    Refresh: every %d seconds\n", listCfg.RefreshIntervalSeconds)
				}
			}
			if listCfg.Path != "" {
				fmt.Printf("    Source: %s (local file)\n", listCfg.Path)
			}
			fmt.Println()
		}
		return nil
	}

	listName := args[0]

	// Check if the list exists in config
	if cfg.IPLists == nil || (*cfg.IPLists)[listName] == nil {
		return fmt.Errorf("IP list '%s' not found in configuration", listName)
	}

	listCfg := (*cfg.IPLists)[listName]

	// Create cache instance
	cacheInstance, err := cache.NewCache(cacheDir, fmt.Sprintf("FlowGuard/%s", Version), verbose)
	if err != nil {
		return fmt.Errorf("failed to create cache: %w", err)
	}

	// Case 2: Load list and show stats (no contains command)
	if len(args) == 1 {
		return loadAndShowStats(listName, listCfg, cacheInstance)
	}

	// Case 3: Check if IP is in list
	if len(args) == 3 && args[1] == "contains" {
		ipAddr := args[2]
		return checkIPInList(listName, listCfg, ipAddr, cacheInstance)
	}

	return fmt.Errorf("invalid arguments. Usage:\n  flowguard iplist\n  flowguard iplist <name>\n  flowguard iplist <name> contains <ip>")
}

// loadAndShowStats loads a list and displays statistics
func loadAndShowStats(listName string, listCfg *config.IPListConfig, cacheInstance *cache.Cache) error {
	fmt.Printf("Loading IP list '%s'...\n\n", listName)

	// Measure memory before loading
	var memBefore runtime.MemStats
	runtime.GC() // Force GC to get accurate baseline
	runtime.ReadMemStats(&memBefore)

	// Measure load time
	startTime := time.Now()

	// Convert config to iplist.ListConfig
	iplistCfg := iplist.ListConfig{
		URL:                    listCfg.URL,
		Path:                   listCfg.Path,
		RefreshIntervalSeconds: listCfg.RefreshIntervalSeconds,
	}

	// Create a temporary manager with just this list
	listsConfig := map[string]iplist.ListConfig{
		listName: iplistCfg,
	}

	manager, err := iplist.New(listsConfig, cacheInstance)
	if err != nil {
		return fmt.Errorf("failed to load list: %w", err)
	}
	defer manager.Stop()

	loadDuration := time.Since(startTime)

	// Measure memory after loading
	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)

	memUsed := memAfter.Alloc - memBefore.Alloc

	// Display statistics
	fmt.Printf("List Statistics:\n")
	fmt.Printf("  Name:        %s\n", listName)
	if listCfg.URL != "" {
		fmt.Printf("  Source:      %s\n", listCfg.URL)
	} else {
		fmt.Printf("  Source:      %s\n", listCfg.Path)
	}
	fmt.Printf("  Load Time:   %v\n", loadDuration)
	fmt.Printf("  Memory Used: ~%s\n", formatBytes(memUsed))
	fmt.Println()

	return nil
}

// checkIPInList checks if an IP is in the list and shows timing
func checkIPInList(listName string, listCfg *config.IPListConfig, ipAddr string, cacheInstance *cache.Cache) error {
	fmt.Printf("Loading IP list '%s'...\n", listName)

	// Measure memory before loading
	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	// Measure load time
	startLoad := time.Now()

	// Convert config to iplist.ListConfig
	iplistCfg := iplist.ListConfig{
		URL:                    listCfg.URL,
		Path:                   listCfg.Path,
		RefreshIntervalSeconds: listCfg.RefreshIntervalSeconds,
	}

	// Create a temporary manager with just this list
	listsConfig := map[string]iplist.ListConfig{
		listName: iplistCfg,
	}

	manager, err := iplist.New(listsConfig, cacheInstance)
	if err != nil {
		return fmt.Errorf("failed to load list: %w", err)
	}
	defer manager.Stop()

	loadDuration := time.Since(startLoad)

	// Measure memory after loading
	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)

	memUsed := memAfter.Alloc - memBefore.Alloc

	// Perform the lookup with timing
	startLookup := time.Now()
	contains := manager.Contains(listName, ipAddr)
	lookupDuration := time.Since(startLookup)

	// Display results
	fmt.Println()
	fmt.Printf("Results:\n")
	fmt.Printf("  IP Address:     %s\n", ipAddr)
	fmt.Printf("  In List:        %v\n", contains)
	fmt.Println()
	fmt.Printf("Performance:\n")
	fmt.Printf("  List Load Time: %v\n", loadDuration)
	fmt.Printf("  Lookup Time:    %v\n", lookupDuration)
	fmt.Printf("  Memory Used:    ~%s\n", formatBytes(memUsed))
	fmt.Println()

	if contains {
		os.Exit(0)
	} else {
		os.Exit(1)
	}

	return nil
}

// formatBytes formats bytes into human-readable format
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
