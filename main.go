package main

import (
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

	var (
		// Proxy configuration
		bindAddrs  = flag.String("bind", "", "Comma-separated list of IP addresses to bind to (default: auto-detect public IPs)")
		httpPort   = flag.String("http-port", "11080", "Port for HTTP proxy server")
		httpsPort  = flag.String("https-port", "11443", "Port for HTTPS proxy server")
		noRedirect = flag.Bool("no-redirect", false, "Skip iptables port redirection setup")

		// Behavior configuration
		verbose    = flag.Bool("verbose", false, "Enable more verbose output")
		cacheDir   = flag.String("cache-dir", "/var/cache/flowguard", "Directory for caching external data")
		configFile = flag.String("config", "/etc/flowguard/config.json", "Path to the configuration file")
	)
	flag.Parse()

	// flowguard setup <host-key>
	if len(os.Args) >= 2 && os.Args[1] == "setup" {
		if len(os.Args) < 3 {
			log.Fatal("Usage: flowguard setup <host-key>")
		}

		if err := setupHost(os.Args[2], *configFile); err != nil {
			log.Printf("[ERROR] Failed to setup host: %v", err)
			os.Exit(1)
		}

		log.Printf("[SUCCESS] Host configured successfully. Configuration saved to %s", *configFile)
		os.Exit(0)
	}

	// At this point we expect to be able to load the config file
	configMgr, err := config.NewManager(*configFile, fmt.Sprintf("FlowGuard/%s", Version), Version, *cacheDir, *verbose)
	if err != nil {
		log.Printf("Failed to load configuration from %s: %v", *configFile, err)
		os.Exit(1)
	}

	// flowguard iplist [<name> [contains <ip>]]
	if len(os.Args) >= 2 && os.Args[1] == "iplist" {
		if err := handleIPListCommand(os.Args[2:], configMgr, *verbose); err != nil {
			log.Printf("[ERROR] %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// flowguard certificates [<hostname>]
	if len(os.Args) >= 2 && os.Args[1] == "certificates" {
		if err := handleCertificatesCommand(os.Args[2:], configMgr, *verbose); err != nil {
			log.Printf("[ERROR] %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Create and start proxy manager
	proxyManager := proxy.NewManager(configMgr, &proxy.Config{
		Verbose:    *verbose,
		Version:    Version,
		HTTPPort:   *httpPort,
		HTTPSPort:  *httpsPort,
		BindAddrs:  parseBindAddrsList(*bindAddrs),
		UserAgent:  fmt.Sprintf("FlowGuard/%s", Version),
		NoRedirect: *noRedirect,
	})

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
func handleIPListCommand(args []string, configMgr *config.Manager, verbose bool) error {
	cfg := configMgr.GetConfig()

	// Case 1: No args - list all configured IP lists
	if len(args) == 0 {
		if cfg.IPLists == nil || len(*cfg.IPLists) == 0 {
			fmt.Println("No IP lists configured")
			return nil
		}

		fmt.Printf("Configured IP lists:\n\n")
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

	// Case 2: Load list and show stats (no contains command)
	if len(args) == 1 {
		return loadAndShowStats(listName, listCfg, configMgr.GetCache())
	}

	// Case 3: Check if IP is in list
	if len(args) == 3 && args[1] == "contains" {
		ipAddr := args[2]
		return checkIPInList(listName, listCfg, ipAddr, configMgr.GetCache())
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

// handleCertificatesCommand handles the certificates subcommand
func handleCertificatesCommand(args []string, configMgr *config.Manager, verbose bool) error {
	cfg := configMgr.GetConfig()

	// Check if we have any certificate sources configured
	if cfg.Host.CertPath == "" && cfg.Host.NginxConfigPath == "" {
		return fmt.Errorf("no certificate sources configured. Set host.cert_path or host.nginx_config_path the the configuration file")
	}

	// Create certificate manager
	cm := certmanager.New(certmanager.Config{
		Verbose:         verbose,
		CertPath:        cfg.Host.CertPath,
		NginxConfigPath: cfg.Host.NginxConfigPath,
		DefaultHostname: cfg.Host.DefaultHostname,
	})
	defer cm.Stop()

	// Case 1: No args - test all certificates
	if len(args) == 0 {
		cm.TestCertificates()
		return nil
	}

	// Case 2: Show certificates for specific hostname
	hostname := args[0]
	cm.ShowCertificatesForHostname(hostname)
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
