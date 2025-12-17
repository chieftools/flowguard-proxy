package cmd

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"flowguard/cache"
	"flowguard/config"
	"flowguard/iplist"

	"github.com/spf13/cobra"
)

var iplistCmd = &cobra.Command{
	Use:   "iplist [list-name] [contains <ip>]",
	Short: "Manage and query IP lists",
	Long: `Manage and query IP lists configured in FlowGuard.

Usage:
  flowguard iplist                          # List all configured IP lists
  flowguard iplist <name>                   # Show statistics for a specific list
  flowguard iplist <name> contains <ip>     # Check if IP is in list`,
	Args: cobra.MaximumNArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		if err := handleIPListCommand(args, GetConfigManager()); err != nil {
			log.Printf("[ERROR] %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(iplistCmd)
}

// handleIPListCommand handles the iplist subcommand
func handleIPListCommand(args []string, configMgr *config.Manager) error {
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

	manager, err := iplist.New(listsConfig, cacheInstance, false)
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

	manager, err := iplist.New(listsConfig, cacheInstance, false)
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
