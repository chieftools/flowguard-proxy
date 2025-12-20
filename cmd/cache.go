package cmd

import (
	"fmt"
	"log"
	"os"

	"flowguard/cache"

	"github.com/spf13/cobra"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage the FlowGuard cache",
	Long:  `Manage the FlowGuard cache for external data like IP lists and databases.`,
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear all cached files",
	Long:  `Clear all cached files from the cache directory.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := handleCacheClear(); err != nil {
			log.Printf("[ERROR] %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(cacheCmd)
	cacheCmd.AddCommand(cacheClearCmd)
}

func handleCacheClear() error {
	// Create a cache instance to clear it
	cacheInstance, err := cache.NewCache(cacheDir, GetUserAgent(), verbose)
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}

	fmt.Printf("Clearing cache directory: %s\n", cacheInstance.Dir())

	removed, err := cacheInstance.ClearCache()
	if err != nil {
		return fmt.Errorf("failed to clear cache: %w", err)
	}

	fmt.Printf("Removed %d cached file(s)\n", removed)
	return nil
}
