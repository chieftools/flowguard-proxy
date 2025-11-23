package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"flowguard/api"

	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup <host-key>",
	Short: "Configure FlowGuard with a host key",
	Long: `Downloads the host configuration from the FlowGuard API and saves it to disk.

The host key is provided by the FlowGuard control panel and looks like: fgsvr_...`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("host key is required (e.g., fgsvr_...)")
		}
		if len(args) > 1 {
			return fmt.Errorf("too many arguments (expected only host key)")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		hostKey := args[0]

		if err := setupHost(hostKey); err != nil {
			log.Printf("[ERROR] Failed to setup host: %v", err)
			os.Exit(1)
		}

		log.Printf("[SUCCESS] Host configured successfully. Configuration saved to %s", configFile)
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
}

// setupHost downloads the host configuration from the FlowGuard API and saves it to disk
func setupHost(hostKey string) error {
	// Create API client
	client := api.NewClient(hostKey, GetUserAgent())

	if verbose {
		log.Printf("Connecting to API: %s", client.GetBaseURL())
	}

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
		// Clean up temp file if rename fails (ignore cleanup errors)
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	return nil
}
