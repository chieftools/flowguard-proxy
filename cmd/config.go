package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var (
	forceUpdate bool
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage FlowGuard configuration",
	Long:  `Commands for managing FlowGuard configuration including version check and updates.`,
}

var configVersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show current configuration version",
	Long:  `Displays the current configuration version (ID) from the local config file.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := showConfigVersion(); err != nil {
			log.Printf("[ERROR] Failed to get configuration version: %v", err)
			os.Exit(1)
		}
	},
}

var configUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update configuration from API",
	Long: `Fetches the latest configuration from the FlowGuard API and updates the local config file.

By default, uses ETag to avoid unnecessary downloads. Use --force to always download.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := updateConfig(forceUpdate); err != nil {
			log.Printf("[ERROR] Failed to update configuration: %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configVersionCmd)
	configCmd.AddCommand(configUpdateCmd)

	// Add --force flag to update command
	configUpdateCmd.Flags().BoolVarP(&forceUpdate, "force", "f", false, "Force update even if configuration hasn't changed")
}

// showConfigVersion displays the current configuration version
func showConfigVersion() error {
	// Create config manager to read current config
	configMgr, err := TryGetConfigManager()
	if err != nil {
		return err
	}
	defer configMgr.Stop()

	cfg := configMgr.GetConfig()
	if cfg == nil {
		return fmt.Errorf("no configuration loaded")
	}

	if cfg.ID != "" {
		fmt.Printf("Configuration version: %s\n", cfg.ID)
	} else {
		fmt.Println("No configuration version set")
	}

	return nil
}

// updateConfig updates the configuration from the API
func updateConfig(force bool) error {
	// Create config manager
	configMgr := GetConfigManager()

	cfg := configMgr.GetConfig()
	if cfg == nil {
		return fmt.Errorf("no configuration loaded")
	}

	// Check if we have a host key
	if cfg.Host == nil || cfg.Host.Key == "" {
		return fmt.Errorf("no host key configured. Run 'flowguard setup <host-key>' first")
	}

	currentID := cfg.ID
	if currentID != "" {
		if force {
			log.Printf("Forcing configuration update (current version: %s)", currentID)
		} else {
			log.Printf("Checking for configuration updates (current version: %s)", currentID)
		}
	} else {
		log.Printf("Checking for configuration updates (no version set)")
	}

	// Refresh from API
	if err := configMgr.RefreshFromAPI(force); err != nil {
		return err
	}

	// Reload to get the new config
	if err := configMgr.Load(); err != nil {
		return fmt.Errorf("failed to reload configuration after update: %w", err)
	}

	newCfg := configMgr.GetConfig()
	newID := ""
	if newCfg != nil {
		newID = newCfg.ID
	}

	if newID != "" && newID != currentID {
		log.Printf("[SUCCESS] Configuration updated successfully (version: %s -> %s)", currentID, newID)
	} else if newID == currentID {
		log.Printf("[SUCCESS] Configuration is already up to date (version: %s)", currentID)
	} else {
		log.Printf("[SUCCESS] Configuration updated successfully")
	}

	return nil
}
