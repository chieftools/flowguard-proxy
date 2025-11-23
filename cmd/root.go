package cmd

import (
	"flowguard/config"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Global flags shared across commands
	verbose    bool
	configFile string
	cacheDir   string

	// Version is set by the build process
	Version string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "flowguard",
	Short: "FlowGuard - High-performance reverse proxy with advanced security filtering",
	Long: `FlowGuard is a high-performance reverse proxy written in Go that provides
transparent HTTP/HTTPS traffic interception with advanced security filtering.`,
}

// Execute adds all child commands to the root command and sets appropriate flags.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags available to all commands
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "/etc/flowguard/config.json", "Path to the configuration file")
	rootCmd.PersistentFlags().StringVar(&cacheDir, "cache-dir", "/var/cache/flowguard", "Directory for caching external data")
}

// GetVersion returns the current version string
func GetVersion() string {
	if Version == "" {
		return "dev"
	}
	return Version
}

// GetUserAgent returns the User-Agent string for HTTP requests
func GetUserAgent() string {
	return fmt.Sprintf("FlowGuard/%s", GetVersion())
}

// GetConfigManager loads and returns the configuration manager
func GetConfigManager() *config.Manager {
	configMgr, err := TryGetConfigManager()
	if err != nil {
		log.Printf("Failed to load configuration from %s: %v", configFile, err)
		os.Exit(1)
	}
	return configMgr
}

// TryGetConfigManager attempts to load and return the configuration manager
func TryGetConfigManager() (*config.Manager, error) {
	return config.NewManager(configFile, GetUserAgent(), GetVersion(), cacheDir, verbose)
}
