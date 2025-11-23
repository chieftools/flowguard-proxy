package cmd

import (
	"fmt"
	"log"
	"os"

	"flowguard/certmanager"
	"flowguard/config"

	"github.com/spf13/cobra"
)

var certificatesCmd = &cobra.Command{
	Use:   "certificates [hostname]",
	Short: "Test and view SSL certificates",
	Long: `Test and view SSL certificates configured in FlowGuard.

Usage:
  flowguard certificates              # Test all certificates
  flowguard certificates <hostname>   # Show certificates for specific hostname`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := handleCertificatesCommand(args, GetConfigManager()); err != nil {
			log.Printf("[ERROR] %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(certificatesCmd)
}

// handleCertificatesCommand handles the certificates subcommand
func handleCertificatesCommand(args []string, configMgr *config.Manager) error {
	cfg := configMgr.GetConfig()

	// Check if we have any certificate sources configured
	if cfg.Host.CertPath == "" && cfg.Host.NginxConfigPath == "" {
		return fmt.Errorf("no certificate sources configured. Set host.cert_path or host.nginx_config_path in the configuration file")
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
