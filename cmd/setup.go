package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"flowguard/api"
	"flowguard/certmanager"
	"flowguard/config"

	"github.com/spf13/cobra"
)

var (
	setupDiscover bool

	setupInput  io.Reader = os.Stdin
	setupOutput io.Writer = os.Stdout

	setupIsInteractive = func() bool {
		return isTerminal(os.Stdin)
	}

	setupPsaConfPath       = "/etc/psa/psa.conf"
	setupNginxConfigPath   = "/etc/nginx/nginx.conf"
	setupPleskRootFallback = []string{"/opt/psa", "/usr/local/psa"}
)

type setupAPIClient interface {
	GetConfig(etag string) ([]byte, error)
	PatchConfigPaths(certPath, nginxConfigPath string) error
	GetBaseURL() string
}

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
	setupCmd.Flags().BoolVar(&setupDiscover, "discover", false, "Discover and configure certificate or nginx paths even if already configured")
	rootCmd.AddCommand(setupCmd)
}

// setupHost downloads the host configuration from the FlowGuard API and saves it to disk
func setupHost(hostKey string) error {
	// Create API client
	client := api.NewClient(hostKey, GetUserAgent())

	if verbose {
		log.Printf("Connecting to API: %s", client.GetBaseURL())
	}

	// Fetch configuration from API (no ETag for initial setup)
	return setupHostWithClient(client)
}

func setupHostWithClient(client setupAPIClient) error {
	body, err := client.GetConfig("")
	if err != nil {
		return err
	}

	finalBody := body
	cfg, err := parseSetupConfig(body)
	if err != nil {
		return err
	}

	if shouldRunSetupDiscovery(cfg) {
		finalBody, err = runSetupDiscovery(client, body, cfg)
		if err != nil {
			return err
		}
	}

	return writeSetupConfig(finalBody)
}

func parseSetupConfig(body []byte) (*config.Config, error) {
	var cfg config.Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	return &cfg, nil
}

func shouldRunSetupDiscovery(cfg *config.Config) bool {
	if setupDiscover {
		return true
	}

	certPath, nginxConfigPath := configuredSetupPaths(cfg)
	return certPath == "" && nginxConfigPath == ""
}

func runSetupDiscovery(client setupAPIClient, body []byte, cfg *config.Config) ([]byte, error) {
	certPath, nginxConfigPath := configuredSetupPaths(cfg)
	if !setupIsInteractive() {
		if certPath == "" && nginxConfigPath == "" {
			warnMissingSetupPaths()
		}
		return body, nil
	}

	reader := bufio.NewReader(setupInput)

	discoveredCertPath := ""
	if path, ok := discoverPleskCertificatePath(); ok {
		accepted, err := promptYesNo(reader, setupOutput, fmt.Sprintf("Use discovered Plesk certificate directory %s?", path), true)
		if err != nil {
			return nil, err
		}
		if accepted {
			discoveredCertPath = path
		}
	}

	discoveredNginxConfigPath := ""
	if discoveredCertPath == "" {
		if path, ok := discoverNginxConfigPath(); ok {
			accepted, err := promptYesNo(reader, setupOutput, fmt.Sprintf("Use discovered nginx config %s?", path), true)
			if err != nil {
				return nil, err
			}
			if accepted {
				discoveredNginxConfigPath = path
			}
		}
	}

	if discoveredCertPath == "" && discoveredNginxConfigPath == "" {
		if certPath == "" && nginxConfigPath == "" {
			warnMissingSetupPaths()
		}
		return body, nil
	}

	if err := client.PatchConfigPaths(discoveredCertPath, discoveredNginxConfigPath); err != nil {
		return nil, fmt.Errorf("failed to update configuration paths: %w", err)
	}

	updatedBody, err := client.GetConfig("")
	if err != nil {
		return nil, fmt.Errorf("failed to re-fetch configuration after path update: %w", err)
	}

	updatedCfg, err := parseSetupConfig(updatedBody)
	if err != nil {
		return nil, err
	}

	updatedCertPath, updatedNginxConfigPath := configuredSetupPaths(updatedCfg)
	if updatedCertPath == "" && updatedNginxConfigPath == "" {
		return nil, fmt.Errorf("configuration did not include a certificate or nginx path after update")
	}

	return updatedBody, nil
}

func configuredSetupPaths(cfg *config.Config) (string, string) {
	if cfg == nil || cfg.Host == nil {
		return "", ""
	}

	return cfg.Host.CertPath, cfg.Host.NginxConfigPath
}

func discoverPleskCertificatePath() (string, bool) {
	for _, root := range setupPleskRoots() {
		path := filepath.Join(root, "var", "certificates")
		if err := certmanager.ProbeCertificateDirectory(path); err == nil {
			return path, true
		}
	}

	return "", false
}

func setupPleskRoots() []string {
	var roots []string
	if root, err := readPleskProductRoot(setupPsaConfPath); err == nil && root != "" {
		roots = append(roots, root)
	}
	roots = append(roots, setupPleskRootFallback...)

	seen := make(map[string]bool, len(roots))
	deduped := make([]string, 0, len(roots))
	for _, root := range roots {
		if root == "" || seen[root] {
			continue
		}
		seen[root] = true
		deduped = append(deduped, root)
	}

	return deduped
}

func readPleskProductRoot(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if commentStart := strings.Index(line, "#"); commentStart >= 0 {
			line = line[:commentStart]
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "PRODUCT_ROOT_D" {
			return fields[1], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("PRODUCT_ROOT_D not found in %s", path)
}

func discoverNginxConfigPath() (string, bool) {
	if err := certmanager.ProbeNginxConfig(setupNginxConfigPath); err == nil {
		return setupNginxConfigPath, true
	}

	return "", false
}

func promptYesNo(reader *bufio.Reader, output io.Writer, question string, defaultYes bool) (bool, error) {
	defaultLabel := "y/N"
	if defaultYes {
		defaultLabel = "Y/n"
	}

	for {
		fmt.Fprintf(output, "%s [%s]: ", question, defaultLabel)

		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			return false, fmt.Errorf("failed to read response: %w", err)
		}

		answer := strings.ToLower(strings.TrimSpace(line))
		switch answer {
		case "":
			return defaultYes, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(output, "Please answer yes or no.")
		}
	}
}

func warnMissingSetupPaths() {
	log.Printf("[WARNING] FlowGuard is probably unable to start without a valid host.cert_path or host.nginx_config_path")
}

func writeSetupConfig(body []byte) error {
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

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}
