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
	"time"

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

type setupDiscoveryCandidate struct {
	kind    string
	path    string
	summary certmanager.ProbeSummary
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
	var body []byte
	if err := runSetupStep("Fetching host configuration", "Host configuration received", func() error {
		var err error
		body, err = client.GetConfig("")
		return err
	}); err != nil {
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

	return runSetupStep("Storing configuration", fmt.Sprintf("Stored configuration at %s", configFile), func() error {
		return writeSetupConfig(finalBody)
	})
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

	var certCandidate setupDiscoveryCandidate
	var hasCertCandidate bool
	var nginxCandidate setupDiscoveryCandidate
	var hasNginxCandidate bool
	if err := runSetupStep("Looking for server configuration", "Server configuration discovery complete", func() error {
		certCandidate, hasCertCandidate = discoverPleskCertificatePath()
		nginxCandidate, hasNginxCandidate = discoverNginxConfigPath()
		return nil
	}); err != nil {
		return nil, err
	}

	discoveredCertPath := ""
	if hasCertCandidate {
		printSetupDiscoveryCandidate(certCandidate)
		accepted, err := promptYesNo(reader, setupOutput, "Use this server configuration?", true)
		if err != nil {
			return nil, err
		}
		if accepted {
			discoveredCertPath = certCandidate.path
		}
	}

	discoveredNginxConfigPath := ""
	if discoveredCertPath == "" && hasNginxCandidate {
		printSetupDiscoveryCandidate(nginxCandidate)
		accepted, err := promptYesNo(reader, setupOutput, "Use this server configuration?", true)
		if err != nil {
			return nil, err
		}
		if accepted {
			discoveredNginxConfigPath = nginxCandidate.path
		}
	}

	if discoveredCertPath == "" && discoveredNginxConfigPath == "" {
		if certPath == "" && nginxConfigPath == "" {
			warnMissingSetupPaths()
		}
		return body, nil
	}

	if err := runSetupStep("Updating FlowGuard control plane", "Updated FlowGuard control plane", func() error {
		return client.PatchConfigPaths(discoveredCertPath, discoveredNginxConfigPath)
	}); err != nil {
		return nil, fmt.Errorf("failed to update configuration paths: %w", err)
	}

	var updatedBody []byte
	if err := runSetupStep("Downloading updated configuration", "Downloaded updated configuration", func() error {
		var err error
		updatedBody, err = client.GetConfig("")
		return err
	}); err != nil {
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

func discoverPleskCertificatePath() (setupDiscoveryCandidate, bool) {
	for _, root := range setupPleskRoots() {
		path := filepath.Join(root, "var", "certificates")
		summary, err := certmanager.ProbeCertificateDirectorySummary(path)
		if err == nil {
			return setupDiscoveryCandidate{
				kind:    "certificate",
				path:    path,
				summary: summary,
			}, true
		}
	}

	return setupDiscoveryCandidate{}, false
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

func discoverNginxConfigPath() (setupDiscoveryCandidate, bool) {
	summary, err := certmanager.ProbeNginxConfigSummary(setupNginxConfigPath)
	if err == nil {
		return setupDiscoveryCandidate{
			kind:    "nginx",
			path:    setupNginxConfigPath,
			summary: summary,
		}, true
	}

	return setupDiscoveryCandidate{}, false
}

func printSetupDiscoveryCandidate(candidate setupDiscoveryCandidate) {
	switch candidate.kind {
	case "certificate":
		fmt.Fprintf(setupOutput, "✓ Discovered Plesk certificate directory: %s\n", candidate.path)
	case "nginx":
		fmt.Fprintf(setupOutput, "✓ Discovered nginx config: %s\n", candidate.path)
	default:
		fmt.Fprintf(setupOutput, "✓ Discovered server configuration: %s\n", candidate.path)
	}

	fmt.Fprintf(
		setupOutput,
		"  Found %s covering %s.\n",
		plural(candidate.summary.CertificateCount, "usable certificate", "usable certificates"),
		plural(candidate.summary.HostnameCount, "hostname", "hostnames"),
	)
}

func promptYesNo(reader *bufio.Reader, output io.Writer, question string, defaultYes bool) (bool, error) {
	defaultLabel := "y/N"
	if defaultYes {
		defaultLabel = "Y/n"
	}

	for {
		fmt.Fprintf(output, "\n  %s [%s]: ", question, defaultLabel)

		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			return false, fmt.Errorf("failed to read response: %w", err)
		}

		answer := strings.ToLower(strings.TrimSpace(line))
		switch answer {
		case "":
			fmt.Fprintln(output)
			return defaultYes, nil
		case "y", "yes":
			fmt.Fprintln(output)
			return true, nil
		case "n", "no":
			fmt.Fprintln(output)
			return false, nil
		default:
			fmt.Fprintln(output)
			fmt.Fprintln(output, "  Please answer yes or no.")
		}
	}
}

func warnMissingSetupPaths() {
	fmt.Fprintln(setupOutput, "⚠ FlowGuard is probably unable to start without a valid host.cert_path or host.nginx_config_path")
}

func runSetupStep(activeMessage, successMessage string, action func() error) error {
	spinner := startSetupSpinner(activeMessage)
	if spinner == nil {
		fmt.Fprintf(setupOutput, "%s...\n", activeMessage)
	}

	err := action()
	if spinner != nil {
		spinner.stop(successMessage, err)
		return err
	}

	if err != nil {
		fmt.Fprintf(setupOutput, "✗ %s failed\n", activeMessage)
		return err
	}

	fmt.Fprintf(setupOutput, "✓ %s\n", successMessage)
	return nil
}

type setupSpinner struct {
	activeMessage string
	done          chan struct{}
	stopCh        chan struct{}
}

func startSetupSpinner(activeMessage string) *setupSpinner {
	if !setupOutputSupportsSpinner() {
		return nil
	}

	spinner := &setupSpinner{
		activeMessage: activeMessage,
		done:          make(chan struct{}),
		stopCh:        make(chan struct{}),
	}

	go func() {
		defer close(spinner.done)

		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		index := 0
		for {
			fmt.Fprintf(setupOutput, "\r\033[2K%s %s...", frames[index%len(frames)], activeMessage)
			index++

			select {
			case <-ticker.C:
			case <-spinner.stopCh:
				return
			}
		}
	}()

	return spinner
}

func (s *setupSpinner) stop(successMessage string, err error) {
	close(s.stopCh)
	<-s.done

	if err != nil {
		fmt.Fprintf(setupOutput, "\r\033[2K✗ %s failed\n", s.activeMessage)
		return
	}

	fmt.Fprintf(setupOutput, "\r\033[2K✓ %s\n", successMessage)
}

func setupOutputSupportsSpinner() bool {
	file, ok := setupOutput.(*os.File)
	return ok && isTerminal(file)
}

func plural(count int, singular, plural string) string {
	word := plural
	if count == 1 {
		word = singular
	}

	return fmt.Sprintf("%d %s", count, word)
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
