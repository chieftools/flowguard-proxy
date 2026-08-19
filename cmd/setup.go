package cmd

import (
	"bufio"
	"context"
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
	"flowguard/fail2ban"
	"flowguard/proxy"

	"github.com/spf13/cobra"
)

var (
	setupDiscover bool

	setupInput  io.Reader = os.Stdin
	setupOutput io.Writer = os.Stdout

	setupIsInteractive = func() bool {
		return isTerminal(os.Stdin)
	}
	setupInspectNetwork  = proxy.InspectNetwork
	setupInspectFail2Ban = fail2ban.Inspect

	setupPsaConfPath       = "/etc/psa/psa.conf"
	setupACMEPaths         = []string{"/etc/traefik/acme.json", "/var/lib/traefik/acme.json"}
	setupNginxConfigPath   = "/etc/nginx/nginx.conf"
	setupPleskRootFallback = []string{"/opt/psa", "/usr/local/psa"}
)

type setupAPIClient interface {
	GetConfig(etag string) ([]byte, error)
	PatchConfig(payload api.ConfigPatch) error
	GetBaseURL() string
}

type setupDiscoveryCandidate struct {
	kind    string
	path    string
	summary certmanager.ProbeSummary
}

var setupCmd = &cobra.Command{
	Use:   "setup [host-key]",
	Short: "Configure FlowGuard with a host key",
	Long: `Downloads the host configuration from the FlowGuard API and saves it to disk.

The host key is provided by the FlowGuard control panel and looks like: fgsvr_...
If omitted, FlowGuard reuses the host key from the existing configuration and
rediscovers the local server configuration.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 1 {
			return fmt.Errorf("too many arguments (expected only host key)")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		hostKey, discover, err := resolveSetupInvocation(args)
		if err != nil {
			log.Printf("[ERROR] Failed to setup host: %v", err)
			os.Exit(1)
		}

		if err := setupHost(hostKey, discover); err != nil {
			log.Printf("[ERROR] Failed to setup host: %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	setupCmd.Flags().BoolVar(&setupDiscover, "discover", false, "Discover and configure certificate or nginx paths even if already configured")
	rootCmd.AddCommand(setupCmd)
}

func resolveSetupInvocation(args []string) (string, bool, error) {
	if len(args) == 1 {
		return args[0], setupDiscover, nil
	}

	hostKey, err := configuredSetupHostKey(configFile)
	if err != nil {
		return "", false, err
	}

	return hostKey, true, nil
}

func configuredSetupHostKey(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("host key is required (e.g., fgsvr_...); no existing configuration found at %s", path)
		}
		return "", fmt.Errorf("read existing configuration at %s: %w", path, err)
	}

	cfg, err := parseSetupConfig(body)
	if err != nil {
		return "", fmt.Errorf("load existing configuration at %s: %w", path, err)
	}
	if cfg.Host == nil || strings.TrimSpace(cfg.Host.Key) == "" {
		return "", fmt.Errorf("host key is required (e.g., fgsvr_...); existing configuration at %s has no host key", path)
	}

	return cfg.Host.Key, nil
}

// setupHost downloads the host configuration from the FlowGuard API and saves it to disk.
func setupHost(hostKey string, discover bool) error {
	// Create API client
	client := api.NewClient(hostKey, GetUserAgent())

	if verbose {
		log.Printf("Connecting to API: %s", client.GetBaseURL())
	}

	// Fetch configuration from API (no ETag for initial setup)
	return setupHostWithClientAndDiscovery(client, discover)
}

func setupHostWithClient(client setupAPIClient) error {
	return setupHostWithClientAndDiscovery(client, setupDiscover)
}

func setupHostWithClientAndDiscovery(client setupAPIClient, discover bool) error {
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

	finalBody, err = runSetupDiscovery(client, body, cfg, discover)
	if err != nil {
		return err
	}

	finalConfig, err := parseSetupConfig(finalBody)
	if err != nil {
		return err
	}
	if err := validateSetupNetwork(finalConfig); err != nil {
		return err
	}

	if err := runSetupStep("Storing configuration", fmt.Sprintf("Stored configuration at %s", configFile), func() error {
		return writeSetupConfig(finalBody)
	}); err != nil {
		return err
	}

	printSetupCompletion()
	return nil
}

func printSetupCompletion() {
	fmt.Fprintln(setupOutput, "✓ Setup complete")
	fmt.Fprintln(setupOutput, "  Start FlowGuard, or restart it if already running, to apply this configuration.")
	fmt.Fprintln(setupOutput, "  systemd: sudo systemctl restart flowguard")
}

func validateSetupNetwork(cfg *config.Config) error {
	if cfg == nil || cfg.UpstreamClientIPMode() != config.UpstreamClientIPModeTransparent {
		return nil
	}
	inspection, err := setupInspectNetwork(cfg, nil)
	if err != nil {
		return fmt.Errorf("inspect transparent upstream networking: %w", err)
	}
	if !inspection.Ready {
		fmt.Fprint(setupOutput, proxy.FormatNetworkInspection(inspection))
		return fmt.Errorf("transparent upstream networking is not ready; run flowguard network inspect for details")
	}
	fmt.Fprintln(setupOutput, "✓ Transparent upstream networking ready")
	return nil
}

func parseSetupConfig(body []byte) (*config.Config, error) {
	var cfg config.Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	return &cfg, nil
}

func runSetupDiscovery(client setupAPIClient, body []byte, cfg *config.Config, rediscover bool) ([]byte, error) {
	certPath, acmePath, nginxConfigPath := configuredSetupPaths(cfg)
	if !setupIsInteractive() {
		if certPath == "" && acmePath == "" && nginxConfigPath == "" {
			warnMissingSetupPaths()
		}
		return body, nil
	}

	reader := bufio.NewReader(setupInput)

	discoveredCertPath := ""
	discoveredACMEPath := ""
	discoveredNginxConfigPath := ""
	if rediscover || (certPath == "" && acmePath == "" && nginxConfigPath == "") {
		var certCandidate setupDiscoveryCandidate
		var hasCertCandidate bool
		var acmeCandidate setupDiscoveryCandidate
		var hasACMECandidate bool
		var nginxCandidate setupDiscoveryCandidate
		var hasNginxCandidate bool
		var discoveryDiagnostics []string
		if err := runSetupStep("Looking for server configuration", "Server configuration discovery complete", func() error {
			var diagnostics []string
			certCandidate, hasCertCandidate, diagnostics = discoverPleskCertificatePath()
			discoveryDiagnostics = append(discoveryDiagnostics, diagnostics...)
			acmeCandidate, hasACMECandidate, diagnostics = discoverTraefikACMEPath()
			discoveryDiagnostics = append(discoveryDiagnostics, diagnostics...)
			nginxCandidate, hasNginxCandidate, diagnostics = discoverNginxConfigPath()
			discoveryDiagnostics = append(discoveryDiagnostics, diagnostics...)
			return nil
		}); err != nil {
			return nil, err
		}
		if verbose {
			fmt.Fprintln(setupOutput, "  Verbose server configuration detection:")
			for _, diagnostic := range discoveryDiagnostics {
				fmt.Fprintf(setupOutput, "    - %s\n", diagnostic)
			}
		}

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

		if discoveredCertPath == "" && hasACMECandidate {
			printSetupDiscoveryCandidate(acmeCandidate)
			accepted, err := promptYesNo(reader, setupOutput, "Use this server configuration?", true)
			if err != nil {
				return nil, err
			}
			if accepted {
				discoveredACMEPath = acmeCandidate.path
			}
		}

		if discoveredCertPath == "" && discoveredACMEPath == "" && hasNginxCandidate {
			printSetupDiscoveryCandidate(nginxCandidate)
			accepted, err := promptYesNo(reader, setupOutput, "Use this server configuration?", true)
			if err != nil {
				return nil, err
			}
			if accepted {
				discoveredNginxConfigPath = nginxCandidate.path
			}
		}
	} else if verbose {
		fmt.Fprintf(setupOutput, "  Verbose server configuration detection:\n    - skipped because configured paths are being reused (certificate=%q, acme=%q, nginx=%q)\n", certPath, acmePath, nginxConfigPath)
	}

	if discoveredCertPath == "" && discoveredACMEPath == "" && discoveredNginxConfigPath == "" {
		if certPath == "" && acmePath == "" && nginxConfigPath == "" {
			warnMissingSetupPaths()
		}
	} else {
		applySetupPaths(cfg, discoveredCertPath, discoveredACMEPath, discoveredNginxConfigPath)
	}

	serverPatch, err := promptSetupServerConfiguration(reader, cfg, rediscover)
	if err != nil {
		return nil, err
	}
	fail2banPatch, err := promptSetupFail2Ban(reader, cfg)
	if err != nil {
		return nil, err
	}
	payload := api.ConfigPatch{Server: &serverPatch, Fail2Ban: fail2banPatch}
	if discoveredCertPath != "" || discoveredACMEPath != "" || discoveredNginxConfigPath != "" {
		payload.Host = &api.HostConfigPatch{
			CertPath:        discoveredCertPath,
			ACMEPath:        discoveredACMEPath,
			NginxConfigPath: discoveredNginxConfigPath,
		}
	}

	if err := runSetupStep("Updating FlowGuard control plane", "Updated FlowGuard control plane", func() error {
		return client.PatchConfig(payload)
	}); err != nil {
		return nil, fmt.Errorf("failed to update setup configuration: %w", err)
	}

	var updatedBody []byte
	if err := runSetupStep("Downloading updated configuration", "Downloaded updated configuration", func() error {
		var err error
		updatedBody, err = client.GetConfig("")
		return err
	}); err != nil {
		return nil, fmt.Errorf("failed to re-fetch configuration after setup update: %w", err)
	}

	updatedCfg, err := parseSetupConfig(updatedBody)
	if err != nil {
		return nil, err
	}

	if err := validateSetupPatchResponse(updatedCfg, payload); err != nil {
		return nil, err
	}

	return updatedBody, nil
}

func promptSetupFail2Ban(reader *bufio.Reader, cfg *config.Config) (*api.Fail2BanConfigPatch, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inspection := setupInspectFail2Ban(ctx)
	current := cfg.Fail2BanEnabled()
	if !inspection.Available {
		if current {
			fmt.Fprintf(setupOutput, "⚠ Fail2Ban integration remains enabled, but availability could not be verified: %s\n", inspection.Reason)
		} else if verbose && inspection.Reason != "" {
			fmt.Fprintf(setupOutput, "  Fail2Ban integration not offered: %s\n", inspection.Reason)
		}
		return nil, nil
	}

	fmt.Fprintf(setupOutput, "  ✓ Detected Fail2Ban with %d active jail(s): %s\n", len(inspection.Jails), setupListOrNone(inspection.Jails))
	fmt.Fprintln(setupOutput, "  FlowGuard can silently block HTTP requests from addresses banned by any active jail.")
	enabled, err := promptYesNo(reader, setupOutput, "Enable Fail2Ban integration?", current)
	if err != nil {
		return nil, err
	}
	return &api.Fail2BanConfigPatch{Enabled: enabled}, nil
}

func applySetupPaths(cfg *config.Config, certPath, acmePath, nginxConfigPath string) {
	if cfg.Host == nil {
		cfg.Host = &config.HostConfig{}
	}
	if certPath != "" {
		cfg.Host.CertPath = certPath
	}
	if acmePath != "" {
		cfg.Host.ACMEPath = acmePath
	}
	if nginxConfigPath != "" {
		cfg.Host.NginxConfigPath = nginxConfigPath
	}
}

func configuredSetupPaths(cfg *config.Config) (string, string, string) {
	if cfg == nil || cfg.Host == nil {
		return "", "", ""
	}

	return cfg.Host.CertPath, cfg.Host.ACMEPath, cfg.Host.NginxConfigPath
}

func discoverPleskCertificatePath() (setupDiscoveryCandidate, bool, []string) {
	var diagnostics []string
	for _, root := range setupPleskRoots() {
		path := filepath.Join(root, "var", "certificates")
		summary, err := certmanager.ProbeCertificateDirectorySummary(path)
		if err == nil {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"Plesk certificates: accepted %s (%d usable certificate(s), %d hostname(s))",
				path, summary.CertificateCount, summary.HostnameCount,
			))
			return setupDiscoveryCandidate{
				kind:    "certificate",
				path:    path,
				summary: summary,
			}, true, diagnostics
		}
		diagnostics = append(diagnostics, fmt.Sprintf("Plesk certificates: rejected %s: %v", path, err))
	}

	return setupDiscoveryCandidate{}, false, diagnostics
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

func discoverTraefikACMEPath() (setupDiscoveryCandidate, bool, []string) {
	var diagnostics []string
	for _, path := range setupACMEPaths {
		summary, err := certmanager.ProbeTraefikACMEFileSummary(path)
		if err == nil {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"Traefik ACME storage: accepted %s (%d usable certificate(s), %d hostname(s))",
				path, summary.CertificateCount, summary.HostnameCount,
			))
			return setupDiscoveryCandidate{
				kind:    "acme",
				path:    path,
				summary: summary,
			}, true, diagnostics
		}
		diagnostics = append(diagnostics, fmt.Sprintf("Traefik ACME storage: rejected %s: %v", path, err))
	}

	return setupDiscoveryCandidate{}, false, diagnostics
}

func discoverNginxConfigPath() (setupDiscoveryCandidate, bool, []string) {
	summary, err := certmanager.ProbeNginxConfigSummary(setupNginxConfigPath)
	if err == nil {
		return setupDiscoveryCandidate{
			kind:    "nginx",
			path:    setupNginxConfigPath,
			summary: summary,
		}, true, []string{fmt.Sprintf(
			"NGINX configuration: accepted %s (%d usable certificate(s), %d hostname(s))",
			setupNginxConfigPath, summary.CertificateCount, summary.HostnameCount,
		)}
	}

	return setupDiscoveryCandidate{}, false, []string{fmt.Sprintf("NGINX configuration: rejected %s: %v", setupNginxConfigPath, err)}
}

func printSetupDiscoveryCandidate(candidate setupDiscoveryCandidate) {
	switch candidate.kind {
	case "certificate":
		fmt.Fprintf(setupOutput, "  ✓ Discovered Plesk certificate directory: %s\n", candidate.path)
	case "acme":
		fmt.Fprintf(setupOutput, "  ✓ Discovered Traefik ACME storage: %s\n", candidate.path)
	case "nginx":
		fmt.Fprintf(setupOutput, "  ✓ Discovered nginx config: %s\n", candidate.path)
	default:
		fmt.Fprintf(setupOutput, "  ✓ Discovered server configuration: %s\n", candidate.path)
	}

	fmt.Fprintf(
		setupOutput,
		"    Found %s covering %s.\n",
		plural(candidate.summary.CertificateCount, "usable certificate", "usable certificates"),
		plural(candidate.summary.HostnameCount, "hostname", "hostnames"),
	)
}

func promptYesNoPlain(reader *bufio.Reader, output io.Writer, question string, defaultYes bool) (bool, error) {
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
	fmt.Fprintln(setupOutput, "⚠ FlowGuard is probably unable to start without a valid host.cert_path, host.acme_path, or host.nginx_config_path")
}

func runSetupStep(activeMessage, successMessage string, action func() error) error {
	if currentSetupInteractionMode() == setupInteractionPlain {
		fmt.Fprintf(setupOutput, "%s...\n", activeMessage)
		err := action()
		if err != nil {
			fmt.Fprintf(setupOutput, "✗ %s failed\n", activeMessage)
			return err
		}
		fmt.Fprintf(setupOutput, "✓ %s\n", successMessage)
		return nil
	}

	err := runSetupSpinner(activeMessage, action)
	if err != nil {
		fmt.Fprintf(setupOutput, "✗ %s failed\n", activeMessage)
		return err
	}
	fmt.Fprintf(setupOutput, "✓ %s\n", successMessage)
	return nil
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
