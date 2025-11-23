package cmd

import (
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"flowguard/config"
	"flowguard/proxy"

	"github.com/spf13/cobra"
)

var (
	// Run command specific flags
	bindAddrs  string
	httpPort   string
	httpsPort  string
	noRedirect bool
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the proxy server",
	Long: `Start the FlowGuard reverse proxy server.

The proxy will intercept HTTP/HTTPS traffic and apply security filtering based on
the configured rules. By default, it sets up iptables rules to redirect traffic from
ports 80/443 to the proxy ports (11080/11443).`,
	Run: func(cmd *cobra.Command, args []string) {
		runProxy()
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	// Run-specific flags
	runCmd.Flags().StringVar(&bindAddrs, "bind", "", "Comma-separated list of IP addresses to bind to (default: auto-detect public IPs)")
	runCmd.Flags().StringVar(&httpPort, "http-port", "11080", "Port for HTTP proxy server")
	runCmd.Flags().StringVar(&httpsPort, "https-port", "11443", "Port for HTTPS proxy server")
	runCmd.Flags().BoolVar(&noRedirect, "no-redirect", false, "Skip iptables port redirection setup")
}

func runProxy() {
	log.Printf("FlowGuard version %s", GetVersion())

	// Load configuration
	configMgr, err := config.NewManager(configFile, GetUserAgent(), GetVersion(), cacheDir, verbose)
	if err != nil {
		log.Printf("Failed to load configuration from %s: %v", configFile, err)
		os.Exit(1)
	}

	err = configMgr.RefreshFromAPI(false)
	if err != nil {
		log.Printf("Warning: Failed to refresh configuration from API: %v", err)
	}

	// Create and start proxy manager
	proxyManager := proxy.NewManager(configMgr, &proxy.Config{
		Verbose:    verbose,
		Version:    GetVersion(),
		HTTPPort:   httpPort,
		HTTPSPort:  httpsPort,
		BindAddrs:  parseBindAddrsList(bindAddrs),
		UserAgent:  GetUserAgent(),
		NoRedirect: noRedirect,
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
