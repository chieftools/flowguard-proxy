package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"http-sec-proxy/certmanager"
	"http-sec-proxy/proxy"
)

func main() {
	var (
		// Proxy configuration
		bindAddrs    = flag.String("bind", "", "Comma-separated list of IP addresses to bind to (default: auto-detect public IPs)")
		httpPort     = flag.String("http-port", "11080", "Port for HTTP proxy server")
		httpsPort    = flag.String("https-port", "11443", "Port for HTTPS proxy server")
		noRedirect   = flag.Bool("no-redirect", false, "Skip iptables port redirection setup")
		serverHeader = flag.String("server", "Alboweb-Proxy/1.0", "The Server header value to use in responses")

		// Certificate configuration
		certPath  = flag.String("cert-path", "/opt/psa/var/certificates", "Path to combined certificate files")
		testCerts = flag.Bool("test-certs", false, "Test loading all certificates and exit")

		// Middleware: ipfilter
		ipsetV4Name = flag.String("ipset-v4", "abuseipdb_v4", "Name of the IPv4 ipset blocklist")
		ipsetV6Name = flag.String("ipset-v6", "abuseipdb_v6", "Name of the IPv6 ipset blocklist")

		// Trusted proxy configuration
		trustedProxyURLs    = flag.String("trusted-proxy-urls", "https://www.cloudflare.com/ips-v4,https://www.cloudflare.com/ips-v6", "Comma-separated list of URLs to fetch trusted proxy IP ranges")
		trustedProxyRefresh = flag.Duration("trusted-proxy-refresh", 12*time.Hour, "Refresh interval for trusted proxy IP lists")
	)
	flag.Parse()

	// Certificate test mode
	if *testCerts {
		cm := certmanager.New(*certPath)
		cm.TestCertificates()
		os.Exit(0)
	}

	proxyManager := proxy.NewManager(&proxy.Config{
		CertPath:            *certPath,
		HTTPPort:            *httpPort,
		HTTPSPort:           *httpsPort,
		BindAddrs:           parseBindAddrsList(*bindAddrs),
		NoRedirect:          *noRedirect,
		IPSetV4Name:         *ipsetV4Name,
		IPSetV6Name:         *ipsetV6Name,
		ServerHeader:        *serverHeader,
		TrustedProxyURLs:    parseBindAddrsList(*trustedProxyURLs),
		TrustedProxyRefresh: *trustedProxyRefresh,
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

	log.Println("HTTP Security Proxy is running...")
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
