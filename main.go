package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"http-sec-proxy/certmanager"
	"http-sec-proxy/proxy"
)

func main() {
	var (
		// Proxy configuration
		bindAddrs  = flag.String("bind", "", "Comma-separated list of IP addresses to bind to (default: auto-detect public IPs)")
		httpPort   = flag.String("http-port", "11080", "Port for HTTP proxy server")
		httpsPort  = flag.String("https-port", "11443", "Port for HTTPS proxy server")
		noRedirect = flag.Bool("no-redirect", false, "Skip iptables port redirection setup")

		// Certificate configuration
		certPath  = flag.String("cert-path", "/opt/psa/var/certificates", "Path to combined certificate files")
		testCerts = flag.Bool("test-certs", false, "Test loading all certificates and exit")

		// Behavior configuration
		cacheDir   = flag.String("cache-dir", "/var/cache/http-sec-proxy", "Directory for caching external data")
		userAgent  = flag.String("user-agent", "Alboweb-Proxy/1.0", "The User-Agent & Server header value to use requests and responses")
		configFile = flag.String("config", "config.json", "Path to the configuration file")
	)
	flag.Parse()

	// Certificate test mode
	if *testCerts {
		cm := certmanager.New(*certPath)
		cm.TestCertificates()
		os.Exit(0)
	}

	proxyManager := proxy.NewManager(&proxy.Config{
		CacheDir:   *cacheDir,
		CertPath:   *certPath,
		HTTPPort:   *httpPort,
		HTTPSPort:  *httpsPort,
		BindAddrs:  parseBindAddrsList(*bindAddrs),
		UserAgent:  *userAgent,
		NoRedirect: *noRedirect,
		ConfigFile: *configFile,
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
