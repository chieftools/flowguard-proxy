package proxy

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"flowguard/certmanager"
	"flowguard/config"
	"flowguard/iplist"
	"flowguard/middleware"
)

type Config struct {
	Verbose         bool
	Version         string
	CertPath        string
	NginxConfigPath string
	CacheDir        string
	HTTPPort        string
	HTTPSPort       string
	BindAddrs       []string
	UserAgent       string
	NoRedirect      bool
	ConfigFile      string
}

type Manager struct {
	config          *Config
	servers         []*Server
	certManager     *certmanager.Manager
	configManager   *config.Manager
	ipListManager   *iplist.Manager
	middlewareChain *middleware.Chain
	mu              sync.RWMutex
}

func NewManager(cfg *Config) *Manager {
	// Create configuration manager
	configMgr, err := config.NewManager(cfg.ConfigFile, cfg.UserAgent, cfg.Version, cfg.CacheDir, cfg.Verbose)
	if err != nil {
		log.Printf("Failed to load configuration from %s: %v", cfg.ConfigFile, err)
		os.Exit(1)
	}

	// Start config file watcher for hot-reload
	configMgr.StartWatcher()

	// Start API refresh if host key is configured (default 15 minutes)
	if configMgr.GetConfig().Host != nil && configMgr.GetConfig().Host.Key != "" {
		configMgr.StartAPIRefresh(15 * time.Minute)
	}

	// Create middleware chain with config-based middleware
	middlewareChain := middleware.NewChain()

	// Add middleware in the order they should execute
	// IP lookup MUST be before other middleware so they can see the enriched context
	middlewareChain.Add(middleware.NewIPLookupMiddleware(configMgr)) // Enriches request with IP/ASN data (must be first!)
	middlewareChain.Add(middleware.NewLoggingMiddleware(configMgr))  // Logs request and response with enriched data
	rulesMiddleware := middleware.NewRulesMiddleware(configMgr)      // Evaluates user defined rules
	middlewareChain.Add(rulesMiddleware)

	// Determine bind addresses based on configuration
	bindAddrs := cfg.BindAddrs
	if len(bindAddrs) == 0 {
		// Default: Get all public IP addresses on the machine
		publicIPs, err := getPublicIPAddresses()
		if err != nil {
			log.Printf("Failed to get public IPs: %v", err)
			os.Exit(1)
		}

		log.Printf("Auto-detected %d public IP address(es) for binding", len(publicIPs))
		cfg.BindAddrs = publicIPs
	}

	// Get certificate paths from both CLI config and JSON config
	certPath := cfg.CertPath
	nginxConfigPath := cfg.NginxConfigPath

	// Also check JSON config for cert/nginx paths (JSON config can override CLI)
	if jsonCfg := configMgr.GetConfig(); jsonCfg != nil && jsonCfg.Host != nil {
		if jsonCfg.Host.CertPath != "" {
			certPath = jsonCfg.Host.CertPath
		}
		if jsonCfg.Host.NginxConfigPath != "" {
			nginxConfigPath = jsonCfg.Host.NginxConfigPath
		}
	}

	defaultHostname := ""
	if configMgr.GetConfig().Host != nil {
		defaultHostname = configMgr.GetConfig().Host.DefaultHostname
	}

	// Initialize IP list manager if IP lists are configured
	var ipListMgr *iplist.Manager
	if jsonCfg := configMgr.GetConfig(); jsonCfg != nil && jsonCfg.IPLists != nil && len(*jsonCfg.IPLists) > 0 {
		// Convert config.IPListConfig to iplist.ListConfig
		listsConfig := make(map[string]iplist.ListConfig)
		for name, cfg := range *jsonCfg.IPLists {
			listsConfig[name] = iplist.ListConfig{
				URL:                    cfg.URL,
				Path:                   cfg.Path,
				RefreshIntervalSeconds: cfg.RefreshIntervalSeconds,
			}
		}

		// Create the IP list manager with the cache instance
		var err error
		ipListMgr, err = iplist.New(listsConfig, configMgr.GetCache())
		if err != nil {
			log.Printf("Failed to initialize IP list manager: %v", err)
		} else {
			// Set the IP list manager on the rules middleware
			rulesMiddleware.SetIPListManager(ipListMgr)
			log.Printf("Initialized IP list manager with %d list(s)", len(listsConfig))
		}
	}

	return &Manager{
		config:          cfg,
		certManager:     certmanager.New(certPath, nginxConfigPath, defaultHostname, cfg.Verbose),
		configManager:   configMgr,
		ipListManager:   ipListMgr,
		middlewareChain: middlewareChain,
	}
}

func (p *Manager) Start() error {
	trustedProxiesRefreshInterval := p.configManager.GetRefreshInterval()
	log.Printf("[trusted_proxy] Starting trusted proxy refresh with interval: %v", trustedProxiesRefreshInterval)

	// Periodically refresh trusted proxy lists from URLs
	go func() {
		ticker := time.NewTicker(trustedProxiesRefreshInterval)
		defer ticker.Stop()

		for range ticker.C {
			// Check if interval has changed in config
			newInterval := p.configManager.GetRefreshInterval()
			if newInterval != trustedProxiesRefreshInterval {
				log.Printf("[trusted_proxy] Refresh interval changed from %v to %v", trustedProxiesRefreshInterval, newInterval)
				ticker.Reset(newInterval)
				trustedProxiesRefreshInterval = newInterval
			}

			if err := p.configManager.RefreshTrustedProxies(); err != nil {
				log.Printf("[trusted_proxy] Failed to refresh trusted proxy lists: %v", err)
			}
		}
	}()

	errChan := make(chan error, len(p.config.BindAddrs)*2)

	// Create servers for each bind address
	for _, bindAddr := range p.config.BindAddrs {
		httpRedirPort := ""
		if !p.config.NoRedirect {
			httpRedirPort = "80"
		}

		httpServer := NewServer(&ServerConfig{
			scheme:     "http",
			verbose:    p.config.Verbose,
			bindAddr:   bindAddr,
			bindPort:   p.config.HTTPPort,
			redirPort:  httpRedirPort,
			middleware: p.middlewareChain,
		})
		p.servers = append(p.servers, httpServer)

		httpsRedirPort := ""
		if !p.config.NoRedirect {
			httpsRedirPort = "443"
		}

		httpsServer := NewServer(&ServerConfig{
			scheme:     "https",
			verbose:    p.config.Verbose,
			bindAddr:   bindAddr,
			bindPort:   p.config.HTTPSPort,
			redirPort:  httpsRedirPort,
			middleware: p.middlewareChain,
		})
		p.servers = append(p.servers, httpsServer)

		// Start HTTP server
		go func(server *Server) {
			errChan <- server.Start(nil)
		}(httpServer)

		// Start HTTPS server
		go func(server *Server) {
			errChan <- server.Start(p.certManager.GetTlsConfig())
		}(httpsServer)

		// Small delay between server starts to avoid race conditions
		time.Sleep(10 * time.Millisecond)
	}

	// Small delay before we setup port redirection rules
	time.Sleep(100 * time.Millisecond)

	for _, server := range p.servers {
		err := server.SetupPortRedirect()
		if err != nil {
			server.CleanupPortRedirect()
			log.Printf("Warning: Failed to setup port redirection for %s:%s: %v", server.config.bindAddr, server.config.bindPort, err)
		}
	}

	select {
	case err := <-errChan:
		return err
	default:
		return nil
	}
}

func (p *Manager) Shutdown() error {
	log.Println("Shutting down proxy server...")

	// Remove the port redirection rules to stop new incoming connections
	for _, server := range p.servers {
		server.CleanupPortRedirect()
	}

	// Stop the configuration mamager
	p.configManager.Stop()

	// Stop the certificate manager
	p.certManager.Stop()

	// Stop the IP list manager if initialized
	if p.ipListManager != nil {
		p.ipListManager.Stop()
	}

	// Small delay before we shut down the servers
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	totalServers := len(p.servers)
	wg.Add(totalServers)

	// Shutdown all servers
	for _, server := range p.servers {
		go func(srv *Server) {
			defer wg.Done()
			srv.Shutdown(ctx)
		}(server)
	}

	wg.Wait()

	// Stop the middleware chain
	p.middlewareChain.Stop()

	log.Println("FlowGuard shutdown complete")
	return nil
}
