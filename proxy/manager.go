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
	Verbose    bool
	Version    string
	HTTPPort   string
	HTTPSPort  string
	BindAddrs  []string
	UserAgent  string
	NoRedirect bool
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

func NewManager(configMgr *config.Manager, cfg *Config) *Manager {
	// Start config file watcher for hot-reload
	configMgr.StartWatcher()

	// Start API refresh if host key is configured (default 15 minutes)
	if configMgr.GetConfig().Host != nil && configMgr.GetConfig().Host.Key != "" {
		configMgr.StartAPIRefresh(15 * time.Minute)
	}

	// Create middleware chain with config-based middleware
	middlewareChain := middleware.NewChain()

	// Add middleware in the order they should execute
	// Timing middleware MUST be first to capture the full middleware stack timing
	middlewareChain.Add(middleware.NewTimingMiddleware())            // Captures precise timing for all middleware (must be first!)
	middlewareChain.Add(middleware.NewIPLookupMiddleware(configMgr)) // Enriches request with IP/ASN data
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
	certPath := ""
	nginxConfigPath := ""

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

	// Create the proxy manager
	pm := &Manager{
		config: cfg,
		certManager: certmanager.New(certmanager.Config{
			Verbose:         cfg.Verbose,
			CertPath:        certPath,
			NginxConfigPath: nginxConfigPath,
			DefaultHostname: defaultHostname,
		}),
		configManager:   configMgr,
		middlewareChain: middlewareChain,
	}

	// Initialize IP list manager with current config
	pm.initializeIPListManager(configMgr.GetConfig(), rulesMiddleware)

	// Register callback to handle IP list configuration changes
	configMgr.OnChange(func(newConfig *config.Config) {
		pm.handleIPListConfigChange(newConfig, rulesMiddleware)
	})

	// Register callback to handle IP list update events from WebSocket
	configMgr.OnIPListUpdate(func(listIDs []string) {
		pm.handleIPListUpdateEvent(listIDs)
	})

	return pm
}

// initializeIPListManager creates and initializes the IP list manager from config
func (p *Manager) initializeIPListManager(cfg *config.Config, rulesMiddleware *middleware.RulesMiddleware) {
	if cfg == nil || cfg.IPLists == nil || len(*cfg.IPLists) == 0 {
		log.Printf("[ip_list] No IP lists configured")
		return
	}

	// Convert config.IPListConfig to iplist.ListConfig
	listsConfig := make(map[string]iplist.ListConfig)
	for name, listCfg := range *cfg.IPLists {
		listsConfig[name] = iplist.ListConfig{
			URL:                    listCfg.URL,
			Path:                   listCfg.Path,
			RefreshIntervalSeconds: listCfg.RefreshIntervalSeconds,
		}
	}

	// Create the IP list manager with the cache instance
	ipListMgr, err := iplist.New(listsConfig, p.configManager.GetCache(), p.config.Verbose)
	if err != nil {
		log.Printf("[ip_list] Failed to initialize IP list manager: %v", err)
		return
	}

	// Store and set the IP list manager
	p.mu.Lock()
	oldManager := p.ipListManager
	p.ipListManager = ipListMgr
	p.mu.Unlock()

	// Stop the old manager if it exists
	if oldManager != nil {
		oldManager.Stop()
	}

	// Set the IP list manager on the rules middleware
	rulesMiddleware.SetIPListManager(ipListMgr)
	log.Printf("[ip_list] Initialized IP list manager with %d list(s)", len(listsConfig))
}

// handleIPListConfigChange handles changes to IP list configuration during hot-reload
func (p *Manager) handleIPListConfigChange(newConfig *config.Config, rulesMiddleware *middleware.RulesMiddleware) {
	// Check if IP lists configuration exists and has changed
	hasIPLists := newConfig != nil && newConfig.IPLists != nil && len(*newConfig.IPLists) > 0

	p.mu.RLock()
	hadIPListManager := p.ipListManager != nil
	p.mu.RUnlock()

	// Case 1: IP lists were added (didn't have manager, now have config)
	if !hadIPListManager && hasIPLists {
		log.Printf("[ip_list] IP lists added to configuration, initializing manager")
		p.initializeIPListManager(newConfig, rulesMiddleware)
		return
	}

	// Case 2: IP lists were removed (had manager, now no config)
	if hadIPListManager && !hasIPLists {
		log.Printf("[ip_list] IP lists removed from configuration, stopping manager")
		p.mu.Lock()
		oldManager := p.ipListManager
		p.ipListManager = nil
		p.mu.Unlock()

		if oldManager != nil {
			oldManager.Stop()
		}
		rulesMiddleware.SetIPListManager(nil)
		return
	}

	// Case 3: IP lists were modified (had manager, still have config)
	if hadIPListManager && hasIPLists {
		log.Printf("[ip_list] IP lists configuration changed, reinitializing manager")
		p.initializeIPListManager(newConfig, rulesMiddleware)
		return
	}

	// Case 4: No IP lists before or after - nothing to do
}

// handleIPListUpdateEvent handles IP list updates triggered by WebSocket events
func (p *Manager) handleIPListUpdateEvent(listIDs []string) {
	p.mu.RLock()
	ipListMgr := p.ipListManager
	p.mu.RUnlock()

	if ipListMgr == nil {
		log.Printf("[ip_list] No IP list manager initialized, ignoring update event for lists: %v", listIDs)
		return
	}

	log.Printf("[ip_list] Processing update event for %d list(s): %v", len(listIDs), listIDs)

	for _, listID := range listIDs {
		if err := ipListMgr.RefreshListsByBaseID(listID); err != nil {
			log.Printf("[ip_list] Failed to refresh list %s: %v", listID, err)
		}
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
