package proxy

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"http-sec-proxy/certmanager"
	"http-sec-proxy/config"
	"http-sec-proxy/middleware"
)

type Config struct {
	Verbose    bool
	CertPath   string
	CacheDir   string
	HTTPPort   string
	HTTPSPort  string
	BindAddrs  []string
	UserAgent  string
	NoRedirect bool
	ConfigFile string
}

type Manager struct {
	config          *Config
	servers         []*Server
	configMgr       *config.Manager
	certManager     *certmanager.Manager
	middlewareChain *middleware.Chain
	ipLookup        *middleware.IPLookupMiddleware
	mu              sync.RWMutex
}

func NewManager(cfg *Config) *Manager {
	// Create configuration manager
	configMgr, err := config.NewManager(cfg.ConfigFile, cfg.UserAgent, cfg.CacheDir)
	if err != nil {
		log.Printf("Failed to load configuration from %s: %v", cfg.ConfigFile, err)
		os.Exit(1)
	}

	// Start config file watcher for hot-reload
	configMgr.StartWatcher(10 * time.Second)

	// Add IP enrichment middleware first to enrich all requests with IP/ASN data
	var ipLookup *middleware.IPLookupMiddleware
	ipLookup, err = middleware.NewIPLookupMiddleware(configMgr)
	if err != nil {
		log.Printf("Failed to initialize IP enrichment middleware: %v", err)
		os.Exit(1)
	}

	// Create middleware chain with config-based middleware
	middlewareChain := middleware.NewChain()

	// Add middlewares in order
	middlewareChain.Add(ipLookup)
	middlewareChain.Add(middleware.NewRulesMiddleware(configMgr))

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

	return &Manager{
		config:          cfg,
		ipLookup:        ipLookup,
		configMgr:       configMgr,
		certManager:     certmanager.New(cfg.CertPath),
		middlewareChain: middlewareChain,
	}
}

func (p *Manager) Start() error {
	trustedProxiesRefreshInterval := p.configMgr.GetRefreshInterval()
	log.Printf("Starting trusted proxy refresh with interval: %v", trustedProxiesRefreshInterval)

	// Periodically refresh trusted proxy lists from URLs
	go func() {
		ticker := time.NewTicker(trustedProxiesRefreshInterval)
		defer ticker.Stop()

		for range ticker.C {
			// Check if interval has changed in config
			newInterval := p.configMgr.GetRefreshInterval()
			if newInterval != trustedProxiesRefreshInterval {
				log.Printf("Refresh interval changed from %v to %v", trustedProxiesRefreshInterval, newInterval)
				ticker.Reset(newInterval)
				trustedProxiesRefreshInterval = newInterval
			}

			if err := p.configMgr.RefreshTrustedProxies(); err != nil {
				log.Printf("Failed to refresh trusted proxy lists: %v", err)
			}
		}
	}()

	ipDbRefreshInterval := p.configMgr.GetIPDatabaseRefreshInterval()
	log.Printf("Starting IP database refresh with interval: %v", ipDbRefreshInterval)

	// Periodically refresh IP database
	go func() {
		ticker := time.NewTicker(ipDbRefreshInterval)
		defer ticker.Stop()

		for range ticker.C {
			// Check if interval has changed in config
			newInterval := p.configMgr.GetIPDatabaseRefreshInterval()
			if newInterval != ipDbRefreshInterval {
				log.Printf("IP database refresh interval changed from %v to %v", ipDbRefreshInterval, newInterval)
				ticker.Reset(newInterval)
				ipDbRefreshInterval = newInterval
			}

			// Reload IP database (checks for updates)
			p.ipLookup.ReloadDatabase()
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
			scheme:       "http",
			verbose:      p.config.Verbose,
			bindAddr:     bindAddr,
			bindPort:     p.config.HTTPPort,
			redirPort:    httpRedirPort,
			middleware:   p.middlewareChain,
			serverHeader: p.config.UserAgent,
		})
		p.servers = append(p.servers, httpServer)

		httpsRedirPort := ""
		if !p.config.NoRedirect {
			httpsRedirPort = "443"
		}

		httpsServer := NewServer(&ServerConfig{
			scheme:       "https",
			verbose:      p.config.Verbose,
			bindAddr:     bindAddr,
			bindPort:     p.config.HTTPSPort,
			redirPort:    httpsRedirPort,
			middleware:   p.middlewareChain,
			serverHeader: p.config.UserAgent,
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

	// Stop config watcher if running
	p.configMgr.StopWatcher()

	// Small delay before we shutdown the servers
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

	// Close IP lookup database if open
	p.ipLookup.Close()

	// Shutdown certificate manager
	p.certManager.Stop()

	log.Println("Proxy server shutdown complete")
	return nil
}
