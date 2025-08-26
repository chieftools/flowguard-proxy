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
	configMgr       *config.Manager
	servers         []*Server
	certManager     *certmanager.Manager
	middlewareChain *middleware.Chain
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

	// Create middleware chain with config-based middleware
	middlewareChain := middleware.NewChain()
	rulesMiddleware := middleware.NewRulesMiddleware(configMgr)
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

	return &Manager{
		config:          cfg,
		configMgr:       configMgr,
		certManager:     certmanager.New(cfg.CertPath),
		middlewareChain: middlewareChain,
	}
}

func (p *Manager) Start() error {
	// Start trusted proxy refresh if using config manager
	if p.configMgr != nil {
		// Get refresh interval from config
		refreshInterval := p.configMgr.GetRefreshInterval()
		log.Printf("Starting trusted proxy refresh with interval: %v", refreshInterval)
		
		// Periodically refresh trusted proxy lists from URLs
		go func() {
			ticker := time.NewTicker(refreshInterval)
			defer ticker.Stop()

			for range ticker.C {
				// Check if interval has changed in config
				newInterval := p.configMgr.GetRefreshInterval()
				if newInterval != refreshInterval {
					log.Printf("Refresh interval changed from %v to %v", refreshInterval, newInterval)
					ticker.Reset(newInterval)
					refreshInterval = newInterval
				}
				
				if err := p.configMgr.RefreshTrustedProxies(); err != nil {
					log.Printf("Failed to refresh trusted proxy lists: %v", err)
				}
			}
		}()
	}

	errChan := make(chan error, len(p.config.BindAddrs)*2)

	// Create servers for each bind address
	for _, bindAddr := range p.config.BindAddrs {
		httpRedirPort := ""
		if !p.config.NoRedirect {
			httpRedirPort = "80"
		}

		httpServer := NewServer(&ServerConfig{
			scheme:       "http",
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

	// Stop config watcher if running
	if p.configMgr != nil {
		p.configMgr.StopWatcher()
	}

	// Remove the port redirection rules to stop new incoming connections
	for _, server := range p.servers {
		server.CleanupPortRedirect()
	}

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

	// Shutdown certificate manager
	if p.certManager != nil {
		p.certManager.Stop()
	}

	log.Println("Proxy server shutdown complete")
	return nil
}
