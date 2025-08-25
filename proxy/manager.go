package proxy

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"http-sec-proxy/certmanager"
	"http-sec-proxy/middleware"
)

type Config struct {
	CertPath            string
	HTTPPort            string
	HTTPSPort           string
	BindAddrs           []string
	NoRedirect          bool
	IPSetV4Name         string
	IPSetV6Name         string
	UserAgent           string
	TrustedProxyURLs    []string
	TrustedProxyRefresh time.Duration
}

type Manager struct {
	config          *Config
	servers         []*Server
	certManager     *certmanager.Manager
	middlewareChain *middleware.Chain
	trustedProxyMgr *middleware.TrustedProxyManager
	mu              sync.RWMutex
}

func NewManager(config *Config) *Manager {
	// Create IP filter
	ipFilter := middleware.NewIPFilter(config.IPSetV4Name, config.IPSetV6Name)

	// Create trusted proxy manager if URLs are provided
	var trustedProxyMgr *middleware.TrustedProxyManager
	if len(config.TrustedProxyURLs) > 0 {
		trustedProxyMgr = middleware.NewTrustedProxyManager(config.TrustedProxyURLs, config.TrustedProxyRefresh, config.UserAgent)
		ipFilter.SetTrustedProxyManager(trustedProxyMgr)
	}

	// Create middleware chain
	middlewareChain := middleware.NewChain()
	middlewareChain.Add(ipFilter)
	middlewareChain.Add(middleware.NewAgentFilter())

	// Determine bind addresses based on configuration
	bindAddrs := config.BindAddrs
	if len(bindAddrs) == 0 {
		// Default: Get all public IP addresses on the machine
		publicIPs, err := getPublicIPAddresses()
		if err != nil {
			log.Printf("Failed to get public IPs: %v", err)
			os.Exit(1)
		}

		log.Printf("Auto-detected %d public IP address(es) for binding", len(publicIPs))
		config.BindAddrs = publicIPs
	}

	return &Manager{
		config:          config,
		certManager:     certmanager.New(config.CertPath),
		middlewareChain: middlewareChain,
		trustedProxyMgr: trustedProxyMgr,
	}
}

func (p *Manager) Start() error {
	// Start trusted proxy manager if configured
	if p.trustedProxyMgr != nil {
		if err := p.trustedProxyMgr.Start(); err != nil {
			return err
		}
		log.Println("Trusted proxy manager started")
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

	// Stop trusted proxy manager if running
	if p.trustedProxyMgr != nil {
		p.trustedProxyMgr.Stop()
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
