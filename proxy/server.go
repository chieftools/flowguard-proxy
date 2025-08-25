package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"time"

	"http-sec-proxy/middleware"
)

type ServerConfig struct {
	scheme       string
	bindAddr     string
	bindPort     string
	redirPort    string
	middleware   *middleware.Chain
	serverHeader string
}

type Server struct {
	config     *ServerConfig
	httpServer *http.Server
}

func NewServer(config *ServerConfig) *Server {
	return &Server{
		config: config,
	}
}

func (s *Server) Start(tlsConfig *tls.Config) error {
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%s", maybeFormatV6Addr(s.config.bindAddr), s.config.bindPort),
		Handler:      http.HandlerFunc(s.handleRequest),
		TLSConfig:    tlsConfig,
		ReadTimeout:  300 * time.Second,
		WriteTimeout: 300 * time.Second,
		IdleTimeout:  900 * time.Second,
	}

	log.Printf("[%s:%s] Starting %s proxy server", s.config.bindAddr, s.config.bindPort, s.config.scheme)
	if tlsConfig == nil {
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("[%s:%s] %s server failed: %w", s.config.bindAddr, s.config.bindPort, s.config.scheme, err)
		}
	} else {
		if err := s.httpServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("[%s:%s] %s server failed: %w", s.config.bindAddr, s.config.bindPort, s.config.scheme, err)
		}
	}

	return nil
}

func (s *Server) Shutdown(ctx context.Context) {
	log.Printf("[%s:%s] Request received to shutdown server", s.config.bindAddr, s.config.bindPort)

	s.CleanupPortRedirect()

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("[%s:%s] Error shutting down server: %v", s.config.bindAddr, s.config.bindPort, err)
		} else {
			s.httpServer = nil
			log.Printf("[%s:%s] Proxy server stopped gracefully", s.config.bindAddr, s.config.bindPort)
		}
	}
}

func (s *Server) SetupPortRedirect() error {
	// If no redirection port is set we can skip the setup
	if s.config.redirPort == "" {
		return nil
	}

	// Detect the interface for this IP
	iface, err := getInterfaceForIP(s.config.bindAddr)
	if err != nil {
		log.Printf("Warning: Could not detect interface for IP %s: %v", s.config.bindAddr, err)
		return err
	}

	// Determine if this is IPv6
	parsedIP := net.ParseIP(s.config.bindAddr)
	isIPv6 := parsedIP != nil && parsedIP.To4() == nil

	// Choose the correct iptables command
	iptablesCmd := "iptables"
	if isIPv6 {
		iptablesCmd = "ip6tables"
	}

	commands := [][]string{
		// INPUT rule to allow traffic to the redirection port
		{iptablesCmd, "-I", "INPUT", "-p", "tcp", "--dport", s.config.bindPort, "-j", "ACCEPT", "-m", "comment", "--comment", "HTTP Security Proxy"},
		// PREROUTING rule for external traffic - use DNAT for explicit destination
		{iptablesCmd, "-t", "nat", "-A", "PREROUTING", "-i", iface, "-d", s.config.bindAddr, "-p", "tcp", "--dport", s.config.redirPort, "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%s", maybeFormatV6Addr(s.config.bindAddr), s.config.bindPort)},
	}

	// Execute all commands
	for _, cmd := range commands {
		err = exec.Command(cmd[0], cmd[1:]...).Run()
		if err != nil {
			s.CleanupPortRedirect()
			return fmt.Errorf("failed to setup %s rules for %s:%s: %w", iptablesCmd, s.config.bindAddr, s.config.bindPort, err)
		}
	}

	log.Printf("[%s] redirection setup complete for %s:%s on interface %s", iptablesCmd, s.config.bindAddr, s.config.bindPort, iface)
	return nil
}

func (s *Server) CleanupPortRedirect() {
	// If no redirection port was set we can skip the cleanup
	if s.config.redirPort == "" {
		return
	}

	// Detect the interface for this IP
	iface, err := getInterfaceForIP(s.config.bindAddr)
	if err != nil {
		log.Printf("Warning: Could not detect interface for IP %s: %v", s.config.bindAddr, err)
		return
	}

	// Determine if this is IPv6
	parsedIP := net.ParseIP(s.config.bindAddr)
	isIPv6 := parsedIP != nil && parsedIP.To4() == nil

	// Choose the correct iptables command
	iptablesCmd := "iptables"
	if isIPv6 {
		iptablesCmd = "ip6tables"
	}

	commands := [][]string{
		// Remove PREROUTING rule
		{iptablesCmd, "-t", "nat", "-D", "PREROUTING", "-i", iface, "-d", s.config.bindAddr, "-p", "tcp", "--dport", s.config.redirPort, "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%s", maybeFormatV6Addr(s.config.bindAddr), s.config.bindPort)},
		// Remove INPUT rule
		{iptablesCmd, "-D", "INPUT", "-p", "tcp", "--dport", s.config.bindPort, "-j", "ACCEPT", "-m", "comment", "--comment", "HTTP Security Proxy"},
	}

	// Execute all commands
	for _, cmd := range commands {
		err = exec.Command(cmd[0], cmd[1:]...).Run()
		if err != nil {
			// We can ignore errors here as the rule might not exist
			return
		}
	}

	log.Printf("[%s] redirection cleanup complete for %s:%s", iptablesCmd, s.config.bindAddr, s.config.bindPort)
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Process through middleware chain
	if !s.config.middleware.Process(w, r) {
		// Request was denied by middleware
		return
	}

	// Create target URL that points to the actual backend server
	proxyTarget := &url.URL{
		Scheme: s.config.scheme,
		Host:   maybeFormatV6Addr(s.config.bindAddr),
	}

	proxyHost := r.Host
	if host, _, err := net.SplitHostPort(r.Host); err == nil {
		proxyHost = host
	}

	proxy := s.createReverseProxyWithHost(proxyTarget, proxyHost)
	proxy.ServeHTTP(w, r)
}

func (s *Server) createReverseProxyWithHost(target *url.URL, proxyHost string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)

	if target.Scheme == "https" {
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         proxyHost, // Use the original hostname for the TLS handshake
				InsecureSkipVerify: true,      // Skip verification as we're proxying to the same server
			},
		}
	}

	// Customize the director to preserve the original Host header
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Override the Host header to preserve the original one
		req.Host = proxyHost
		// Ensure URL points to the actual backend
		req.URL.Host = target.Host
		req.URL.Scheme = target.Scheme
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[%s:%s] proxy error for %s: %v", s.config.bindAddr, s.config.bindPort, proxyHost, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("Server", s.config.serverHeader)
		return nil
	}

	log.Printf("[%s:%s] routing request for %s", s.config.bindAddr, s.config.bindPort, proxyHost)

	return proxy
}
