package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"flowguard/middleware"
)

type ServerConfig struct {
	scheme     string
	verbose    bool
	bindAddr   string
	bindPort   string
	redirPort  string
	middleware *middleware.Chain
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
		ErrorLog:     newFilteredLogger(s.config.verbose),
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

	// Clean up any existing rules first (in case of previous crash)
	s.CleanupPortRedirect()

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
		{iptablesCmd, "-I", "INPUT", "-d", s.config.bindAddr, "-p", "tcp", "--dport", s.config.bindPort, "-j", "ACCEPT", "-m", "comment", "--comment", "FlowGuard"},
		// PREROUTING rule for external traffic - use DNAT for explicit destination
		{iptablesCmd, "-t", "nat", "-A", "PREROUTING", "-i", iface, "-d", s.config.bindAddr, "-p", "tcp", "--dport", s.config.redirPort, "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%s", maybeFormatV6Addr(s.config.bindAddr), s.config.bindPort), "-m", "comment", "--comment", "FlowGuard"},
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
		{iptablesCmd, "-t", "nat", "-D", "PREROUTING", "-i", iface, "-d", s.config.bindAddr, "-p", "tcp", "--dport", s.config.redirPort, "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%s", maybeFormatV6Addr(s.config.bindAddr), s.config.bindPort), "-m", "comment", "--comment", "FlowGuard"},
		// Remove INPUT rule
		{iptablesCmd, "-D", "INPUT", "-d", s.config.bindAddr, "-p", "tcp", "--dport", s.config.bindPort, "-j", "ACCEPT", "-m", "comment", "--comment", "FlowGuard"},
	}

	// Remove all instances of each rule (loop until deletion fails)
	totalRemoved := 0
	for _, cmd := range commands {
		removed := 0
		// Keep removing until we get an error (rule doesn't exist)
		for {
			err = exec.Command(cmd[0], cmd[1:]...).Run()
			if err != nil {
				// Rule doesn't exist anymore, move to next rule
				break
			}
			removed++
			totalRemoved++
		}
		if removed > 0 {
			log.Printf("[%s] removed %d instance(s) of rule: %v", iptablesCmd, removed, cmd[1:])
		}
	}

	if totalRemoved > 0 {
		log.Printf("[%s] redirection cleanup complete for %s:%s (%d rules removed)", iptablesCmd, s.config.bindAddr, s.config.bindPort, totalRemoved)
	}
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Create the proxy handler that will be called after middleware processing
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	})

	// Let the middleware chain handle the request with the proxy as the final handler
	s.config.middleware.ServeHTTPWithHandler(w, r, proxyHandler)
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
		if s.config.verbose || !strings.Contains(err.Error(), "context canceled") {
			log.Printf("[%s:%s] proxy error for %s: %v", s.config.bindAddr, s.config.bindPort, proxyHost, err)
		}

		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		// Remove headers we don't want to expose
		resp.Header.Del("Server")
		resp.Header.Del("X-Powered-By")

		// Remove duplicate headers with identical values
		for key, values := range resp.Header {
			if len(values) > 1 {
				// Create a map to track unique values while preserving order
				seen := make(map[string]bool)
				var unique []string

				for _, value := range values {
					if !seen[value] {
						seen[value] = true
						unique = append(unique, value)
					}
				}

				// Only update if we actually removed duplicates
				if len(unique) < len(values) {
					resp.Header[key] = unique
				}
			}
		}

		// Add Via header to indicate proxying and our stream ID
		resp.Header.Add("Via", fmt.Sprintf("%d.%d flowguard", resp.ProtoMajor, resp.ProtoMinor))
		resp.Header.Add("FG-Stream", middleware.GetStreamID(resp.Request))

		return nil
	}

	if s.config.verbose {
		log.Printf("[%s:%s] routing request for %s", s.config.bindAddr, s.config.bindPort, proxyHost)
	}

	return proxy
}

// filteredLogger wraps a logger and filters out TLS handshake errors when not in verbose mode
type filteredLogger struct {
	verbose bool
	logger  *log.Logger
}

func newFilteredLogger(verbose bool) *log.Logger {
	return log.New(&filteredLogger{
		verbose: verbose,
		logger:  log.Default(),
	}, "", 0)
}

var filteredMessageParts = []string{
	"received GOAWAY",
	"TLS handshake error",
	"error reading preface from client",
}

func (fl *filteredLogger) Write(p []byte) (n int, err error) {
	msg := string(p)

	// Only filter messages if not in verbose mode
	if !fl.verbose {
		// Check if the message contains any of the filtered parts
		for _, part := range filteredMessageParts {
			if strings.Contains(msg, part) {
				return len(p), nil // Pretend we wrote it but don't actually log
			}
		}
	}

	// Otherwise, pass through to the underlying logger
	return fl.logger.Writer().(io.Writer).Write(p)
}
