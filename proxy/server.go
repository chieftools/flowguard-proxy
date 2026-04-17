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
	"strings"
	"sync"
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
	config          *ServerConfig
	httpServer      *http.Server
	listener        net.Listener
	serveOnce       sync.Once
	runner          firewallRunner
	interfaceLookup func(string) (string, error)
}

func NewServer(config *ServerConfig) *Server {
	return &Server{
		config:          config,
		runner:          execFirewallRunner{},
		interfaceLookup: getInterfaceForIP,
	}
}

func (s *Server) Start(tlsConfig *tls.Config, errChan chan<- error) error {
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
	listener, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("[%s:%s] %s server failed: %w", s.config.bindAddr, s.config.bindPort, s.config.scheme, err)
	}
	s.listener = listener

	go s.serve(tlsConfig, errChan)

	return nil
}

func (s *Server) serve(tlsConfig *tls.Config, errChan chan<- error) {
	listener := s.listener
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}

	if err := s.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errChan <- fmt.Errorf("[%s:%s] %s server failed: %w", s.config.bindAddr, s.config.bindPort, s.config.scheme, err)
	}
}

func (s *Server) CloseListener() error {
	if s.listener == nil {
		return nil
	}

	var err error
	s.serveOnce.Do(func() {
		err = s.listener.Close()
		s.listener = nil
	})

	if errors.Is(err, net.ErrClosed) {
		return nil
	}

	return err
}

func (s *Server) markListenerClosed() {
	s.serveOnce.Do(func() {
		s.listener = nil
	})
}

func (s *Server) resetListenerState() {
	s.listener = nil
	s.serveOnce = sync.Once{}
}

func (s *Server) Shutdown(ctx context.Context) {
	log.Printf("[%s:%s] Request received to shutdown server", s.config.bindAddr, s.config.bindPort)

	s.CleanupPortRedirect()

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("[%s:%s] Error shutting down server: %v", s.config.bindAddr, s.config.bindPort, err)
			if closeErr := s.CloseListener(); closeErr != nil {
				log.Printf("[%s:%s] Error closing listener: %v", s.config.bindAddr, s.config.bindPort, closeErr)
			}
		} else {
			s.markListenerClosed()
			log.Printf("[%s:%s] Proxy server stopped gracefully", s.config.bindAddr, s.config.bindPort)
		}
		s.httpServer = nil
		s.resetListenerState()
	} else {
		if err := s.CloseListener(); err != nil {
			log.Printf("[%s:%s] Error closing listener: %v", s.config.bindAddr, s.config.bindPort, err)
		}
		s.resetListenerState()
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

		req.Header.Set("FG-Stream", middleware.GetStreamID(req))
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
