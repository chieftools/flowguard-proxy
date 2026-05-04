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

	"flowguard/config"
	"flowguard/fingerprint"
	"flowguard/middleware"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Server struct {
	config          *ServerConfig
	runner          firewallRunner
	udpConn         net.PacketConn
	udpOnce         sync.Once
	listener        net.Listener
	httpServer      *http.Server
	http3Server     *http3.Server
	listenerOnce    sync.Once
	fingerprints    *fingerprint.Store
	interfaceLookup func(string) (string, error)
}

type ServerConfig struct {
	scheme     string
	altSvc     bool
	verbose    bool
	bindAddr   string
	bindPort   string
	redirPort  string
	protocols  *config.ProtocolSettings
	middleware *middleware.Chain
}

func NewServer(config *ServerConfig) *Server {
	return &Server{
		config:          config,
		runner:          execFirewallRunner{},
		fingerprints:    fingerprint.NewStore(),
		interfaceLookup: getInterfaceForIP,
	}
}

func (s *Server) serve(server *http.Server, listener net.Listener, tlsConfig *tls.Config, errChan chan<- error) {
	if tlsConfig != nil {
		listener = ja4Listener{Listener: listener}
		listener = tls.NewListener(listener, tlsConfig)
	}

	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errChan <- fmt.Errorf("[%s:%s] %s server failed: %w", s.config.bindAddr, s.config.bindPort, s.config.scheme, err)
	}
}

func (s *Server) serveHTTP3(server *http3.Server, conn net.PacketConn, errChan chan<- error) {
	if err := server.Serve(conn); err != nil &&
		!errors.Is(err, http.ErrServerClosed) &&
		!errors.Is(err, net.ErrClosed) {
		errChan <- fmt.Errorf("[%s:%s] http/3 server failed: %w", s.config.bindAddr, s.config.bindPort, err)
	}
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	r = s.withJA4Fingerprint(r)

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

func (s *Server) withJA4Fingerprint(r *http.Request) *http.Request {
	if middleware.GetJA4Fingerprint(r) != "" {
		return r
	}

	if conn, ok := r.Context().Value(ja4ConnContextKey{}).(*ja4Conn); ok {
		if ja4 := conn.JA4(); ja4 != "" {
			return middleware.WithJA4Fingerprint(r, ja4)
		}
	}

	localAddr, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if localAddr == nil {
		return r
	}

	if ja4 := s.fingerprints.Get(localAddr.String(), r.RemoteAddr); ja4 != "" {
		return middleware.WithJA4Fingerprint(r, ja4)
	}

	return r
}

func (s *Server) markListenerClosed() {
	s.listenerOnce.Do(func() {
		s.listener = nil
	})
}

func (s *Server) resetListenerState() {
	s.listener = nil
	s.udpConn = nil
	s.listenerOnce = sync.Once{}
	s.udpOnce = sync.Once{}
}

func (s *Server) createReverseProxyWithHost(target *url.URL, proxyHost string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)

	if target.Scheme == "https" {
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         proxyHost, // Use the original hostname for the TLS handshake
				InsecureSkipVerify: true,      // Skip verification as we're proxying to the same server
			},
			ForceAttemptHTTP2: true,
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

		s.addAltSvcHeader(resp)

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

func (s *Server) addAltSvcHeader(resp *http.Response) {
	if !s.shouldAdvertiseHTTP3AltSvc() {
		return
	}

	addAltSvcValue(resp.Header, fmt.Sprintf(`h3=":%s"; ma=86400`, s.config.publicHTTPSPort()))
}

func (s *Server) shouldAdvertiseHTTP3AltSvc() bool {
	return s.config.scheme == "https" && s.config.altSvc && s.config.resolvedProtocols().HTTP3
}

func (c *ServerConfig) publicHTTPSPort() string {
	if c.redirPort != "" {
		return c.redirPort
	}

	return c.bindPort
}

func (s *Server) Start(tlsConfig *tls.Config, errChan chan<- error) error {
	addr := fmt.Sprintf("%s:%s", maybeFormatV6Addr(s.config.bindAddr), s.config.bindPort)
	protocols := s.config.resolvedProtocols()
	tcpEnabled := protocols.HTTP1 || (tlsConfig != nil && protocols.HTTP2)
	udpEnabled := tlsConfig != nil && protocols.HTTP3
	tcpTLSConfig := s.tlsConfigWithJA4(tlsConfig, "t")

	if !tcpEnabled && !udpEnabled {
		return fmt.Errorf("[%s:%s] %s server has no enabled protocols", s.config.bindAddr, s.config.bindPort, s.config.scheme)
	}

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      http.HandlerFunc(s.handleRequest),
		ErrorLog:     newFilteredLogger(s.config.verbose),
		TLSConfig:    tcpTLSConfig,
		Protocols:    httpServerProtocols(protocols, tcpTLSConfig != nil),
		ConnContext:  s.tcpConnContext,
		ReadTimeout:  300 * time.Second,
		IdleTimeout:  900 * time.Second,
		WriteTimeout: 300 * time.Second,
	}

	log.Printf("[%s:%s] Starting %s proxy server", s.config.bindAddr, s.config.bindPort, s.config.scheme)

	if tcpEnabled {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("[%s:%s] %s server failed: %w", s.config.bindAddr, s.config.bindPort, s.config.scheme, err)
		}

		s.listener = listener

		go s.serve(s.httpServer, listener, tcpTLSConfig, errChan)
	}

	if udpEnabled {
		udpConn, err := net.ListenPacket("udp", addr)
		if err != nil {
			if closeErr := s.CloseListener(); closeErr != nil {
				log.Printf("[%s:%s] Error closing listener after HTTP/3 bind failure: %v", s.config.bindAddr, s.config.bindPort, closeErr)
			}

			s.resetListenerState()

			return fmt.Errorf("[%s:%s] http/3 server failed: %w", s.config.bindAddr, s.config.bindPort, err)
		}

		s.udpConn = udpConn
		s.http3Server = &http3.Server{
			Addr:        addr,
			Handler:     http.HandlerFunc(s.handleRequest),
			TLSConfig:   http3.ConfigureTLSConfig(s.tlsConfigWithJA4(tlsConfig, "q")),
			QUICConfig:  &quic.Config{},
			IdleTimeout: 900 * time.Second,
			ConnContext: s.http3ConnContext,
		}

		go s.serveHTTP3(s.http3Server, s.udpConn, errChan)
	}

	return nil
}

func (s *Server) tlsConfigWithJA4(tlsConfig *tls.Config, transport string) *tls.Config {
	if tlsConfig == nil {
		return nil
	}

	cfg := tlsConfig.Clone()
	getConfigForClient := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		s.recordJA4Fingerprint(hello, transport)
		if getConfigForClient == nil {
			return nil, nil
		}
		return getConfigForClient(hello)
	}

	return cfg
}

func (s *Server) recordJA4Fingerprint(hello *tls.ClientHelloInfo, transport string) {
	if hello == nil || hello.Conn == nil {
		return
	}

	ja4 := fingerprint.JA4FromClientHello(hello, transport)
	if ja4 == "" {
		return
	}

	if conn, ok := hello.Conn.(*ja4Conn); ok {
		conn.SetJA4(ja4)
		return
	}

	s.fingerprints.Set(hello.Conn.LocalAddr().String(), hello.Conn.RemoteAddr().String(), ja4)
}

func (s *Server) tcpConnContext(ctx context.Context, conn net.Conn) context.Context {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}

	if ja4Conn, ok := conn.(*ja4Conn); ok {
		return context.WithValue(ctx, ja4ConnContextKey{}, ja4Conn)
	}

	return ctx
}

func (s *Server) http3ConnContext(ctx context.Context, conn *quic.Conn) context.Context {
	if conn == nil {
		return ctx
	}

	localAddr := conn.LocalAddr().String()
	remoteAddr := conn.RemoteAddr().String()
	ja4 := s.fingerprints.Get(localAddr, remoteAddr)
	if ja4 == "" {
		return ctx
	}

	go func() {
		<-conn.Context().Done()
		s.fingerprints.Delete(localAddr, remoteAddr)
	}()

	return middleware.ContextWithJA4Fingerprint(ctx, ja4)
}

func (s *Server) Shutdown(ctx context.Context) {
	log.Printf("[%s:%s] Request received to shutdown server", s.config.bindAddr, s.config.bindPort)

	s.CleanupPortRedirect()

	if s.http3Server != nil {
		if err := s.http3Server.Shutdown(ctx); err != nil {
			log.Printf("[%s:%s] Error shutting down HTTP/3 server: %v", s.config.bindAddr, s.config.bindPort, err)
			if closeErr := s.http3Server.Close(); closeErr != nil {
				log.Printf("[%s:%s] Error closing HTTP/3 server: %v", s.config.bindAddr, s.config.bindPort, closeErr)
			}
		}
		s.http3Server = nil
	}

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("[%s:%s] Error shutting down server: %v", s.config.bindAddr, s.config.bindPort, err)
			if closeErr := s.CloseListener(); closeErr != nil {
				log.Printf("[%s:%s] Error closing listener: %v", s.config.bindAddr, s.config.bindPort, closeErr)
			}
		} else {
			s.markListenerClosed()
			log.Printf("[%s:%s] Proxy server stopped gracefully", s.config.bindAddr, s.config.bindPort)
			if closeErr := s.CloseListener(); closeErr != nil {
				log.Printf("[%s:%s] Error closing listener: %v", s.config.bindAddr, s.config.bindPort, closeErr)
			}
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

func (s *Server) CloseListener() error {
	var closeErr error

	s.listenerOnce.Do(func() {
		if s.listener != nil {
			if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				closeErr = errors.Join(closeErr, err)
			}
			s.listener = nil
		}
	})

	s.udpOnce.Do(func() {
		if s.udpConn != nil {
			if err := s.udpConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				closeErr = errors.Join(closeErr, err)
			}
			s.udpConn = nil
		}
	})

	return closeErr
}

func (c *ServerConfig) resolvedProtocols() config.ProtocolSettings {
	if c.protocols != nil {
		return *c.protocols
	}

	return config.DefaultProtocolSettings()
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
