package proxy

import (
	"context"
	"fmt"
	"log"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.chief.tools/flowguard-proxy/api"
	"go.chief.tools/flowguard-proxy/certmanager"
	"go.chief.tools/flowguard-proxy/config"
	"go.chief.tools/flowguard-proxy/engine"
	"go.chief.tools/flowguard-proxy/fail2ban"
	"go.chief.tools/flowguard-proxy/middleware"
	"go.chief.tools/flowguard-proxy/systemdnotify"
	"go.chief.tools/flowguard-proxy/updater"
)

// DefaultShutdownTimeout is how long servers drain in-flight requests on
// shutdown when Config.ShutdownTimeout is not set.
const DefaultShutdownTimeout = 10 * time.Second

type Config struct {
	Verbose              bool
	Version              string
	HTTPPort             string
	HTTPSPort            string
	BindAddrs            []string
	UserAgent            string
	Protocols            config.ProtocolSettings
	NoRedirect           bool
	AdvertiseHTTP3       bool
	UpstreamClientIPMode string
	Updater              *updater.Updater
	// Fail2Ban replaces the default Fail2Ban manager, mainly for tests.
	Fail2Ban *fail2ban.Manager
	// ShutdownTimeout is how long servers drain in-flight requests before
	// remaining connections, including WebSockets, are closed.
	ShutdownTimeout time.Duration
}

type Manager struct {
	config                 *Config
	servers                []*Server
	updater                *updater.Updater
	engine                 *engine.Engine
	certManager            *certmanager.Manager
	configManager          *config.Manager
	firewallState          api.FirewallHeartbeat
	middlewareChain        *middleware.Chain
	upstreamMode           string
	upstreamModeOverride   string
	upstreamSettings       config.TransparentUpstreamSettings
	addressPairs           AddressPairResolution
	transparentPool        *transparentTransportPool
	transparentNet         *transparentNetworkManager
	upstreamHeaderSettings *atomic.Pointer[config.UpstreamHeaderSettings]

	serveErrChan        chan error
	stopFirewallMonitor chan struct{}

	mu       sync.RWMutex
	serverMu sync.Mutex
}

func NewManager(configMgr *config.Manager, cfg *Config) (*Manager, error) {
	// The heartbeat reads the manager's state, which exists only after the
	// manager is built below.
	var pm *Manager
	flowguard := engine.New(configMgr, engine.Options{
		Verbose:  cfg.Verbose,
		Version:  cfg.Version,
		Fail2Ban: cfg.Fail2Ban,
		Heartbeat: func() engine.HeartbeatDetails {
			return pm.heartbeatDetails()
		},
	})

	// Determine bind addresses based on configuration
	autoDetectedBindAddrs := len(cfg.BindAddrs) == 0
	if autoDetectedBindAddrs {
		// Default: Get all public IP addresses on the machine
		publicIPs, err := getPublicIPAddresses(cfg.Verbose)
		if err != nil {
			log.Printf("[network] Failed to get public IPs: %v", err)
			os.Exit(1)
		}

		cfg.BindAddrs = publicIPs
	}
	log.Printf("[network] %s", formatBindAddresses(cfg.BindAddrs, autoDetectedBindAddrs))

	// Get certificate paths from both CLI config and JSON config
	certPath := ""
	acmePath := ""
	nginxConfigPath := ""

	// Also check JSON config for cert/nginx paths (JSON config can override CLI)
	if jsonCfg := configMgr.GetConfig(); jsonCfg != nil && jsonCfg.Host != nil {
		if jsonCfg.Host.CertPath != "" {
			certPath = jsonCfg.Host.CertPath
		}
		if jsonCfg.Host.ACMEPath != "" {
			acmePath = jsonCfg.Host.ACMEPath
		}
		if jsonCfg.Host.NginxConfigPath != "" {
			nginxConfigPath = jsonCfg.Host.NginxConfigPath
		}
	}

	defaultHostname := ""
	if configMgr.GetConfig().Host != nil {
		defaultHostname = configMgr.GetConfig().Host.DefaultHostname
	}
	protocols := configMgr.GetConfig().ProtocolSettings()
	cfg.Protocols = protocols
	cfg.AdvertiseHTTP3 = configMgr.GetConfig().AdvertiseHTTP3()
	upstreamMode, err := resolveUpstreamClientIPMode(
		configMgr.GetConfig().UpstreamClientIPMode(),
		cfg.UpstreamClientIPMode,
	)
	if err != nil {
		return nil, err
	}
	upstreamSettings := configMgr.GetConfig().TransparentUpstreamSettings()
	var addressPairs AddressPairResolution
	var transparentPool *transparentTransportPool
	var transparentNet *transparentNetworkManager
	if upstreamMode == config.UpstreamClientIPModeTransparent {
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("server.upstream.client_ip_mode=%q is supported only on Linux", upstreamMode)
		}
		resolvedPairs, resolveErr := ResolveAddressPairs(configMgr.GetConfig(), cfg.BindAddrs)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve transparent upstream address pairs: %w", resolveErr)
		}
		addressPairs = resolvedPairs
		if !addressPairs.Complete() {
			return nil, fmt.Errorf("transparent upstream address pairing is ambiguous for: %s", strings.Join(addressPairs.Unresolved, ", "))
		}
		transparentPool = newTransparentTransportPool(
			upstreamSettings.MaxClientPools,
			time.Duration(upstreamSettings.PoolIdleSeconds)*time.Second,
			upstreamSettings.FWMark,
		)
		transparentNet = newTransparentNetworkManager(upstreamSettings, cfg.BindAddrs)
	}

	pm = &Manager{
		config:                 cfg,
		engine:                 flowguard,
		configManager:          configMgr,
		middlewareChain:        flowguard.Chain(),
		upstreamMode:           upstreamMode,
		upstreamModeOverride:   cfg.UpstreamClientIPMode,
		upstreamSettings:       upstreamSettings,
		addressPairs:           addressPairs,
		transparentPool:        transparentPool,
		transparentNet:         transparentNet,
		upstreamHeaderSettings: &atomic.Pointer[config.UpstreamHeaderSettings]{},

		certManager: certmanager.New(certmanager.Config{
			Verbose:         cfg.Verbose,
			CertPath:        certPath,
			ACMEPath:        acmePath,
			TLSNextProtos:   tlsNextProtos(protocols),
			NginxConfigPath: nginxConfigPath,
			DefaultHostname: defaultHostname,
		}),

		serveErrChan:        make(chan error, max(1, len(cfg.BindAddrs)*2)),
		stopFirewallMonitor: make(chan struct{}),
	}
	pm.setUpstreamHeaderSettings(configMgr.GetConfig().UpstreamHeaderSettings())

	// Register callback to handle server configuration changes
	configMgr.OnChange(func(newConfig *config.Config) {
		pm.handleServerConfigChange(newConfig)
		pm.setUpstreamHeaderSettings(newConfig.UpstreamHeaderSettings())
	})

	// Initialize updater for remote package upgrades (non-fatal if detection fails)
	cacheDir := ""
	if configMgr.GetConfig().Host != nil && configMgr.GetConfig().Host.CacheDir != "" {
		cacheDir = configMgr.GetConfig().Host.CacheDir
	}
	if cacheDir == "" {
		cacheDir = "/var/cache/flowguard"
	}
	u := cfg.Updater
	if u == nil {
		u, err = updater.New(cfg.Version, cacheDir, cfg.Verbose)
	}
	if err != nil {
		log.Printf("[updater] Package upgrades unavailable: %v", err)
	} else if u != nil {
		pm.updater = u
		configMgr.OnUpgradeRequest(func(version string) {
			pm.handleUpgradeRequest(version)
		})
	}

	if err := pm.validateCertificateSources(certPath, acmePath, nginxConfigPath); err != nil {
		pm.certManager.Stop()
		pm.engine.StopChain()
		return nil, err
	}

	return pm, nil
}

func (p *Manager) validateCertificateSources(certPath, acmePath, nginxConfigPath string) error {
	if p.certManager.HostnameCount() > 0 {
		return nil
	}

	if nginxConfigPath != "" && p.certManager.NginxConfigLoaded() {
		log.Printf("[cert_manager] No certificates loaded, but readable NGINX config %s was found; allowing proxy startup", nginxConfigPath)
		return nil
	}

	if certPath != "" {
		return fmt.Errorf("no valid certificates found in cert_path=%q", certPath)
	}

	if acmePath != "" {
		return fmt.Errorf("no valid certificates found in acme_path=%q", acmePath)
	}

	if nginxConfigPath != "" {
		return fmt.Errorf("no valid certificates found and nginx_config_path=%q could not be read", nginxConfigPath)
	}

	return fmt.Errorf("no certificate sources configured")
}

func (p *Manager) setUpstreamHeaderSettings(settings config.UpstreamHeaderSettings) {
	p.upstreamHeaderSettings.Store(&settings)
}

func (p *Manager) handleServerConfigChange(newConfig *config.Config) {
	if newConfig == nil {
		return
	}

	newProtocols := newConfig.ProtocolSettings()
	newAdvertiseHTTP3 := newConfig.AdvertiseHTTP3()
	newUpstreamMode, err := resolveUpstreamClientIPMode(newConfig.UpstreamClientIPMode(), p.upstreamModeOverride)
	if err != nil {
		log.Printf("[server] Invalid upstream client IP mode override: %v", err)
		return
	}
	newUpstreamSettings := newConfig.TransparentUpstreamSettings()
	if newUpstreamMode != p.upstreamMode || !reflect.DeepEqual(newUpstreamSettings, p.upstreamSettings) {
		log.Printf("[server] Upstream client IP settings changed; restart FlowGuard to apply them")
	}

	p.serverMu.Lock()
	defer p.serverMu.Unlock()

	oldProtocols := p.config.resolvedProtocols()
	oldAdvertiseHTTP3 := p.config.AdvertiseHTTP3
	if oldProtocols == newProtocols && oldAdvertiseHTTP3 == newAdvertiseHTTP3 {
		return
	}

	oldServers := p.servers
	log.Printf("[server] Server configuration changed, restarting listeners")

	p.stopServers(oldServers)
	p.servers = nil

	newServers, err := p.startServers(newProtocols, newAdvertiseHTTP3)
	if err != nil {
		log.Printf("[server] Failed to restart listeners with new server configuration: %v", err)
		p.stopServers(newServers)

		rollbackServers, rollbackErr := p.startServers(oldProtocols, oldAdvertiseHTTP3)
		if rollbackErr != nil {
			log.Printf("[server] Failed to roll back to previous server configuration: %v", rollbackErr)
			p.config.Protocols = oldProtocols
			p.config.AdvertiseHTTP3 = oldAdvertiseHTTP3
			p.servers = nil
			return
		}

		p.config.Protocols = oldProtocols
		p.config.AdvertiseHTTP3 = oldAdvertiseHTTP3
		p.servers = rollbackServers
		if err := p.setupPortRedirectsLocked(); err != nil {
			log.Printf("[server] Failed to restore port redirection after rollback: %v", err)
		}
		return
	}

	p.config.Protocols = newProtocols
	p.config.AdvertiseHTTP3 = newAdvertiseHTTP3
	p.servers = newServers
	if err := p.setupPortRedirectsLocked(); err != nil {
		log.Printf("[server] Failed to refresh port redirection after server configuration change: %v", err)
	}
}

func resolveUpstreamClientIPMode(configured, override string) (string, error) {
	mode := configured
	if override != "" {
		mode = override
	}
	if mode != config.UpstreamClientIPModeHeaders && mode != config.UpstreamClientIPModeTransparent {
		return "", fmt.Errorf("upstream client IP mode must be %q or %q", config.UpstreamClientIPModeHeaders, config.UpstreamClientIPModeTransparent)
	}
	return mode, nil
}

func formatBindAddresses(addresses []string, autoDetected bool) string {
	source := "configured"
	if autoDetected {
		source = "auto-detected"
	}

	return fmt.Sprintf("Bind addresses (%d, %s): %s", len(addresses), source, strings.Join(addresses, ", "))
}

func (p *Manager) stopServers(servers []*Server) {
	if len(servers) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.shutdownTimeout())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(len(servers))
	for _, server := range servers {
		go func(srv *Server) {
			defer wg.Done()
			srv.Shutdown(ctx)
		}(server)
	}
	wg.Wait()
}

func (p *Manager) shutdownTimeout() time.Duration {
	if p.config.ShutdownTimeout > 0 {
		return p.config.ShutdownTimeout
	}

	return DefaultShutdownTimeout
}

// handleUpgradeRequest processes an upgrade request from the WebSocket channel.
func (p *Manager) handleUpgradeRequest(version string) {
	p.mu.RLock()
	u := p.updater
	p.mu.RUnlock()

	if u == nil {
		log.Printf("[updater] No updater available, ignoring upgrade request for version %s", version)
		return
	}

	go func() {
		if err := u.Upgrade(updater.UpgradeRequest{Version: version}); err != nil {
			log.Printf("[updater] Upgrade to version %s failed: %v", version, err)
		}
	}()
}

func (p *Manager) managesRedirect() bool {
	return !p.config.NoRedirect
}

func (p *Manager) managesFirewall() bool {
	return p.managesRedirect() || p.transparentNet != nil
}

func (p *Manager) firewallMonitorSettings() (enabled bool, autoRepair bool, interval time.Duration) {
	const defaultInterval = 30 * time.Second

	if !p.managesFirewall() {
		return false, false, defaultInterval
	}

	enabled = true
	autoRepair = true
	interval = defaultInterval

	cfg := p.configManager.GetConfig()
	if cfg != nil && cfg.Firewall != nil {
		if cfg.Firewall.MonitorEnabled != nil {
			enabled = *cfg.Firewall.MonitorEnabled
		}
		if cfg.Firewall.AutoRepair != nil {
			autoRepair = *cfg.Firewall.AutoRepair
		}
		if cfg.Firewall.CheckIntervalSeconds > 0 {
			interval = time.Duration(cfg.Firewall.CheckIntervalSeconds) * time.Second
		}
	}

	if interval < 5*time.Second {
		interval = 5 * time.Second
	}

	return enabled, autoRepair, interval
}

func (p *Manager) setInitialFirewallState(state api.FirewallHeartbeat) {
	p.mu.Lock()
	p.firewallState = state
	p.mu.Unlock()
}

func (p *Manager) getFirewallState() api.FirewallHeartbeat {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.firewallState
}

func (p *Manager) updateFirewallState(next api.FirewallHeartbeat) {
	p.mu.Lock()
	prev := p.firewallState
	if next.LastRepairedAt == 0 {
		next.LastRepairedAt = prev.LastRepairedAt
	}
	p.firewallState = next
	p.mu.Unlock()

	if prev.Status == next.Status {
		return
	}

	log.Printf("[firewall] State changed from %q to %q", prev.Status, next.Status)
	if err := systemdnotify.NotifyStatus(p.statusMessageFromState(next)); err != nil && p.config.Verbose {
		log.Printf("[systemd] Failed to update status: %v", err)
	}
	p.requestImmediateHeartbeat()
}

func (p *Manager) requestImmediateHeartbeat() {
	if p.engine != nil {
		p.engine.RequestHeartbeat()
	}
}

func (p *Manager) heartbeatDetails() engine.HeartbeatDetails {
	return engine.HeartbeatDetails{
		Firewall:      p.getFirewallState(),
		HostnameCount: p.certManager.HostnameCount(),
		BindAddresses: p.config.BindAddrs,
	}
}

func (p *Manager) statusMessageFromState(state api.FirewallHeartbeat) string {
	switch state.Status {
	case firewallStatusDisabled:
		return "FlowGuard running; firewall redirect management disabled"
	case firewallStatusDegraded:
		if state.MissingRuleCount > 0 {
			return fmt.Sprintf("FlowGuard running; firewall degraded (%d missing redirect rules)", state.MissingRuleCount)
		}
		if state.LastError != "" {
			return fmt.Sprintf("FlowGuard running; firewall degraded (%s)", state.LastError)
		}
		return "FlowGuard running; firewall degraded"
	default:
		return "FlowGuard running; firewall healthy"
	}
}

func (p *Manager) initialFirewallState() api.FirewallHeartbeat {
	if !p.managesFirewall() {
		return api.FirewallHeartbeat{Status: firewallStatusDisabled}
	}

	return api.FirewallHeartbeat{
		Status:        firewallStatusHealthy,
		LastCheckedAt: time.Now().Unix(),
	}
}

func (p *Manager) setupPortRedirects() error {
	p.serverMu.Lock()
	defer p.serverMu.Unlock()

	return p.setupPortRedirectsLocked()
}

func (p *Manager) setupPortRedirectsLocked() error {
	if !p.managesRedirect() {
		return nil
	}

	for _, server := range p.servers {
		if err := server.SetupPortRedirect(); err != nil {
			return fmt.Errorf("failed to setup port redirection for %s:%s: %w", server.config.bindAddr, server.config.bindPort, err)
		}
	}

	return nil
}

func (p *Manager) evaluateFirewall(autoRepair bool) api.FirewallHeartbeat {
	p.serverMu.Lock()
	defer p.serverMu.Unlock()

	state := api.FirewallHeartbeat{
		Status:        firewallStatusHealthy,
		LastCheckedAt: time.Now().Unix(),
	}

	if !p.managesFirewall() {
		state.Status = firewallStatusDisabled
		return state
	}

	totalMissing := 0
	lastError := ""
	repairError := ""
	repairedAt := int64(0)

	checkServers := func(repair bool) {
		if p.managesRedirect() {
			for _, server := range p.servers {
				missing, err := server.CheckPortRedirect()
				if err != nil {
					lastError = err.Error()
					if totalMissing == 0 {
						totalMissing = 1
					}
					continue
				}

				totalMissing += len(missing)
				if len(missing) == 0 || !repair {
					continue
				}

				log.Printf("[firewall] Detected %d missing redirect rule(s) for %s:%s, attempting repair", len(missing), server.config.bindAddr, server.config.bindPort)
				if err := server.RepairPortRedirect(missing); err != nil {
					lastError = err.Error()
					repairError = lastError
					continue
				}

				repairedAt = time.Now().Unix()
			}
		}

		if p.transparentNet != nil {
			missing, err := p.transparentNet.Check()
			if err != nil {
				lastError = err.Error()
				if totalMissing == 0 {
					totalMissing = 1
				}
				return
			}
			totalMissing += len(missing)
			if len(missing) > 0 && repair {
				log.Printf("[firewall] Detected %d missing transparent upstream resource(s), attempting repair", len(missing))
				if err := p.transparentNet.Repair(); err != nil {
					lastError = err.Error()
					repairError = lastError
					return
				}
				repairedAt = time.Now().Unix()
			}
		}
	}

	checkServers(autoRepair)

	if autoRepair && totalMissing > 0 {
		totalMissing = 0
		lastError = ""
		checkServers(false)
		if lastError == "" {
			lastError = repairError
		}
	}

	state.MissingRuleCount = totalMissing
	state.LastError = lastError
	state.LastRepairedAt = repairedAt

	if totalMissing > 0 || lastError != "" {
		state.Status = firewallStatusDegraded
	}

	return state
}

func (p *Manager) runFirewallMonitor() {
	if p.config.Verbose {
		log.Println("[firewall] Monitor started")
	}

	for {
		enabled, autoRepair, interval := p.firewallMonitorSettings()
		if !enabled {
			timer := time.NewTimer(interval)
			select {
			case <-p.stopFirewallMonitor:
				timer.Stop()
				if p.config.Verbose {
					log.Println("[firewall] Monitor stopped")
				}
				return
			case <-timer.C:
				continue
			}
		}

		timer := time.NewTimer(interval)
		select {
		case <-p.stopFirewallMonitor:
			timer.Stop()
			if p.config.Verbose {
				log.Println("[firewall] Monitor stopped")
			}
			return
		case <-timer.C:
			p.updateFirewallState(p.evaluateFirewall(autoRepair))
		}
	}
}

func (p *Manager) startServers(protocols config.ProtocolSettings, advertiseHTTP3 bool) ([]*Server, error) {
	started := make([]*Server, 0, len(p.config.BindAddrs)*2)

	for _, bindAddr := range p.config.BindAddrs {
		if protocols.HTTP1 {
			httpRedirPort := ""
			if !p.config.NoRedirect {
				httpRedirPort = "80"
			}

			httpServer := NewServer(&ServerConfig{
				scheme:          "http",
				altSvc:          advertiseHTTP3,
				verbose:         p.config.Verbose,
				bindAddr:        bindAddr,
				bindPort:        p.config.HTTPPort,
				redirPort:       httpRedirPort,
				protocols:       &protocols,
				middleware:      p.middlewareChain,
				transparentPool: p.transparentPool,
				addressPairs:    p.addressPairs,
				upstreamHeaders: p.upstreamHeaderSettings,
				loadBalancer:    p.configManager.IsProxyProtocolPeer,
			})
			started = append(started, httpServer)

			if err := httpServer.Start(nil, p.serveErrChan); err != nil {
				return started, err
			}
		}

		httpsRedirPort := ""
		if !p.config.NoRedirect {
			httpsRedirPort = "443"
		}

		httpsServer := NewServer(&ServerConfig{
			scheme:          "https",
			altSvc:          advertiseHTTP3,
			verbose:         p.config.Verbose,
			bindAddr:        bindAddr,
			bindPort:        p.config.HTTPSPort,
			redirPort:       httpsRedirPort,
			protocols:       &protocols,
			middleware:      p.middlewareChain,
			transparentPool: p.transparentPool,
			addressPairs:    p.addressPairs,
			upstreamHeaders: p.upstreamHeaderSettings,
			loadBalancer:    p.configManager.IsProxyProtocolPeer,
		})
		started = append(started, httpsServer)

		tlsConfig := p.certManager.GetTlsConfig()
		tlsConfig.NextProtos = tlsNextProtos(protocols)
		if err := httpsServer.Start(tlsConfig, p.serveErrChan); err != nil {
			return started, err
		}
	}

	return started, nil
}

func formatProxyStartupSummary(servers []*Server, bindAddressCount int) string {
	httpEndpoints := 0
	httpsEndpoints := 0
	for _, server := range servers {
		if server == nil || server.config == nil {
			continue
		}
		switch server.config.scheme {
		case "http":
			httpEndpoints++
		case "https":
			httpsEndpoints++
		}
	}

	details := make([]string, 0, 2)
	if httpEndpoints > 0 {
		details = append(details, fmt.Sprintf("%d HTTP", httpEndpoints))
	}
	if httpsEndpoints > 0 {
		details = append(details, fmt.Sprintf("%d HTTPS", httpsEndpoints))
	}

	endpointLabel := "endpoints"
	if len(servers) == 1 {
		endpointLabel = "endpoint"
	}
	addressLabel := "addresses"
	if bindAddressCount == 1 {
		addressLabel = "address"
	}

	return fmt.Sprintf(
		"Started %d proxy %s across %d bind %s (%s)",
		len(servers),
		endpointLabel,
		bindAddressCount,
		addressLabel,
		strings.Join(details, ", "),
	)
}

func (p *Manager) Start() error {
	log.Printf("[proxy] Upstream client IP mode: %s", p.upstreamMode)
	if p.upstreamMode == config.UpstreamClientIPModeTransparent {
		if warning := transparentHeaderFallbackWarning(p.addressPairs, p.config.BindAddrs); warning != "" {
			log.Printf("[proxy] WARNING: %s", warning)
		}
	}
	p.engine.Start()

	if p.transparentNet != nil {
		if err := p.transparentNet.Setup(); err != nil {
			return fmt.Errorf("setup transparent upstream networking: %w", err)
		}
	}

	servers, err := p.startServers(p.config.resolvedProtocols(), p.config.AdvertiseHTTP3)
	if err != nil {
		p.stopServers(servers)
		return err
	}
	p.serverMu.Lock()
	p.servers = servers
	p.serverMu.Unlock()
	log.Printf("[proxy] %s", formatProxyStartupSummary(servers, len(p.config.BindAddrs)))

	// Small delay before we setup port redirection rules
	time.Sleep(100 * time.Millisecond)

	if err := p.setupPortRedirects(); err != nil {
		return err
	}
	if p.managesRedirect() {
		endpointLabel := "endpoints"
		if len(servers) == 1 {
			endpointLabel = "endpoint"
		}
		log.Printf("[firewall] Configured traffic redirection for %d proxy %s", len(servers), endpointLabel)
	}

	p.setInitialFirewallState(p.initialFirewallState())

	if p.managesFirewall() {
		go p.runFirewallMonitor()
	}

	select {
	case err := <-p.serveErrChan:
		return err
	default:
		p.engine.StartPanel()
		return nil
	}
}

func (p *Manager) Errors() <-chan error {
	return p.serveErrChan
}

func (p *Manager) Shutdown() error {
	log.Println("Shutting down proxy server...")

	// Remove the port redirection rules to stop new incoming connections
	p.serverMu.Lock()
	servers := p.servers
	p.servers = nil
	for _, server := range servers {
		server.CleanupPortRedirect()
	}
	p.serverMu.Unlock()

	// Stop the heartbeat, Fail2Ban, configuration updates and IP list refreshes
	close(p.stopFirewallMonitor)
	p.engine.StopBackground()

	// Stop the certificate manager
	p.certManager.Stop()

	// Small delay before we shut down the servers
	time.Sleep(100 * time.Millisecond)

	p.stopServers(servers)
	if p.transparentPool != nil {
		p.transparentPool.Close()
	}
	if p.transparentNet != nil {
		p.transparentNet.Cleanup()
	}

	// Stop the middleware chain
	p.engine.StopChain()

	log.Println("FlowGuard shutdown complete")
	return nil
}

func (p *Manager) StatusMessage() string {
	return p.statusMessageFromState(p.getFirewallState())
}

func (c *Config) resolvedProtocols() config.ProtocolSettings {
	if c != nil && c.Protocols.AnyEnabled() {
		return c.Protocols
	}

	return config.DefaultProtocolSettings()
}
