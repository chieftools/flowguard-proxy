package proxy

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"runtime"
	"sync"
	"time"

	"flowguard/api"
	"flowguard/certmanager"
	"flowguard/config"
	"flowguard/iplist"
	"flowguard/middleware"
	"flowguard/systemdnotify"
	"flowguard/updater"
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
	config              *Config
	servers             []*Server
	updater             *updater.Updater
	startedAt           time.Time
	certManager         *certmanager.Manager
	serveErrChan        chan error
	stopHeartbeat       chan struct{}
	stopFirewallMonitor chan struct{}
	forceHeartbeat      chan struct{}
	configManager       *config.Manager
	ipListManager       *iplist.Manager
	middlewareChain     *middleware.Chain
	firewallState       api.FirewallHeartbeat
	mu                  sync.RWMutex
}

func NewManager(configMgr *config.Manager, cfg *Config) (*Manager, error) {
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
		config:    cfg,
		startedAt: time.Now(),
		certManager: certmanager.New(certmanager.Config{
			Verbose:         cfg.Verbose,
			CertPath:        certPath,
			NginxConfigPath: nginxConfigPath,
			DefaultHostname: defaultHostname,
		}),
		serveErrChan:        make(chan error, max(1, len(cfg.BindAddrs)*2)),
		stopHeartbeat:       make(chan struct{}),
		stopFirewallMonitor: make(chan struct{}),
		forceHeartbeat:      make(chan struct{}, 1),
		configManager:       configMgr,
		middlewareChain:     middlewareChain,
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

	// Initialize updater for remote package upgrades (non-fatal if detection fails)
	cacheDir := ""
	if configMgr.GetConfig().Host != nil && configMgr.GetConfig().Host.CacheDir != "" {
		cacheDir = configMgr.GetConfig().Host.CacheDir
	}
	if cacheDir == "" {
		cacheDir = "/var/cache/flowguard"
	}
	u, err := updater.New(cfg.Version, cacheDir, cfg.Verbose)
	if err != nil {
		log.Printf("[updater] Package upgrades unavailable: %v", err)
	} else {
		pm.updater = u
		configMgr.OnUpgradeRequest(func(version string) {
			pm.handleUpgradeRequest(version)
		})
	}

	// Verify that at least some certificates were loaded
	if pm.certManager.HostnameCount() == 0 {
		return nil, fmt.Errorf("no valid certificates found (checked cert_path=%q, nginx_config_path=%q)", certPath, nginxConfigPath)
	}

	return pm, nil
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

func (p *Manager) firewallMonitorSettings() (enabled bool, autoRepair bool, interval time.Duration) {
	const defaultInterval = 30 * time.Second

	if !p.managesRedirect() {
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
	select {
	case p.forceHeartbeat <- struct{}{}:
	default:
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

func (p *Manager) StatusMessage() string {
	return p.statusMessageFromState(p.getFirewallState())
}

func (p *Manager) initialFirewallState() api.FirewallHeartbeat {
	if !p.managesRedirect() {
		return api.FirewallHeartbeat{Status: firewallStatusDisabled}
	}

	return api.FirewallHeartbeat{
		Status:        firewallStatusHealthy,
		LastCheckedAt: time.Now().Unix(),
	}
}

func (p *Manager) setupPortRedirects() error {
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
	state := api.FirewallHeartbeat{
		Status:        firewallStatusHealthy,
		LastCheckedAt: time.Now().Unix(),
	}

	if !p.managesRedirect() {
		state.Status = firewallStatusDisabled
		return state
	}

	totalMissing := 0
	lastError := ""
	repairError := ""
	repairedAt := int64(0)

	checkServers := func(repair bool) {
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
	log.Println("[firewall] Monitor started")

	for {
		enabled, autoRepair, interval := p.firewallMonitorSettings()
		if !enabled {
			timer := time.NewTimer(interval)
			select {
			case <-p.stopFirewallMonitor:
				timer.Stop()
				log.Println("[firewall] Monitor stopped")
				return
			case <-timer.C:
				continue
			}
		}

		timer := time.NewTimer(interval)
		select {
		case <-p.stopFirewallMonitor:
			timer.Stop()
			log.Println("[firewall] Monitor stopped")
			return
		case <-timer.C:
			p.updateFirewallState(p.evaluateFirewall(autoRepair))
		}
	}
}

func (p *Manager) runHeartbeat() {
	// Read heartbeat config defaults
	const defaultInterval = 300 // 5 minutes
	const defaultJitter = 30    // 30 seconds

	getConfig := func() (enabled bool, interval, jitter int) {
		hbCfg := p.configManager.GetConfig().Heartbeat

		enabled = true
		interval = defaultInterval
		jitter = defaultJitter

		if hbCfg != nil {
			if hbCfg.Enabled != nil {
				enabled = *hbCfg.Enabled
			}
			if hbCfg.IntervalSeconds > 0 {
				interval = hbCfg.IntervalSeconds
			}
			if hbCfg.JitterSeconds > 0 {
				jitter = hbCfg.JitterSeconds
			}
		}

		return
	}

	enabled, _, _ := getConfig()
	if !enabled {
		if p.config.Verbose {
			log.Println("[heartbeat] Disabled by configuration")
		}
		// Still listen for stop signal, but also re-check config each default interval
		// in case it gets re-enabled
		for {
			timer := time.NewTimer(time.Duration(defaultInterval) * time.Second)
			select {
			case <-p.stopHeartbeat:
				timer.Stop()
				return
			case <-p.forceHeartbeat:
				timer.Stop()
				continue
			case <-timer.C:
				enabled, _, _ = getConfig()
				if enabled {
					log.Println("[heartbeat] Re-enabled by configuration")
					break
				}
				continue
			}
			break
		}
	}

	log.Println("[heartbeat] Started")

	// Send immediately on startup
	p.sendHeartbeat()

	for {
		enabled, interval, jitter := getConfig()
		if !enabled {
			if p.config.Verbose {
				log.Println("[heartbeat] Disabled by configuration, pausing")
			}
			// Wait until re-enabled or stopped
			timer := time.NewTimer(time.Duration(defaultInterval) * time.Second)
			select {
			case <-p.stopHeartbeat:
				timer.Stop()
				log.Println("[heartbeat] Stopped")
				return
			case <-p.forceHeartbeat:
				timer.Stop()
				continue
			case <-timer.C:
				continue
			}
		}

		// Apply jitter: interval +/- jitter (uniform random)
		jitteredInterval := interval
		if jitter > 0 {
			jitteredInterval += rand.IntN(2*jitter+1) - jitter
		}
		if jitteredInterval < 1 {
			jitteredInterval = 1
		}

		timer := time.NewTimer(time.Duration(jitteredInterval) * time.Second)
		select {
		case <-p.stopHeartbeat:
			timer.Stop()
			log.Println("[heartbeat] Stopped")
			return
		case <-p.forceHeartbeat:
			timer.Stop()
			p.sendHeartbeat()
		case <-timer.C:
			p.sendHeartbeat()
		}
	}
}

func (p *Manager) sendHeartbeat() {
	payload := api.HeartbeatPayload{
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Version:       p.config.Version,
		Firewall:      p.getFirewallState(),
		StartedAt:     p.startedAt.Unix(),
		HostnameCount: p.certManager.HostnameCount(),
		BindAddresses: p.config.BindAddrs,
	}

	if err := p.configManager.GetAPIClient().SendHeartbeat(payload); err != nil {
		log.Printf("[heartbeat] Failed to send: %v", err)
		return
	}

	if p.config.Verbose {
		log.Println("[heartbeat] Sent successfully")
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

		if err := httpServer.Start(nil, p.serveErrChan); err != nil {
			return err
		}
		if err := httpsServer.Start(p.certManager.GetTlsConfig(), p.serveErrChan); err != nil {
			return err
		}
	}

	// Small delay before we setup port redirection rules
	time.Sleep(100 * time.Millisecond)

	if err := p.setupPortRedirects(); err != nil {
		return err
	}

	p.setInitialFirewallState(p.initialFirewallState())

	cfg := p.configManager.GetConfig()
	if cfg.Host != nil && cfg.Host.Key != "" {
		go p.runHeartbeat()
	}

	if p.managesRedirect() {
		go p.runFirewallMonitor()
	}

	select {
	case err := <-p.serveErrChan:
		return err
	default:
		return nil
	}
}

func (p *Manager) Errors() <-chan error {
	return p.serveErrChan
}

func (p *Manager) Shutdown() error {
	log.Println("Shutting down proxy server...")

	// Remove the port redirection rules to stop new incoming connections
	for _, server := range p.servers {
		server.CleanupPortRedirect()
	}

	// Stop the heartbeat goroutine
	close(p.stopHeartbeat)
	close(p.stopFirewallMonitor)

	// Stop the configuration manager
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
