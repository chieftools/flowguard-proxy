// Package engine runs FlowGuard's request filtering independently of how
// traffic reaches it: the middleware chain, IP lists, Fail2Ban and the
// control panel connection. The standalone proxy and the Caddy plugin each
// build one Engine and put its chain in front of their own upstream handling.
package engine

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"go.chief.tools/flowguard-proxy/config"
	"go.chief.tools/flowguard-proxy/fail2ban"
	"go.chief.tools/flowguard-proxy/iplist"
	"go.chief.tools/flowguard-proxy/middleware"
)

type Options struct {
	Verbose bool
	Version string
	// Fail2Ban replaces the default Fail2Ban manager, mainly for tests.
	Fail2Ban *fail2ban.Manager
	// Heartbeat supplies the host-specific heartbeat fields. It may be nil.
	Heartbeat func() HeartbeatDetails
}

type Engine struct {
	options       Options
	startedAt     time.Time
	configManager *config.Manager
	chain         *middleware.Chain
	rules         *middleware.RulesMiddleware
	fail2ban      *fail2ban.Manager

	mu            sync.RWMutex
	ipListManager *iplist.Manager

	stopHeartbeat    chan struct{}
	forceHeartbeat   chan struct{}
	heartbeatStarted atomic.Bool
	stopBackground   sync.Once
	stopChain        sync.Once
}

// New builds the middleware chain and starts watching the configuration.
// Call Start before serving requests and Stop when done.
func New(configMgr *config.Manager, options Options) *Engine {
	// Start config file watcher for hot-reload
	configMgr.StartWatcher()

	// Start API refresh if host key is configured (default 15 minutes)
	if configMgr.GetConfig().Host != nil && configMgr.GetConfig().Host.Key != "" {
		configMgr.StartAPIRefresh(15 * time.Minute)
	}

	fail2banManager := options.Fail2Ban
	if fail2banManager == nil {
		fail2banManager = fail2ban.NewManager(fail2ban.Options{Verbose: options.Verbose})
	}

	// Create middleware chain with config-based middleware
	chain := middleware.NewChain()

	// Add middleware in the order they should execute
	// Timing middleware MUST be first to capture the full middleware stack timing
	chain.Add(middleware.NewTimingMiddleware())                  // Captures precise timing for all middleware (must be first!)
	chain.Add(middleware.NewIPLookupMiddleware(configMgr))       // Enriches request with IP/ASN data
	chain.Add(middleware.NewBehaviorTracker())                   // Tracks rolling request behavior for logs and rules
	chain.Add(middleware.NewLoggingMiddleware(configMgr))        // Logs request and response with enriched data
	chain.Add(middleware.NewFail2BanMiddleware(fail2banManager)) // Enforces synchronized Fail2Ban bans
	rulesMiddleware := middleware.NewRulesMiddleware(configMgr)  // Evaluates user defined rules
	chain.Add(rulesMiddleware)

	e := &Engine{
		options:        options,
		startedAt:      time.Now(),
		configManager:  configMgr,
		chain:          chain,
		rules:          rulesMiddleware,
		fail2ban:       fail2banManager,
		stopHeartbeat:  make(chan struct{}),
		forceHeartbeat: make(chan struct{}, 1),
	}

	// Initialize IP list manager with current config
	e.initializeIPListManager(configMgr.GetConfig())

	// Register callback to handle IP list and Fail2Ban configuration changes
	configMgr.OnChange(func(newConfig *config.Config) {
		e.handleIPListConfigChange(newConfig)
		e.fail2ban.SetEnabled(newConfig.Fail2BanEnabled())
	})

	// Register callback to handle IP list update events from WebSocket
	configMgr.OnIPListUpdate(func(listIDs []string) {
		e.handleIPListUpdateEvent(listIDs)
	})

	return e
}

// Chain returns the middleware chain that filters each request.
func (e *Engine) Chain() *middleware.Chain {
	return e.chain
}

// ConfigManager returns the configuration manager the engine runs on.
func (e *Engine) ConfigManager() *config.Manager {
	return e.configManager
}

// StartedAt returns when the engine was created.
func (e *Engine) StartedAt() time.Time {
	return e.startedAt
}

// Start starts the background work requests depend on. It returns once the
// initial Fail2Ban snapshot was attempted, so bans apply from the first request.
func (e *Engine) Start() {
	e.configManager.StartTrustedProxyRefresh()

	fail2banEnabled := e.configManager.GetConfig().Fail2BanEnabled()
	e.fail2ban.SetEnabled(fail2banEnabled)
	initialAttempt := e.fail2ban.Start()
	if fail2banEnabled {
		<-initialAttempt
	}
}

// StartPanel connects to the control panel: periodic heartbeats when a host
// key is configured, and realtime updates. Call it once the host is serving.
func (e *Engine) StartPanel() {
	cfg := e.configManager.GetConfig()
	if cfg.Host != nil && cfg.Host.Key != "" {
		e.heartbeatStarted.Store(true)
		go e.runHeartbeat()
	}

	e.configManager.StartRealtime()
}

// StopBackground stops the heartbeat, Fail2Ban, configuration updates and IP
// list refreshes. The chain keeps serving in-flight requests until StopChain.
func (e *Engine) StopBackground() {
	e.stopBackground.Do(func() {
		close(e.stopHeartbeat)
		if e.heartbeatStarted.Load() {
			e.sendHeartbeatStop()
		}
		e.fail2ban.Stop()

		// Stop the configuration manager
		e.configManager.Stop()

		// Stop the IP list manager if initialized
		e.mu.RLock()
		ipListMgr := e.ipListManager
		e.mu.RUnlock()
		if ipListMgr != nil {
			ipListMgr.Stop()
		}
	})
}

// StopChain stops the middleware chain, which closes the logging sinks.
func (e *Engine) StopChain() {
	e.stopChain.Do(e.chain.Stop)
}

// Stop stops everything the engine runs.
func (e *Engine) Stop() {
	e.StopBackground()
	e.StopChain()
}

// initializeIPListManager creates and initializes the IP list manager from config
func (e *Engine) initializeIPListManager(cfg *config.Config) {
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
	ipListMgr, err := iplist.New(listsConfig, e.configManager.GetCache(), e.options.Verbose)
	if err != nil {
		log.Printf("[ip_list] Failed to initialize IP list manager: %v", err)
		return
	}

	// Store and set the IP list manager
	e.mu.Lock()
	oldManager := e.ipListManager
	e.ipListManager = ipListMgr
	e.mu.Unlock()

	// Stop the old manager if it exists
	if oldManager != nil {
		oldManager.Stop()
	}

	// Set the IP list manager on the rules middleware
	e.rules.SetIPListManager(ipListMgr)
	listCount, entryCount := ipListMgr.Stats()
	listLabel := "lists"
	if listCount == 1 {
		listLabel = "list"
	}
	entryLabel := "entries"
	if entryCount == 1 {
		entryLabel = "entry"
	}
	log.Printf("[ip_list] Initialized %d %s with %d total %s", listCount, listLabel, entryCount, entryLabel)
}

// handleIPListConfigChange handles changes to IP list configuration during hot-reload
func (e *Engine) handleIPListConfigChange(newConfig *config.Config) {
	// Check if IP lists configuration exists and has changed
	hasIPLists := newConfig != nil && newConfig.IPLists != nil && len(*newConfig.IPLists) > 0

	e.mu.RLock()
	hadIPListManager := e.ipListManager != nil
	e.mu.RUnlock()

	// Case 1: IP lists were added (didn't have manager, now have config)
	if !hadIPListManager && hasIPLists {
		log.Printf("[ip_list] IP lists added to configuration, initializing manager")
		e.initializeIPListManager(newConfig)
		return
	}

	// Case 2: IP lists were removed (had manager, now no config)
	if hadIPListManager && !hasIPLists {
		log.Printf("[ip_list] IP lists removed from configuration, stopping manager")
		e.mu.Lock()
		oldManager := e.ipListManager
		e.ipListManager = nil
		e.mu.Unlock()

		if oldManager != nil {
			oldManager.Stop()
		}
		e.rules.SetIPListManager(nil)
		return
	}

	// Case 3: IP lists were modified (had manager, still have config)
	if hadIPListManager && hasIPLists {
		log.Printf("[ip_list] IP lists configuration changed, reinitializing manager")
		e.initializeIPListManager(newConfig)
		return
	}

	// Case 4: No IP lists before or after - nothing to do
}

// handleIPListUpdateEvent handles IP list updates triggered by WebSocket events
func (e *Engine) handleIPListUpdateEvent(listIDs []string) {
	e.mu.RLock()
	ipListMgr := e.ipListManager
	e.mu.RUnlock()

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
