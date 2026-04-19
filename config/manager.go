package config

import (
	"fmt"
	"log"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"flowguard/api"
	"flowguard/cache"
	"flowguard/pusher"

	"github.com/fsnotify/fsnotify"
)

// Manager manages the configuration with hot-reload support
type Manager struct {
	configPath      string
	userAgent       string
	version         string
	verbose         bool
	config          *Config
	sortedRules     []*Rule // Pre-sorted rules for efficient iteration
	cache           *cache.Cache
	lastModified    time.Time
	currentConfigID string
	apiClient       *api.Client
	realtimeClient  *pusher.Client
	trustedProxyIPs []net.IPNet
	callbacks       []func(*Config)
	watcher         *fsnotify.Watcher
	stopWatcher     chan struct{}
	stopAPIRefresh  chan struct{}
	mu              sync.RWMutex

	// IP list update callback support with debouncing
	ipListUpdateCallbacks []func(listIDs []string)
	ipListDebounceTimer   *time.Timer
	ipListPendingUpdates  map[string]struct{} // Set of pending list IDs to refresh
	ipListMu              sync.Mutex          // Separate mutex for IP list update handling

	// Upgrade request callback support
	upgradeCallbacks []func(version string)
	upgradeMu        sync.Mutex
}

// NewManager creates a new configuration manager
func NewManager(configPath string, userAgent string, version string, cacheDir string, verbose bool) (*Manager, error) {
	// Create cache if cache directory is provided
	var c *cache.Cache
	if cacheDir != "" {
		var err error
		c, err = cache.NewCache(cacheDir, userAgent, verbose)
		if err != nil {
			return nil, fmt.Errorf("failed to create cache: %w", err)
		}
	}

	// Create fsnotify watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("[config] Warning: Failed to create file watcher: %v. Configuration updates will not be automatic.", err)
	}

	m := &Manager{
		cache:                c,
		version:              version,
		verbose:              verbose,
		watcher:              watcher,
		userAgent:            userAgent,
		configPath:           configPath,
		stopWatcher:          make(chan struct{}),
		stopAPIRefresh:       make(chan struct{}),
		apiClient:            api.NewClient("", userAgent),
		callbacks:            make([]func(*Config), 0),
		ipListPendingUpdates: make(map[string]struct{}),
	}

	// Load initial configuration
	if err := m.Load(); err != nil {
		return nil, err
	}

	// Setup file watcher if available
	if watcher != nil {
		// Watch the directory containing the config file for changes
		configDir := filepath.Dir(configPath)
		err = watcher.Add(configDir)
		if err != nil {
			log.Printf("[config] Warning: Failed to watch configuration directory %s: %v", configDir, err)
			watcher.Close()
			m.watcher = nil
		} else if verbose {
			log.Printf("[config] Watching configuration directory %s for changes", configDir)
		}
	}

	return m, nil
}

// GetConfig returns a copy of the current configuration
func (m *Manager) GetConfig() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// GetCache returns the HTTP cache instance
func (m *Manager) GetCache() *cache.Cache {
	return m.cache
}

// GetAPIClient returns the API client instance
func (m *Manager) GetAPIClient() *api.Client {
	return m.apiClient
}

// GetRules returns the current rules configuration
func (m *Manager) GetRules() map[string]*Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.config == nil {
		return nil
	}
	return m.config.Rules
}

// GetActions returns the current actions configuration
func (m *Manager) GetActions() map[string]*RuleAction {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.config == nil {
		return nil
	}
	return m.config.Actions
}

// GetSortedRules returns the pre-sorted rules for efficient iteration
func (m *Manager) GetSortedRules() []*Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sortedRules
}

// GetVersion returns the application version
func (m *Manager) GetVersion() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version
}

// GetUserAgent returns the full User-Agent string with version
func (m *Manager) GetUserAgent() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.userAgent
}

// OnChange adds a callback to be called when configuration changes
func (m *Manager) OnChange(callback func(*Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = append(m.callbacks, callback)
}

// RemoveOnChange removes a specific callback (by comparing function pointers)
// Note: This is not commonly needed but provided for completeness
func (m *Manager) RemoveOnChange(callback func(*Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, cb := range m.callbacks {
		if reflect.ValueOf(cb).Pointer() == reflect.ValueOf(callback).Pointer() {
			// Remove callback by replacing with last element and truncating
			m.callbacks[i] = m.callbacks[len(m.callbacks)-1]
			m.callbacks = m.callbacks[:len(m.callbacks)-1]
			break
		}
	}
}

// OnIPListUpdate adds a callback to be called when IP list updates are received
// The callback receives a slice of list base IDs that need to be refreshed
func (m *Manager) OnIPListUpdate(callback func(listIDs []string)) {
	m.ipListMu.Lock()
	defer m.ipListMu.Unlock()
	m.ipListUpdateCallbacks = append(m.ipListUpdateCallbacks, callback)
}

// OnUpgradeRequest adds a callback to be called when a proxy upgrade is requested
// via WebSocket. The callback receives the target version string.
func (m *Manager) OnUpgradeRequest(callback func(version string)) {
	m.upgradeMu.Lock()
	defer m.upgradeMu.Unlock()
	m.upgradeCallbacks = append(m.upgradeCallbacks, callback)
}

// Stop stops the configuration file watcher
func (m *Manager) Stop() {
	close(m.stopAPIRefresh)
	close(m.stopWatcher)

	// Close fsnotify watcher
	if m.watcher != nil {
		m.watcher.Close()
	}

	// Disconnect Realtime client
	m.mu.Lock()
	if m.realtimeClient != nil {
		m.realtimeClient.Disconnect()
		m.realtimeClient = nil
	}
	m.mu.Unlock()
}
