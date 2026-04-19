package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"flowguard/api"
	"flowguard/pusher"

	"github.com/fsnotify/fsnotify"
)

// handleUpgradeEvent processes the proxy.upgrade WebSocket event
func (m *Manager) handleUpgradeEvent(version string) {
	// Check if unattended upgrades are allowed
	m.mu.RLock()
	cfg := m.config
	m.mu.RUnlock()

	if cfg == nil || cfg.Updates == nil || !cfg.Updates.AllowUnattended {
		log.Printf("[updater] Received upgrade request for version %s, but unattended upgrades are disabled", version)
		return
	}

	log.Printf("[updater] Received upgrade request for version %s", version)

	// Copy callbacks to avoid holding lock during execution
	m.upgradeMu.Lock()
	callbacks := make([]func(string), len(m.upgradeCallbacks))
	copy(callbacks, m.upgradeCallbacks)
	m.upgradeMu.Unlock()

	for _, callback := range callbacks {
		callback(version)
	}
}

// handleIPListUpdateEvent handles the iplist.updated WebSocket event with debouncing
// Events are debounced for up to 5 seconds to batch rapid consecutive updates
func (m *Manager) handleIPListUpdateEvent(listID string) {
	m.ipListMu.Lock()
	defer m.ipListMu.Unlock()

	// Add list ID to pending updates
	m.ipListPendingUpdates[listID] = struct{}{}

	// If timer is already running, it will fire with accumulated updates
	// Otherwise, start a new 5-second debounce timer
	if m.ipListDebounceTimer == nil {
		m.ipListDebounceTimer = time.AfterFunc(5*time.Second, m.flushIPListUpdates)
		if m.verbose {
			log.Printf("[config] Started IP list update debounce timer for list: %s", listID)
		}
	} else if m.verbose {
		log.Printf("[config] Added list %s to pending IP list updates (debouncing)", listID)
	}
}

// flushIPListUpdates processes all pending IP list updates after debounce period
func (m *Manager) flushIPListUpdates() {
	m.ipListMu.Lock()

	// Collect all pending list IDs
	listIDs := make([]string, 0, len(m.ipListPendingUpdates))
	for listID := range m.ipListPendingUpdates {
		listIDs = append(listIDs, listID)
	}

	// Clear pending updates and timer
	m.ipListPendingUpdates = make(map[string]struct{})
	m.ipListDebounceTimer = nil

	// Copy callbacks to avoid holding lock during callback execution
	callbacks := make([]func([]string), len(m.ipListUpdateCallbacks))
	copy(callbacks, m.ipListUpdateCallbacks)

	m.ipListMu.Unlock()

	if len(listIDs) == 0 {
		return
	}

	log.Printf("[config] Flushing IP list updates for %d list(s): %v", len(listIDs), listIDs)

	// Notify all registered callbacks
	for _, callback := range callbacks {
		callback(listIDs)
	}
}

// StartWatcher starts watching the configuration file for changes using fsnotify
func (m *Manager) StartWatcher() {
	if m.watcher == nil {
		// Fall back to polling if fsnotify is not available
		log.Printf("[config] fsnotify not available, falling back to polling every 10 seconds")
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					m.checkAndReload()
				case <-m.stopWatcher:
					return
				}
			}
		}()
		return
	}

	go m.watchConfigFile()
}

// watchConfigFile implements the fsnotify-based file watching with debouncing
func (m *Manager) watchConfigFile() {
	if m.watcher == nil {
		return
	}

	debounce := time.NewTimer(0)
	<-debounce.C // Drain the initial timer
	var pendingReload bool

	configFileName := filepath.Base(m.configPath)

	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			// Check if event is for our config file
			eventFileName := filepath.Base(event.Name)
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0 && eventFileName == configFileName {
				// Ignore temporary files
				if strings.HasPrefix(eventFileName, ".") || strings.HasSuffix(eventFileName, "~") || strings.HasSuffix(eventFileName, ".tmp") {
					continue
				}

				if m.verbose {
					log.Printf("[config] Detected change in configuration file: %s (%v)", configFileName, event.Op)
				}

				// Use debouncing to avoid multiple reloads for rapid changes
				if !pendingReload {
					pendingReload = true
					debounce.Reset(100 * time.Millisecond)
				}
			}

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[config] File watcher error: %v", err)

		case <-debounce.C:
			if pendingReload {
				pendingReload = false
				m.checkAndReload()
			}

		case <-m.stopWatcher:
			return
		}
	}
}

// checkAndReload checks if the config file has changed and reloads if necessary
func (m *Manager) checkAndReload() {
	shouldReload, reason := m.shouldReloadConfig()
	if shouldReload {
		log.Printf("[config] Configuration %s, reloading...", reason)
		if err := m.Load(); err != nil {
			log.Printf("[config] Failed to reload configuration: %v", err)
		} else {
			log.Printf("[config] Configuration reloaded successfully")
		}
	}
}

// shouldReloadConfig determines if the configuration should be reloaded
// Returns true and reason if reload is needed, false otherwise
func (m *Manager) shouldReloadConfig() (bool, string) {
	// First check if file exists and get info
	info, err := os.Stat(m.configPath)
	if err != nil {
		log.Printf("[config] Failed to stat config file: %v", err)
		return false, ""
	}

	// Read the file to check for ID changes
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		log.Printf("[config] Failed to read config file for ID check: %v", err)
		// Fall back to modification time check
		m.mu.RLock()
		lastMod := m.lastModified
		m.mu.RUnlock()

		if info.ModTime().After(lastMod) {
			return true, "file modification time changed"
		}
		return false, ""
	}

	// Parse just enough to get the ID
	var tempConfig struct {
		ID string `json:"id,omitempty"`
	}
	if err := json.Unmarshal(data, &tempConfig); err != nil {
		log.Printf("[config] Failed to parse config for ID check: %v", err)
		// Fall back to modification time check
		m.mu.RLock()
		lastMod := m.lastModified
		m.mu.RUnlock()

		if info.ModTime().After(lastMod) {
			return true, "file modification time changed (JSON parse failed)"
		}
		return false, ""
	}

	m.mu.RLock()
	currentID := m.currentConfigID
	lastMod := m.lastModified
	m.mu.RUnlock()

	// If we have an ID in the new config, use ID comparison
	if tempConfig.ID != "" {
		if tempConfig.ID != currentID {
			return true, fmt.Sprintf("ID changed from '%s' to '%s'", currentID, tempConfig.ID)
		}
		// IDs match, no reload needed
		return false, ""
	}

	// No ID in new config, fall back to modification time
	if info.ModTime().After(lastMod) {
		return true, "file modification time changed (no ID in config)"
	}

	return false, ""
}

// RefreshFromAPI fetches the latest configuration from the API and updates the config file
// If force is true, bypasses ETag check and always downloads a fresh copy
func (m *Manager) RefreshFromAPI(force bool) error {
	m.mu.RLock()
	hasHostKey := m.config != nil && m.config.Host != nil && m.config.Host.Key != ""
	currentConfigID := m.currentConfigID
	m.mu.RUnlock()

	// Only refresh if we have a host key
	if !hasHostKey {
		return nil
	}

	// Determine ETag to use: empty string if force, otherwise current config ID
	etag := currentConfigID
	if force {
		etag = ""
	}

	// Fetch configuration from API using the client, passing ETag if not forced
	body, err := m.apiClient.GetConfig(etag)
	if err != nil {
		// Handle 304 Not Modified - configuration hasn't changed
		if errors.Is(err, api.ErrNotModified) {
			if m.verbose {
				log.Printf("[config] API configuration not modified (version: %s)", currentConfigID)
			}
			return nil
		}
		return fmt.Errorf("failed to fetch configuration from API: %w", err)
	}

	// Parse the new configuration to check ID
	var newConfig struct {
		ID string `json:"id,omitempty"`
	}
	if err := json.Unmarshal(body, &newConfig); err != nil {
		return fmt.Errorf("failed to parse API configuration: %w", err)
	}

	// If we have an ID in the new config, check if it's different from current
	// This is a fallback check in case the server doesn't support ETag properly
	if newConfig.ID != "" && newConfig.ID == currentConfigID {
		if m.verbose {
			log.Printf("[config] API configuration ID (%s) matches current, skipping update", newConfig.ID)
		}
		return nil
	}

	// Write to temporary file first for atomic update
	tmpFile := m.configPath + ".tmp"
	if err := os.WriteFile(tmpFile, body, 0644); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}

	// Atomically rename to final location
	if err := os.Rename(tmpFile, m.configPath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	if newConfig.ID != "" {
		log.Printf("[config] Configuration refreshed from API successfully (ID: %s -> %s)", currentConfigID, newConfig.ID)
	} else {
		log.Printf("[config] Configuration refreshed from API successfully (no ID)")
	}

	// The file watcher will detect the change and reload automatically
	return nil
}

// StartAPIRefresh starts a goroutine that periodically refreshes the configuration from the API
func (m *Manager) StartAPIRefresh(interval time.Duration) {
	log.Printf("[config] Started API configuration refresher")

	go func() {
		// Initial refresh on startup
		if err := m.RefreshFromAPI(false); err != nil {
			log.Printf("[config] Initial API refresh failed: %v", err)
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := m.RefreshFromAPI(false); err != nil {
					log.Printf("[config] API refresh failed: %v", err)
				}
			case <-m.stopAPIRefresh:
				return
			}
		}
	}()
}

// updatePusherClient updates or creates the Realtime client based on configuration
func (m *Manager) updatePusherClient(config *Config) {
	// If no pusher config or no host key, disconnect any existing client
	if config.Realtime == nil || config.Host == nil || config.Host.Key == "" {
		if m.realtimeClient != nil {
			m.realtimeClient.Disconnect()
			m.realtimeClient = nil
			if config.Realtime == nil {
				log.Printf("[config] Realtime client disconnected (no configuration)")
			} else {
				log.Printf("[config] Realtime client disconnected (no host key)")
			}
		}
		return
	}

	// If no existing client, create new one
	if m.realtimeClient == nil {
		m.realtimeClient = pusher.NewClient(config.Realtime, m.userAgent, config.Host.Key, m.verbose)

		if m.realtimeClient != nil {
			// Set up event handler for config updates
			m.realtimeClient.OnEvent("config.updated", func(message pusher.Message) {
				log.Printf("[config] Received config update event from realtime event")

				if err := m.RefreshFromAPI(false); err != nil {
					log.Printf("[config] Failed to refresh config from API after realtime event: %v", err)
				}
			})

			// Set up event handler for IP list updates
			m.realtimeClient.OnEvent("iplist.updated", func(message pusher.Message) {
				var eventData struct {
					ID string `json:"id"`
				}
				if err := message.UnmarshalData(&eventData); err != nil {
					log.Printf("[config] Failed to parse iplist.updated event data: %v", err)
					return
				}

				if eventData.ID == "" {
					log.Printf("[config] Received iplist.updated event with empty ID")
					return
				}

				log.Printf("[config] Received iplist.updated event for list: %s", eventData.ID)
				m.handleIPListUpdateEvent(eventData.ID)
			})

			// Set up event handler for proxy upgrade requests
			m.realtimeClient.OnEvent("proxy.upgrade", func(message pusher.Message) {
				var eventData struct {
					Version string `json:"version"`
				}
				if err := message.UnmarshalData(&eventData); err != nil {
					log.Printf("[config] Failed to parse proxy.upgrade event data: %v", err)
					return
				}

				if eventData.Version == "" {
					log.Printf("[config] Received proxy.upgrade event with empty version")
					return
				}

				m.handleUpgradeEvent(eventData.Version)
			})

			// Start connection in background
			go func() {
				if err := m.realtimeClient.Connect(); err != nil {
					log.Printf("[config] Failed to connect to realtime server: %v", err)
				}
			}()

			log.Printf("[config] Realtime client initialized")
		}
	} else {
		// Update existing client configuration
		if err := m.realtimeClient.UpdateConfig(config.Realtime); err != nil {
			log.Printf("[config] Failed to update realtime client configuration: %v", err)
		}
	}
}
