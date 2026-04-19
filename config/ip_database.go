package config

import (
	"fmt"
	"log"
	"os"
	"time"
)

// GetIPDatabaseRefreshInterval returns the configured refresh interval for the IP database
func (m *Manager) GetIPDatabaseRefreshInterval() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.config != nil && m.config.IPDatabase != nil && m.config.IPDatabase.RefreshIntervalSeconds > 0 {
		return time.Duration(m.config.IPDatabase.RefreshIntervalSeconds) * time.Second
	}

	// Default to 24 hours if not configured
	return 24 * time.Hour
}

// GetIPDatabasePath downloads the IP database if configured and returns the local path
func (m *Manager) GetIPDatabasePath() (string, error) {
	m.mu.RLock()

	var dbURL string
	var refreshInterval time.Duration

	if m.config != nil && m.config.IPDatabase != nil {
		dbURL = m.config.IPDatabase.URL

		if m.config.IPDatabase.RefreshIntervalSeconds > 0 {
			refreshInterval = time.Duration(m.config.IPDatabase.RefreshIntervalSeconds) * time.Second
		}
	}

	m.mu.RUnlock()

	if dbURL == "" {
		// No database URL configured, use local file if exists
		if _, err := os.Stat("ipinfo_lite.mmdb"); err == nil {
			return "ipinfo_lite.mmdb", nil
		}
		return "", fmt.Errorf("no IP database configured")
	}

	// Use cache to download and store the database file
	if m.cache == nil {
		return "", fmt.Errorf("cache not initialized")
	}

	// Use configured TTL or default to 24 hours
	cacheTTL := 24 * time.Hour
	if refreshInterval > 0 {
		cacheTTL = refreshInterval
	}

	// Download/retrieve from cache (API key will be applied automatically if URL starts with API base)
	cachedPath, _, err := m.cache.FetchFileWithCache(dbURL, cacheTTL)
	if err != nil {
		// Fallback to local file if download fails
		if _, err := os.Stat("ipinfo_lite.mmdb"); err == nil {
			log.Printf("[config] Failed to download IP database, using local file: %v", err)
			return "ipinfo_lite.mmdb", nil
		}
		return "", fmt.Errorf("failed to download IP database: %w", err)
	}

	// Note: Cache already logs the status (cache hit, 304, fresh file)
	return cachedPath, nil
}
