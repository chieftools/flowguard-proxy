package logger

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"sync"
)

// Manager manages multiple logging sinks
type Manager struct {
	sinks       map[string]Sink
	sinkConfigs map[string]string // name -> config hash
	mu          sync.RWMutex
}

// NewManager creates a new logger manager
func NewManager() *Manager {
	return &Manager{
		sinks:       make(map[string]Sink),
		sinkConfigs: make(map[string]string),
	}
}

// Write writes a log entry to all configured sinks
func (m *Manager) Write(entry *LogEntry) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, sink := range m.sinks {
		if err := sink.Write(entry); err != nil {
			log.Printf("[logger] Failed to write to sink %s: %v", sink.Name(), err)
		}
	}
}

// UpdateSinks updates the configured sinks based on new configuration
// It intelligently detects which sinks have actually changed and only
// recreates those that need to be updated
func (m *Manager) UpdateSinks(sinksConfig map[string]map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Track which sinks are in the new config
	newSinkNames := make(map[string]bool)
	for name := range sinksConfig {
		newSinkNames[name] = true
	}

	// Remove sinks that are no longer in the config
	for name, sink := range m.sinks {
		if !newSinkNames[name] {
			log.Printf("[logger] Removing sink: %s", name)
			if err := sink.Close(); err != nil {
				log.Printf("[logger] Error closing sink %s: %v", name, err)
			}
			delete(m.sinks, name)
			delete(m.sinkConfigs, name)
		}
	}

	// Add or update sinks
	for name, config := range sinksConfig {
		configHash := computeConfigHash(config)

		// Check if this sink already exists with the same config
		if existingHash, exists := m.sinkConfigs[name]; exists {
			if existingHash == configHash {
				// Config hasn't changed, keep the existing sink
				continue
			}

			// Config changed, close the old sink
			log.Printf("[logger] Sink %s config changed, recreating", name)
			if oldSink, exists := m.sinks[name]; exists {
				if err := oldSink.Close(); err != nil {
					log.Printf("[logger] Error closing old sink %s: %v", name, err)
				}
			}
		}

		// Create new sink
		sink, err := CreateSink(name, config)
		if err != nil {
			log.Printf("[logger] Failed to create sink %s: %v", name, err)
			// Don't fail completely, just skip this sink
			continue
		}

		m.sinks[name] = sink
		m.sinkConfigs[name] = configHash
		log.Printf("[logger] Sink %s created/updated successfully", name)
	}

	return nil
}

// Close closes all sinks and releases resources
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstError error
	for name, sink := range m.sinks {
		if err := sink.Close(); err != nil {
			log.Printf("[logger] Error closing sink %s: %v", name, err)
			if firstError == nil {
				firstError = err
			}
		}
	}

	m.sinks = make(map[string]Sink)
	m.sinkConfigs = make(map[string]string)

	return firstError
}

// HasSinks returns true if there are any configured sinks
func (m *Manager) HasSinks() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sinks) > 0
}

// SinkCount returns the number of configured sinks
func (m *Manager) SinkCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sinks)
}

// computeConfigHash computes a hash of a configuration map
// This is used to detect if a sink's configuration has actually changed
func computeConfigHash(config map[string]interface{}) string {
	// Marshal to JSON for consistent hashing
	jsonBytes, err := json.Marshal(config)
	if err != nil {
		// If we can't marshal, generate a random hash to force recreation
		return fmt.Sprintf("error-%d", len(config))
	}

	hash := sha256.Sum256(jsonBytes)
	return fmt.Sprintf("%x", hash)
}
