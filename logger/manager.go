package logger

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// Manager manages multiple logging sinks
type Manager struct {
	sinks       map[string]Sink
	sinkConfigs map[string]string // name -> config hash
	userAgent   string
	mu          sync.RWMutex
	diagnostics *sinkDiagnostics
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	closed      bool
}

// NewManager creates a new logger manager
func NewManager(userAgent string) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	manager := &Manager{
		sinks:       make(map[string]Sink),
		sinkConfigs: make(map[string]string),
		userAgent:   userAgent,
		diagnostics: newSinkDiagnostics(),
		cancel:      cancel,
	}
	manager.wg.Add(1)
	go manager.runDiagnostics(ctx)

	return manager
}

// Write writes a log entry to all configured sinks
func (m *Manager) Write(entry *LogEntry) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed || len(m.sinks) == 0 {
		return
	}
	if _, err := entry.prepare(); err != nil {
		m.diagnostics.recordError(err)
		return
	}

	for _, sink := range m.sinks {
		if err := sink.Write(entry); err != nil {
			m.diagnostics.recordError(fmt.Errorf("sink %s: %w", sink.Name(), err))
		}
	}
}

// UpdateSinks updates the configured sinks based on new configuration
// It intelligently detects which sinks have actually changed and only
// recreates those that need to be updated
func (m *Manager) UpdateSinks(sinksConfig map[string]map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("logger manager is closed")
	}

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
		sink, err := CreateSink(name, config, m.userAgent)
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
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true

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
	m.mu.Unlock()

	m.cancel()
	m.wg.Wait()
	m.diagnostics.report("manager", "manager")

	return firstError
}

func (m *Manager) runDiagnostics(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(defaultReportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.diagnostics.report("manager", "manager")
		case <-ctx.Done():
			return
		}
	}
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
