package logger

import (
	"encoding/json"
	"fmt"
)

// Sink represents a logging destination that can receive log entries
type Sink interface {
	// Write writes a log entry to the sink
	Write(entry *LogEntry) error

	// Close closes the sink and releases any resources
	Close() error

	// Name returns the name/ID of this sink
	Name() string

	// ConfigHash returns a hash of the current configuration
	// Used to detect if the sink's config has actually changed
	ConfigHash() string
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Data map[string]interface{}
}

// MarshalJSON marshals the log entry to JSON
func (e *LogEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.Data)
}

// SinkConfig represents the configuration for a sink
type SinkConfig struct {
	Type string                 `json:"type"` // "file" or "axiom"
	Raw  map[string]interface{} `json:"-"`    // Raw config for hash comparison
}

// SinkFactory creates a sink from a configuration
type SinkFactory func(name string, config map[string]interface{}) (Sink, error)

var sinkFactories = make(map[string]SinkFactory)

// RegisterSinkFactory registers a sink factory for a specific type
func RegisterSinkFactory(sinkType string, factory SinkFactory) {
	sinkFactories[sinkType] = factory
}

// CreateSink creates a sink from configuration
func CreateSink(name string, config map[string]interface{}) (Sink, error) {
	sinkType, ok := config["type"].(string)
	if !ok {
		return nil, fmt.Errorf("sink %s: missing or invalid 'type' field", name)
	}

	factory, ok := sinkFactories[sinkType]
	if !ok {
		return nil, fmt.Errorf("sink %s: unknown sink type '%s'", name, sinkType)
	}

	return factory(name, config)
}
