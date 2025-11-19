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

// Flatten returns a flattened version of the log entry data where nested objects
// are converted to keys seperated by the given seperator argument. For example:
// {"client": {"ip": "1.2.3.4", "as": {"num": 123}}}
// becomes:
// {"client.ip": "1.2.3.4", "client.as.num": 123}
// This is useful for systems that don't support nested JSON structures or require flattened schemas for querying.
func (e *LogEntry) Flatten(seperator string) (map[string]interface{}, error) {
	// First, marshal and unmarshal to convert any structs to map[string]interface{}
	// This ensures nested objects are proper maps that can be flattened
	jsonBytes, err := json.Marshal(e.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entry: %w", err)
	}

	var normalizedData map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &normalizedData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal entry: %w", err)
	}

	// Flatten the normalized data
	flattened := make(map[string]interface{})
	flattenMap(normalizedData, "", seperator, flattened)

	return flattened, nil
}

// flattenMap recursively flattens nested maps with dot-separated keys
func flattenMap(data map[string]interface{}, prefix string, seperator string, result map[string]interface{}) {
	for key, value := range data {
		// Build the full key path
		fullKey := key
		if prefix != "" {
			fullKey = prefix + seperator + key
		}

		// If the value is a map, recurse
		if nestedMap, ok := value.(map[string]interface{}); ok {
			flattenMap(nestedMap, fullKey, seperator, result)
		} else {
			// Otherwise, add to result
			result[fullKey] = value
		}
	}
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
