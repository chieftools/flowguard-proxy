package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
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

	mu        sync.Mutex
	encoded   []byte
	timestamp any // Data["_timestamp"], kept when Data is released after encoding
}

// MarshalJSON marshals the log entry to JSON
func (e *LogEntry) MarshalJSON() ([]byte, error) {
	if _, err := e.prepare(); err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	return e.encoded, nil
}

func (e *LogEntry) prepare() (int64, error) {
	if e == nil {
		return 0, fmt.Errorf("nil log entry")
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.encoded != nil {
		return int64(len(e.encoded)), nil
	}

	// Leave <, > and & unescaped: entries are not embedded in HTML, and the
	// FlowGuard ingest payload must not contain the escapes.
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(e.Data); err != nil {
		return 0, fmt.Errorf("failed to marshal entry: %w", err)
	}
	e.encoded = bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	e.timestamp = e.Data["_timestamp"]
	e.Data = nil

	return int64(len(e.encoded)), nil
}

// timestampValue returns the entry's _timestamp value. Call it after prepare.
func (e *LogEntry) timestampValue() any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.timestamp
}

func (e *LogEntry) jsonBytes() ([]byte, error) {
	if _, err := e.prepare(); err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	return e.encoded, nil
}

// Flatten returns a flattened version of the log entry data where nested objects
// are converted to keys seperated by the given seperator argument. For example:
// {"client": {"ip": "1.2.3.4", "as": {"num": 123}}}
// becomes:
// {"client.ip": "1.2.3.4", "client.as.num": 123}
// This is useful for systems that don't support nested JSON structures or require flattened schemas for querying.
func (e *LogEntry) Flatten(seperator string) (map[string]interface{}, error) {
	jsonBytes, err := e.jsonBytes()
	if err != nil {
		return nil, err
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
	Type string                 `json:"type"` // Registered sink type
	Raw  map[string]interface{} `json:"-"`    // Raw config for hash comparison
}

// SinkFactory creates a sink from a configuration
type SinkFactory func(name string, config map[string]interface{}, userAgent string) (Sink, error)

var sinkFactories = make(map[string]SinkFactory)

// RegisterSinkFactory registers a sink factory for a specific type
func RegisterSinkFactory(sinkType string, factory SinkFactory) {
	sinkFactories[sinkType] = factory
}

// CreateSink creates a sink from configuration
func CreateSink(name string, config map[string]interface{}, userAgent string) (Sink, error) {
	sinkType, ok := config["type"].(string)
	if !ok {
		return nil, fmt.Errorf("sink %s: missing or invalid 'type' field", name)
	}

	factory, ok := sinkFactories[sinkType]
	if !ok {
		return nil, fmt.Errorf("sink %s: unknown sink type '%s'", name, sinkType)
	}

	return factory(name, config, userAgent)
}
