package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
)

// FileSink writes log entries to a file
type FileSink struct {
	name       string
	path       string
	file       *os.File
	configHash string
	mu         sync.Mutex
}

// FileSinkConfig represents the configuration for a file sink
type FileSinkConfig struct {
	Path string `json:"path"`
}

func init() {
	RegisterSinkFactory("file", NewFileSink)
}

// NewFileSink creates a new file sink
func NewFileSink(name string, config map[string]interface{}, userAgent string) (Sink, error) {
	// userAgent is not used by file sink since it doesn't make HTTP requests
	// Parse config
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var sinkConfig FileSinkConfig
	if err := json.Unmarshal(configJSON, &sinkConfig); err != nil {
		return nil, fmt.Errorf("failed to parse file sink config: %w", err)
	}

	if sinkConfig.Path == "" {
		return nil, fmt.Errorf("file sink requires 'path' field")
	}

	// Open file
	file, err := os.OpenFile(sinkConfig.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %s: %w", sinkConfig.Path, err)
	}

	log.Printf("[logger:file] File sink %s initialized: %s", name, sinkConfig.Path)

	return &FileSink{
		name:       name,
		path:       sinkConfig.Path,
		file:       file,
		configHash: computeConfigHash(config),
	}, nil
}

// Write writes a log entry to the file
func (s *FileSink) Write(entry *LogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file == nil {
		return fmt.Errorf("file sink %s is closed", s.name)
	}

	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal log entry: %w", err)
	}

	if _, err := s.file.WriteString(string(jsonBytes) + "\n"); err != nil {
		return fmt.Errorf("failed to write to log file: %w", err)
	}

	return nil
}

// Close closes the file
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file != nil {
		log.Printf("[logger:file] Closing file sink %s", s.name)
		err := s.file.Close()
		s.file = nil
		return err
	}

	return nil
}

// Name returns the name of this sink
func (s *FileSink) Name() string {
	return s.name
}

// ConfigHash returns the configuration hash
func (s *FileSink) ConfigHash() string {
	return s.configHash
}
