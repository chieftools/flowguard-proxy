package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// FileSink writes log entries to a file
type FileSink struct {
	name       string
	path       string
	file       *os.File
	writer     *asyncBatchWriter
	configHash string
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

	sink := &FileSink{
		name:       name,
		path:       sinkConfig.Path,
		file:       file,
		configHash: computeConfigHash(config),
	}
	options := defaultAsyncBatchWriterOptions()
	options.maxBatchEntries = 1
	sink.writer = newAsyncBatchWriterWithOptions("file", name, sink.sendBatch, options)

	return sink, nil
}

// Write writes a log entry to the file
func (s *FileSink) Write(entry *LogEntry) error {
	if s.writer == nil {
		return fmt.Errorf("file sink %s is closed", s.name)
	}
	return s.writer.Write(entry)
}

// Close closes the file
func (s *FileSink) Close() error {
	if s.file != nil {
		log.Printf("[logger:file] Closing file sink %s", s.name)
		if s.writer != nil {
			s.writer.Close()
		}
		err := s.file.Close()
		s.file = nil
		return err
	}

	return nil
}

func (s *FileSink) sendBatch(ctx context.Context, entries []*LogEntry) error {
	var batch bytes.Buffer
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		encoded, err := entry.jsonBytes()
		if err != nil {
			return err
		}
		batch.Write(encoded)
		batch.WriteByte('\n')
	}

	if _, err := s.file.Write(batch.Bytes()); err != nil {
		return fmt.Errorf("failed to write to log file: %w", err)
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
