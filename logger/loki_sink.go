package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// LokiSink writes log entries to Grafana Loki
type LokiSink struct {
	name       string
	url        string
	labels     map[string]string
	tenantID   string
	username   string
	password   string
	userAgent  string
	client     *http.Client
	writer     *asyncBatchWriter
	configHash string
}

// LokiSinkConfig represents the configuration for a Loki sink
type LokiSinkConfig struct {
	URL      string            `json:"url"`       // Loki push API URL (e.g., "http://loki:3100/loki/api/v1/push")
	Labels   map[string]string `json:"labels"`    // Static labels to attach to all logs
	TenantID string            `json:"tenant_id"` // Optional: X-Scope-OrgID header for multi-tenancy
	Username string            `json:"username"`  // Optional: Basic auth username
	Password string            `json:"password"`  // Optional: Basic auth password
}

// LokiStream represents a Loki log stream
type LokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

// LokiPushRequest represents a Loki push API request
type LokiPushRequest struct {
	Streams []LokiStream `json:"streams"`
}

func init() {
	RegisterSinkFactory("loki", NewLokiSink)
}

// NewLokiSink creates a new Loki sink
func NewLokiSink(name string, config map[string]interface{}, userAgent string) (Sink, error) {
	// Parse config
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var sinkConfig LokiSinkConfig
	if err := json.Unmarshal(configJSON, &sinkConfig); err != nil {
		return nil, fmt.Errorf("failed to parse loki sink config: %w", err)
	}

	if sinkConfig.URL == "" {
		return nil, fmt.Errorf("loki sink requires 'url' field")
	}

	// Initialize labels map if not provided
	if sinkConfig.Labels == nil {
		sinkConfig.Labels = make(map[string]string)
	}

	// Add default labels if not present
	if _, ok := sinkConfig.Labels["job"]; !ok {
		sinkConfig.Labels["job"] = "flowguard"
	}

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	sink := &LokiSink{
		name:       name,
		url:        sinkConfig.URL,
		labels:     sinkConfig.Labels,
		tenantID:   sinkConfig.TenantID,
		username:   sinkConfig.Username,
		password:   sinkConfig.Password,
		userAgent:  userAgent,
		client:     httpClient,
		configHash: computeConfigHash(config),
	}
	sink.writer = newAsyncBatchWriter("loki", name, sink.sendBatch)

	log.Printf("[logger:loki] Loki sink %s initialized: url=%s, labels=%v", name, sinkConfig.URL, sinkConfig.Labels)

	return sink, nil
}

// Write writes a log entry to Loki
func (s *LokiSink) Write(entry *LogEntry) error {
	if s.writer == nil {
		return fmt.Errorf("loki sink %s is closed", s.name)
	}
	return s.writer.Write(entry)
}

// Close closes the Loki sink
func (s *LokiSink) Close() error {
	log.Printf("[logger:loki] Closing Loki sink %s", s.name)

	if s.writer != nil {
		s.writer.Close()
	}

	s.client = nil

	return nil
}

// Name returns the name of this sink
func (s *LokiSink) Name() string {
	return s.name
}

// ConfigHash returns the configuration hash
func (s *LokiSink) ConfigHash() string {
	return s.configHash
}

// sendBatch sends a batch of log entries to Loki
func (s *LokiSink) sendBatch(ctx context.Context, entries []*LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	// Build Loki push request
	values := make([][]string, 0, len(entries))
	for _, entry := range entries {
		// Flatten and convert log entry to JSON string for the log line
		flattened, err := entry.Flatten(".")
		if err != nil {
			return fmt.Errorf("failed to flatten entry: %w", err)
		}

		// Extract timestamp from entry, default to now if not present
		timestamp := time.Now()
		if ts, ok := flattened["timestamp"].(string); ok {
			if parsedTime, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				timestamp = parsedTime
			}
		}

		logLine, err := json.Marshal(flattened)
		if err != nil {
			return fmt.Errorf("failed to marshal entry: %w", err)
		}

		// Loki expects [timestamp_ns, log_line]
		timestampNs := fmt.Sprintf("%d", timestamp.UnixNano())
		values = append(values, []string{timestampNs, string(logLine)})
	}

	if len(values) == 0 {
		return nil
	}

	// Create stream with labels
	stream := LokiStream{
		Stream: s.labels,
		Values: values,
	}

	pushRequest := LokiPushRequest{
		Streams: []LokiStream{stream},
	}

	// Marshal request
	requestBody, err := json.Marshal(pushRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal push request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", s.url, bytes.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if s.userAgent != "" {
		req.Header.Set("User-Agent", s.userAgent)
	}

	// Add tenant ID header if configured
	if s.tenantID != "" {
		req.Header.Set("X-Scope-OrgID", s.tenantID)
	}

	// Add basic auth if configured
	if s.username != "" && s.password != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	// Send request
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("loki returned non-2xx status: %d %s", resp.StatusCode, resp.Status)
	}

	return nil
}
