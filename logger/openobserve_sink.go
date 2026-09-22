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

// OpenObserveSink writes log entries to OpenObserve
type OpenObserveSink struct {
	name         string
	url          string
	organization string
	stream       string
	username     string
	password     string
	userAgent    string
	client       *http.Client
	writer       *asyncBatchWriter
	configHash   string
}

// OpenObserveSinkConfig represents the configuration for an OpenObserve sink
type OpenObserveSinkConfig struct {
	URL          string `json:"url"`          // OpenObserve base URL (e.g., "https://observe.example.com")
	Organization string `json:"organization"` // Organization name
	Stream       string `json:"stream"`       // Stream name (default: "flowguard")
	Username     string `json:"username"`     // Basic auth username
	Password     string `json:"password"`     // Basic auth password (API token)
}

func init() {
	RegisterSinkFactory("openobserve", NewOpenObserveSink)
}

// NewOpenObserveSink creates a new OpenObserve sink
func NewOpenObserveSink(name string, config map[string]interface{}, userAgent string) (Sink, error) {
	// Parse config
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var sinkConfig OpenObserveSinkConfig
	if err := json.Unmarshal(configJSON, &sinkConfig); err != nil {
		return nil, fmt.Errorf("failed to parse openobserve sink config: %w", err)
	}

	if sinkConfig.URL == "" {
		return nil, fmt.Errorf("openobserve sink requires 'url' field")
	}

	if sinkConfig.Organization == "" {
		return nil, fmt.Errorf("openobserve sink requires 'organization' field")
	}

	// Default stream name
	if sinkConfig.Stream == "" {
		sinkConfig.Stream = "flowguard"
	}

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	sink := &OpenObserveSink{
		name:         name,
		url:          sinkConfig.URL,
		organization: sinkConfig.Organization,
		stream:       sinkConfig.Stream,
		username:     sinkConfig.Username,
		password:     sinkConfig.Password,
		userAgent:    userAgent,
		client:       httpClient,
		configHash:   computeConfigHash(config),
	}
	sink.writer = newAsyncBatchWriter("openobserve", name, sink.sendBatch)

	log.Printf("[logger:openobserve] OpenObserve sink %s initialized: url=%s, org=%s, stream=%s",
		name, sinkConfig.URL, sinkConfig.Organization, sinkConfig.Stream)

	return sink, nil
}

// Write writes a log entry to OpenObserve
func (s *OpenObserveSink) Write(entry *LogEntry) error {
	if s.writer == nil {
		return fmt.Errorf("openobserve sink %s is closed", s.name)
	}
	return s.writer.Write(entry)
}

// Close closes the OpenObserve sink
func (s *OpenObserveSink) Close() error {
	log.Printf("[logger:openobserve] Closing OpenObserve sink %s", s.name)

	if s.writer != nil {
		s.writer.Close()
	}

	s.client = nil

	return nil
}

// Name returns the name of this sink
func (s *OpenObserveSink) Name() string {
	return s.name
}

// ConfigHash returns the configuration hash
func (s *OpenObserveSink) ConfigHash() string {
	return s.configHash
}

// sendBatch sends a batch of log entries to OpenObserve
func (s *OpenObserveSink) sendBatch(ctx context.Context, entries []*LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	// Flatten and convert entries to array of flattened objects
	flattenedEntries := make([]map[string]interface{}, 0, len(entries))
	for _, entry := range entries {
		// Flatten the entry using the LogEntry.Flatten() method
		flattened, err := entry.Flatten("__")
		if err != nil {
			return fmt.Errorf("failed to flatten entry: %w", err)
		}

		flattenedEntries = append(flattenedEntries, flattened)
	}

	// Marshal request (OpenObserve expects an array of JSON objects)
	requestBody, err := json.Marshal(flattenedEntries)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build the ingestion URL
	// OpenObserve API: /api/{org}/{stream}/_json
	url := fmt.Sprintf("%s/api/%s/%s/_json", s.url, s.organization, s.stream)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if s.userAgent != "" {
		req.Header.Set("User-Agent", s.userAgent)
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
		return fmt.Errorf("openobserve returned non-2xx status: %d %s", resp.StatusCode, resp.Status)
	}

	return nil
}
