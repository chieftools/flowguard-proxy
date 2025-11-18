package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// LokiSink writes log entries to Grafana Loki
type LokiSink struct {
	name          string
	url           string
	labels        map[string]string
	tenantID      string
	username      string
	password      string
	client        *http.Client
	channel       chan *LogEntry
	cancelFunc    context.CancelFunc
	configHash    string
	channelDrops  uint64
	channelResets uint64
	wg            sync.WaitGroup
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
func NewLokiSink(name string, config map[string]interface{}) (Sink, error) {
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

	// Create channel
	channel := make(chan *LogEntry, 10000)

	// Create context for ingestion goroutine
	ctx, cancel := context.WithCancel(context.Background())

	sink := &LokiSink{
		name:       name,
		url:        sinkConfig.URL,
		labels:     sinkConfig.Labels,
		tenantID:   sinkConfig.TenantID,
		username:   sinkConfig.Username,
		password:   sinkConfig.Password,
		client:     httpClient,
		channel:    channel,
		cancelFunc: cancel,
		configHash: computeConfigHash(config),
	}

	// Start ingestion goroutine
	sink.wg.Add(1)
	go sink.runIngestion(ctx)

	log.Printf("[logger:loki] Loki sink %s initialized: url=%s, labels=%v", name, sinkConfig.URL, sinkConfig.Labels)

	return sink, nil
}

// Write writes a log entry to Loki
func (s *LokiSink) Write(entry *LogEntry) error {
	if s.channel == nil {
		return fmt.Errorf("loki sink %s is closed", s.name)
	}

	// Try to send to channel (non-blocking)
	select {
	case s.channel <- entry:
		return nil
	default:
		atomic.AddUint64(&s.channelDrops, 1)
		drops := atomic.LoadUint64(&s.channelDrops)
		if drops%100 == 1 {
			log.Printf("[logger:loki] Sink %s channel is full, total drops: %d", s.name, drops)
		}
		return fmt.Errorf("channel full, event dropped")
	}
}

// Close closes the Loki sink
func (s *LokiSink) Close() error {
	log.Printf("[logger:loki] Closing Loki sink %s", s.name)

	// Cancel context to signal shutdown
	if s.cancelFunc != nil {
		s.cancelFunc()
	}

	// Wait for ingestion goroutine to finish (it will flush remaining logs)
	s.wg.Wait()

	// Now it's safe to clean up resources
	if s.channel != nil {
		close(s.channel)
		s.channel = nil
	}

	s.client = nil
	s.cancelFunc = nil

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

// runIngestion runs the Loki ingestion loop
func (s *LokiSink) runIngestion(ctx context.Context) {
	defer s.wg.Done()

	const (
		batchSize           = 100
		batchTimeout        = 1 * time.Second
		initialRetryDelay   = 1 * time.Second
		maxRetryDelay       = 5 * time.Minute
		retryMultiplier     = 2.0
		channelCheckPeriod  = 30 * time.Second
		maxDropsBeforeReset = 1000
	)

	retryDelay := initialRetryDelay
	consecutiveFailures := 0
	lastChannelCheck := time.Now()
	lastDropCount := uint64(0)

	batch := make([]*LogEntry, 0, batchSize)
	batchTimer := time.NewTimer(batchTimeout)
	defer batchTimer.Stop()

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}

		if err := s.sendBatch(ctx, batch); err != nil {
			consecutiveFailures++
			log.Printf("[logger:loki] Sink %s failed to send batch (failure #%d): %v. Retrying in %v", s.name, consecutiveFailures, err, retryDelay)

			select {
			case <-ctx.Done():
				return
			case <-time.After(retryDelay):
				retryDelay = time.Duration(float64(retryDelay) * retryMultiplier)
				if retryDelay > maxRetryDelay {
					retryDelay = maxRetryDelay
				}
			}

			// Retry sending the same batch
			if err := s.sendBatch(ctx, batch); err != nil {
				log.Printf("[logger:loki] Sink %s retry failed, dropping %d log entries: %v", s.name, len(batch), err)
			} else {
				log.Printf("[logger:loki] Sink %s retry successful", s.name)
				consecutiveFailures = 0
				retryDelay = initialRetryDelay
			}
		} else {
			if consecutiveFailures > 0 {
				log.Printf("[logger:loki] Sink %s recovered after %d failures", s.name, consecutiveFailures)
			}
			consecutiveFailures = 0
			retryDelay = initialRetryDelay
		}

		// Clear batch
		batch = make([]*LogEntry, 0, batchSize)
		batchTimer.Reset(batchTimeout)
	}

	for {
		select {
		case <-ctx.Done():
			log.Printf("[logger:loki] Sink %s ingestion stopped (context cancelled)", s.name)
			// Use background context for final flush since our context is cancelled
			if len(batch) > 0 {
				flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if err := s.sendBatch(flushCtx, batch); err != nil {
					log.Printf("[logger:loki] Sink %s failed to flush final batch on shutdown: %v", s.name, err)
				}
				cancel()
			}
			return

		case entry, ok := <-s.channel:
			if !ok {
				log.Printf("[logger:loki] Sink %s channel closed", s.name)
				// Use background context for final flush
				if len(batch) > 0 {
					flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					if err := s.sendBatch(flushCtx, batch); err != nil {
						log.Printf("[logger:loki] Sink %s failed to flush final batch on channel close: %v", s.name, err)
					}
					cancel()
				}
				return
			}

			batch = append(batch, entry)

			if len(batch) >= batchSize {
				flushBatch()
			}

		case <-batchTimer.C:
			flushBatch()
		}

		// Check for excessive drops and recreate channel if needed
		if time.Since(lastChannelCheck) > channelCheckPeriod {
			currentDrops := atomic.LoadUint64(&s.channelDrops)
			dropsInPeriod := currentDrops - lastDropCount

			if dropsInPeriod > maxDropsBeforeReset {
				log.Printf("[logger:loki] Sink %s excessive drops detected (%d in last %v), recreating channel",
					s.name, dropsInPeriod, channelCheckPeriod)

				s.recreateChannel()
				atomic.AddUint64(&s.channelResets, 1)
			}

			lastDropCount = currentDrops
			lastChannelCheck = time.Now()
		}
	}
}

// sendBatch sends a batch of log entries to Loki
func (s *LokiSink) sendBatch(ctx context.Context, entries []*LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	// Build Loki push request
	values := make([][]string, 0, len(entries))
	for _, entry := range entries {
		// Extract timestamp from entry, default to now if not present
		timestamp := time.Now()
		if ts, ok := entry.Data["timestamp"].(string); ok {
			if parsedTime, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				timestamp = parsedTime
			}
		}

		// Flatten and convert log entry to JSON string for the log line
		flattened, err := entry.Flatten()
		if err != nil {
			log.Printf("[logger:loki] Sink %s failed to flatten entry: %v", s.name, err)
			continue
		}

		logLine, err := json.Marshal(flattened)
		if err != nil {
			log.Printf("[logger:loki] Sink %s failed to marshal entry: %v", s.name, err)
			continue
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

// recreateChannel recreates the channel and drains the old one
func (s *LokiSink) recreateChannel() {
	if s.channel != nil {
		oldChannel := s.channel
		s.channel = make(chan *LogEntry, 10000)

		go func() {
			timeout := time.After(5 * time.Second)
			drained := 0
			for {
				select {
				case entry, ok := <-oldChannel:
					if !ok {
						return
					}
					select {
					case s.channel <- entry:
						drained++
					case <-timeout:
						log.Printf("[logger:loki] Sink %s timeout draining old channel, saved %d events", s.name, drained)
						close(oldChannel)
						return
					}
				case <-timeout:
					log.Printf("[logger:loki] Sink %s timeout draining old channel, saved %d events", s.name, drained)
					close(oldChannel)
					return
				default:
					log.Printf("[logger:loki] Sink %s old channel drained, saved %d events", s.name, drained)
					close(oldChannel)
					return
				}
			}
		}()
	}
}
