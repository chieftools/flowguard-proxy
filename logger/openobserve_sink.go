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

// OpenObserveSink writes log entries to OpenObserve
type OpenObserveSink struct {
	name          string
	url           string
	organization  string
	stream        string
	username      string
	password      string
	userAgent     string
	client        *http.Client
	channel       chan *LogEntry
	cancelFunc    context.CancelFunc
	configHash    string
	channelDrops  uint64
	channelResets uint64
	wg            sync.WaitGroup
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

	// Create channel
	channel := make(chan *LogEntry, 10000)

	// Create context for ingestion goroutine
	ctx, cancel := context.WithCancel(context.Background())

	sink := &OpenObserveSink{
		name:         name,
		url:          sinkConfig.URL,
		organization: sinkConfig.Organization,
		stream:       sinkConfig.Stream,
		username:     sinkConfig.Username,
		password:     sinkConfig.Password,
		userAgent:    userAgent,
		client:       httpClient,
		channel:      channel,
		cancelFunc:   cancel,
		configHash:   computeConfigHash(config),
	}

	// Start ingestion goroutine
	sink.wg.Add(1)
	go sink.runIngestion(ctx)

	log.Printf("[logger:openobserve] OpenObserve sink %s initialized: url=%s, org=%s, stream=%s",
		name, sinkConfig.URL, sinkConfig.Organization, sinkConfig.Stream)

	return sink, nil
}

// Write writes a log entry to OpenObserve
func (s *OpenObserveSink) Write(entry *LogEntry) error {
	if s.channel == nil {
		return fmt.Errorf("openobserve sink %s is closed", s.name)
	}

	// Try to send to channel (non-blocking)
	select {
	case s.channel <- entry:
		return nil
	default:
		atomic.AddUint64(&s.channelDrops, 1)
		drops := atomic.LoadUint64(&s.channelDrops)
		if drops%100 == 1 {
			log.Printf("[logger:openobserve] Sink %s channel is full, total drops: %d", s.name, drops)
		}
		return fmt.Errorf("channel full, event dropped")
	}
}

// Close closes the OpenObserve sink
func (s *OpenObserveSink) Close() error {
	log.Printf("[logger:openobserve] Closing OpenObserve sink %s", s.name)

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
func (s *OpenObserveSink) Name() string {
	return s.name
}

// ConfigHash returns the configuration hash
func (s *OpenObserveSink) ConfigHash() string {
	return s.configHash
}

// runIngestion runs the OpenObserve ingestion loop
func (s *OpenObserveSink) runIngestion(ctx context.Context) {
	defer s.wg.Done()

	const (
		batchSize           = 100
		batchTimeout        = 5 * time.Second
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
			// Always reset timer even for empty batches to ensure periodic flushing continues
			batchTimer.Reset(batchTimeout)
			return
		}

		if err := s.sendBatch(ctx, batch); err != nil {
			consecutiveFailures++
			log.Printf("[logger:openobserve] Sink %s failed to send batch (failure #%d): %v. Retrying in %v",
				s.name, consecutiveFailures, err, retryDelay)

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
				log.Printf("[logger:openobserve] Sink %s retry failed, dropping %d log entries: %v", s.name, len(batch), err)
			} else {
				log.Printf("[logger:openobserve] Sink %s retry successful", s.name)
				consecutiveFailures = 0
				retryDelay = initialRetryDelay
			}
		} else {
			if consecutiveFailures > 0 {
				log.Printf("[logger:openobserve] Sink %s recovered after %d failures", s.name, consecutiveFailures)
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
			log.Printf("[logger:openobserve] Sink %s ingestion stopped (context cancelled)", s.name)
			// Use background context for final flush since our context is cancelled
			if len(batch) > 0 {
				flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if err := s.sendBatch(flushCtx, batch); err != nil {
					log.Printf("[logger:openobserve] Sink %s failed to flush final batch on shutdown: %v", s.name, err)
				}
				cancel()
			}
			return

		case entry, ok := <-s.channel:
			if !ok {
				log.Printf("[logger:openobserve] Sink %s channel closed", s.name)
				// Use background context for final flush
				if len(batch) > 0 {
					flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					if err := s.sendBatch(flushCtx, batch); err != nil {
						log.Printf("[logger:openobserve] Sink %s failed to flush final batch on channel close: %v", s.name, err)
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
				log.Printf("[logger:openobserve] Sink %s excessive drops detected (%d in last %v), recreating channel",
					s.name, dropsInPeriod, channelCheckPeriod)

				s.recreateChannel()
				atomic.AddUint64(&s.channelResets, 1)
			}

			lastDropCount = currentDrops
			lastChannelCheck = time.Now()
		}
	}
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
			log.Printf("[logger:openobserve] Sink %s failed to flatten entry: %v", s.name, err)
			continue
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

// recreateChannel recreates the channel and drains the old one
func (s *OpenObserveSink) recreateChannel() {
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
						log.Printf("[logger:openobserve] Sink %s timeout draining old channel, saved %d events", s.name, drained)
						close(oldChannel)
						return
					}
				case <-timeout:
					log.Printf("[logger:openobserve] Sink %s timeout draining old channel, saved %d events", s.name, drained)
					close(oldChannel)
					return
				default:
					log.Printf("[logger:openobserve] Sink %s old channel drained, saved %d events", s.name, drained)
					close(oldChannel)
					return
				}
			}
		}()
	}
}
