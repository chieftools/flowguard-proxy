package logger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/axiomhq/axiom-go/axiom"
	"github.com/axiomhq/axiom-go/axiom/ingest"
)

// AxiomSink writes log entries to Axiom
type AxiomSink struct {
	name          string
	dataset       string
	client        *axiom.Client
	channel       chan axiom.Event
	cancelFunc    context.CancelFunc
	configHash    string
	channelDrops  uint64
	channelResets uint64
}

// AxiomSinkConfig represents the configuration for an Axiom sink
type AxiomSinkConfig struct {
	Token   string `json:"token"`
	Dataset string `json:"dataset"`
}

func init() {
	RegisterSinkFactory("axiom", NewAxiomSink)
}

// NewAxiomSink creates a new Axiom sink
func NewAxiomSink(name string, config map[string]interface{}) (Sink, error) {
	// Parse config
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var sinkConfig AxiomSinkConfig
	if err := json.Unmarshal(configJSON, &sinkConfig); err != nil {
		return nil, fmt.Errorf("failed to parse axiom sink config: %w", err)
	}

	if sinkConfig.Token == "" {
		return nil, fmt.Errorf("axiom sink requires 'token' field")
	}

	if sinkConfig.Dataset == "" {
		return nil, fmt.Errorf("axiom sink requires 'dataset' field")
	}

	// Create Axiom client
	client, err := axiom.NewClient(
		axiom.SetToken(sinkConfig.Token),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Axiom client: %w", err)
	}

	// Create channel
	channel := make(chan axiom.Event, 10000)

	// Create context for ingestion goroutine
	ctx, cancel := context.WithCancel(context.Background())

	sink := &AxiomSink{
		name:       name,
		dataset:    sinkConfig.Dataset,
		client:     client,
		channel:    channel,
		cancelFunc: cancel,
		configHash: computeConfigHash(config),
	}

	// Start ingestion goroutine
	go sink.runIngestion(ctx)

	log.Printf("[logger:axiom] Axiom sink %s initialized: dataset=%s", name, sinkConfig.Dataset)

	return sink, nil
}

// Write writes a log entry to Axiom
func (s *AxiomSink) Write(entry *LogEntry) error {
	if s.channel == nil {
		return fmt.Errorf("axiom sink %s is closed", s.name)
	}

	// Convert LogEntry to axiom.Event
	var event axiom.Event
	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal log entry: %w", err)
	}

	if err := json.Unmarshal(jsonBytes, &event); err != nil {
		return fmt.Errorf("failed to unmarshal to axiom event: %w", err)
	}

	// Try to send to channel (non-blocking)
	select {
	case s.channel <- event:
		return nil
	default:
		atomic.AddUint64(&s.channelDrops, 1)
		drops := atomic.LoadUint64(&s.channelDrops)
		if drops%100 == 1 {
			log.Printf("[logger:axiom] Sink %s channel is full, total drops: %d", s.name, drops)
		}
		return fmt.Errorf("channel full, event dropped")
	}
}

// Close closes the Axiom sink
func (s *AxiomSink) Close() error {
	log.Printf("[logger:axiom] Closing Axiom sink %s", s.name)

	if s.cancelFunc != nil {
		s.cancelFunc()
		s.cancelFunc = nil
	}

	if s.channel != nil {
		close(s.channel)
		s.channel = nil
	}

	s.client = nil

	return nil
}

// Name returns the name of this sink
func (s *AxiomSink) Name() string {
	return s.name
}

// ConfigHash returns the configuration hash
func (s *AxiomSink) ConfigHash() string {
	return s.configHash
}

// runIngestion runs the Axiom ingestion loop
func (s *AxiomSink) runIngestion(ctx context.Context) {
	const (
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

	for {
		select {
		case <-ctx.Done():
			log.Printf("[logger:axiom] Sink %s ingestion stopped (context cancelled)", s.name)
			return
		default:
		}

		if s.client == nil || s.channel == nil {
			log.Printf("[logger:axiom] Sink %s client or channel is nil, stopping ingestion", s.name)
			return
		}

		// Check for excessive drops and recreate channel if needed
		if time.Since(lastChannelCheck) > channelCheckPeriod {
			currentDrops := atomic.LoadUint64(&s.channelDrops)
			dropsInPeriod := currentDrops - lastDropCount

			if dropsInPeriod > maxDropsBeforeReset {
				log.Printf("[logger:axiom] Sink %s excessive drops detected (%d in last %v), recreating channel",
					s.name, dropsInPeriod, channelCheckPeriod)

				s.recreateChannel()
				atomic.AddUint64(&s.channelResets, 1)
			}

			lastDropCount = currentDrops
			lastChannelCheck = time.Now()
		}

		log.Printf("[logger:axiom] Sink %s starting ingestion to dataset %s", s.name, s.dataset)

		ingestionStarted := time.Now()

		// This blocks until context is cancelled or error occurs
		_, err := s.client.IngestChannel(ctx, s.dataset, s.channel, ingest.SetTimestampField("timestamp"))

		ingestionDuration := time.Since(ingestionStarted)

		if ctx.Err() != nil {
			log.Printf("[logger:axiom] Sink %s ingestion stopped (main context cancelled)", s.name)
			return
		}

		if err != nil {
			// Check if this is just a context cancellation from unknown source
			if errors.Is(err, context.Canceled) {
				log.Printf("[logger:axiom] Sink %s ingestion cancelled after %v, reconnecting immediately", s.name, ingestionDuration)
				// Don't treat context cancellation as failure - immediately retry
				continue
			}

			// This is a real error
			consecutiveFailures++
			log.Printf("[logger:axiom] Sink %s ingestion error (failure #%d) after %v: %v. Retrying in %v", s.name, consecutiveFailures, ingestionDuration, err, retryDelay)

			select {
			case <-ctx.Done():
				return
			case <-time.After(retryDelay):
				retryDelay = time.Duration(float64(retryDelay) * retryMultiplier)
				if retryDelay > maxRetryDelay {
					retryDelay = maxRetryDelay
				}
			}
		} else {
			// IngestChannel returned without error (shouldn't normally happen)
			if consecutiveFailures > 0 {
				log.Printf("[logger:axiom] Sink %s ingestion recovered after %d failures", s.name, consecutiveFailures)
			}

			log.Printf("[logger:axiom] Sink %s ingestion completed normally after %v, reconnecting", s.name, ingestionDuration)
			consecutiveFailures = 0
			retryDelay = initialRetryDelay
		}
	}
}

// recreateChannel recreates the channel and drains the old one
func (s *AxiomSink) recreateChannel() {
	if s.channel != nil {
		oldChannel := s.channel
		s.channel = make(chan axiom.Event, 10000)

		go func() {
			timeout := time.After(5 * time.Second)
			drained := 0
			for {
				select {
				case event, ok := <-oldChannel:
					if !ok {
						return
					}
					select {
					case s.channel <- event:
						drained++
					case <-timeout:
						log.Printf("[logger:axiom] Sink %s timeout draining old channel, saved %d events", s.name, drained)
						close(oldChannel)
						return
					}
				case <-timeout:
					log.Printf("[logger:axiom] Sink %s timeout draining old channel, saved %d events", s.name, drained)
					close(oldChannel)
					return
				default:
					log.Printf("[logger:axiom] Sink %s old channel drained, saved %d events", s.name, drained)
					close(oldChannel)
					return
				}
			}
		}()
	}
}
