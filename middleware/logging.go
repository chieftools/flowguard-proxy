package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"flowguard/config"

	"github.com/axiomhq/axiom-go/axiom"
	"github.com/axiomhq/axiom-go/axiom/ingest"
)

const (
	ContextKeyRuleID      contextKey = "ruleID"
	ContextKeyActionTaken contextKey = "actionTaken"
	ContextKeyStartTime   contextKey = "startTime"
)

type RequestLogEntry struct {
	Timestamp string `json:"timestamp"`

	// Action details
	Action string `json:"action"`
	RuleID string `json:"matched_rule_id,omitempty"`

	// Request details
	Method    string `json:"request_method"`
	URL       string `json:"request_url"`
	UserAgent string `json:"request_user_agent,omitempty"`

	// Response details
	ResponseStatus int   `json:"response_response_status"`
	ResponseTimeMS int64 `json:"response_time_ms,omitempty"`

	// Client details
	ClientIP       string `json:"client_ip"`
	ClientCountry  string `json:"client_country,omitempty"`
	ClientASN      uint   `json:"client_asn,omitempty"`
	ClientASName   string `json:"client_as_name,omitempty"`
	ClientASDomain string `json:"client_as_domain,omitempty"`

	// Proxy details if request was proxied
	ProxyIP       string `json:"proxy_ip,omitempty"`
	ProxyCountry  string `json:"proxy_country,omitempty"`
	ProxyASN      uint   `json:"proxy_asn,omitempty"`
	ProxyASName   string `json:"proxy_as_name,omitempty"`
	ProxyASDomain string `json:"proxy_as_domain,omitempty"`
}

type LoggingMiddleware struct {
	configMgr       *config.Manager
	logFile         *os.File
	enabled         bool
	config          *config.LoggingConfig
	axiomClient     *axiom.Client
	axiomChannel    chan axiom.Event
	axiomCancelFunc context.CancelFunc
	mu              sync.RWMutex
}

func NewLoggingMiddleware(configMgr *config.Manager) (*LoggingMiddleware, error) {
	m := &LoggingMiddleware{
		configMgr: configMgr,
	}

	if err := m.updateLogOutput(configMgr.GetConfig()); err != nil {
		return nil, fmt.Errorf("failed to initialize logging: %w", err)
	}

	// Set up config change notification
	configMgr.OnChange(m.onConfigChange)

	return m, nil
}

func (lm *LoggingMiddleware) onConfigChange(cfg *config.Config) {
	if err := lm.updateLogOutput(cfg); err != nil {
		log.Printf("[middleware:logging] Failed to update log output on config change: %v", err)
	}
}

func (lm *LoggingMiddleware) updateLogOutput(cfg *config.Config) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if cfg == nil || cfg.Logging == nil {
		lm.config = nil
		lm.enabled = false

		return nil
	}

	loggingCfg := cfg.Logging

	lm.enabled = loggingCfg.Enabled

	err := lm.updateFileOutput(loggingCfg)
	if err != nil {
		return err
	}

	err = lm.updateAxiomOutput(loggingCfg)
	if err != nil {
		return err
	}

	lm.config = loggingCfg

	return nil
}

func (lm *LoggingMiddleware) updateFileOutput(loggingCfg *config.LoggingConfig) error {
	if lm.config != nil && lm.config.FilePath == loggingCfg.FilePath {
		return nil
	}

	if lm.logFile != nil {
		err := lm.logFile.Close()
		if err != nil {
			return err
		}
		lm.logFile = nil
	}

	if loggingCfg.FilePath == "" {
		return nil
	}

	file, err := os.OpenFile(loggingCfg.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", loggingCfg.FilePath, err)
	}
	lm.logFile = file

	log.Printf("[middleware:logging] File logging enabled to %s", loggingCfg.FilePath)

	return nil
}

func (lm *LoggingMiddleware) updateAxiomOutput(loggingCfg *config.LoggingConfig) error {
	if lm.config != nil && lm.config.AxiomDataset == loggingCfg.AxiomDataset && lm.config.AxiomToken == loggingCfg.AxiomToken {
		return nil
	}

	if lm.axiomCancelFunc != nil {
		lm.axiomCancelFunc()
		lm.axiomCancelFunc = nil
	}

	if lm.axiomChannel != nil {
		close(lm.axiomChannel)
		lm.axiomChannel = nil
		lm.axiomClient = nil
	}

	if loggingCfg.AxiomDataset == "" || loggingCfg.AxiomToken == "" {
		return nil
	}

	client, err := axiom.NewClient(
		axiom.SetToken(loggingCfg.AxiomToken),
	)
	if err != nil {
		return fmt.Errorf("failed to create Axiom client: %w", err)
	}

	lm.axiomClient = client
	lm.axiomChannel = make(chan axiom.Event, 10000)

	ctx, cancel := context.WithCancel(context.Background())
	lm.axiomCancelFunc = cancel

	go func() {
		_, err = client.IngestChannel(ctx, loggingCfg.AxiomDataset, lm.axiomChannel, ingest.SetTimestampField("timestamp"))
		if err != nil && ctx.Err() == nil {
			log.Printf("[middleware:logging] Axiom ingestion error: %v", err)
		}
	}()

	log.Printf("[middleware:logging] Axiom logging enabled to dataset %s", loggingCfg.AxiomDataset)

	return nil
}

func (lm *LoggingMiddleware) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	lm.mu.RLock()
	enabled := lm.enabled
	lm.mu.RUnlock()

	if !enabled {
		next.ServeHTTP(w, r)
		return
	}

	// Set start time for request duration tracking
	ctx := context.WithValue(r.Context(), ContextKeyStartTime, time.Now())
	r = r.WithContext(ctx)

	// Create wrapper to capture response status code
	wrapper := &ResponseWriterWrapper{
		ResponseWriter:  w,
		StatusCodeValue: http.StatusOK,
	}

	// Process the request through the next handler
	next.ServeHTTP(wrapper, r)

	// Log the completed request - now r has the enriched context from IP lookup
	lm.logCompletedRequest(r, wrapper.StatusCodeValue)
}

func (lm *LoggingMiddleware) logCompletedRequest(r *http.Request, statusCode int) {
	lm.mu.RLock()
	enabled := lm.enabled
	lm.mu.RUnlock()

	if !enabled {
		return
	}

	entry := lm.buildLogEntry(r, statusCode)
	lm.writeLogEntry(entry)
}

func (lm *LoggingMiddleware) buildLogEntry(r *http.Request, statusCode int) *RequestLogEntry {
	entry := &RequestLogEntry{
		Timestamp:      time.Now().Format(time.RFC3339),
		Method:         r.Method,
		URL:            r.URL.String(),
		ClientIP:       GetClientIP(r),
		ResponseStatus: statusCode,
		UserAgent:      r.Header.Get("User-Agent"),
	}

	if r.Host != "" {
		if r.URL.Scheme == "" {
			if r.TLS != nil {
				entry.URL = "https://" + r.Host + entry.URL
			} else {
				entry.URL = "http://" + r.Host + entry.URL
			}
		}
	}

	startTime := GetStartTime(r)
	responseTime := 0 * time.Millisecond

	if !startTime.IsZero() {
		responseTime = time.Since(startTime)
	}

	if responseTime > 0 {
		entry.ResponseTimeMS = responseTime.Milliseconds()
	}

	if proxyIP := GetProxyIP(r); proxyIP != "" {
		entry.ProxyIP = proxyIP

		if proxyASN := GetProxyASN(r); proxyASN != nil {
			entry.ProxyASN = proxyASN.GetASN()
			entry.ProxyASName = proxyASN.ASName
			entry.ProxyCountry = proxyASN.CountryCode
			entry.ProxyASDomain = proxyASN.ASDomain
		}
	}

	if clientASN := GetClientASN(r); clientASN != nil {
		entry.ClientASN = clientASN.GetASN()
		entry.ClientASName = clientASN.ASName
		entry.ClientCountry = clientASN.CountryCode
		entry.ClientASDomain = clientASN.ASDomain
	}

	ctx := r.Context()
	if ruleID, ok := ctx.Value(ContextKeyRuleID).(string); ok {
		entry.RuleID = ruleID
	}

	if actionTaken, ok := ctx.Value(ContextKeyActionTaken).(string); ok {
		entry.Action = actionTaken
	} else {
		entry.Action = "proxy"
	}

	return entry
}

func (lm *LoggingMiddleware) writeLogEntry(entry *RequestLogEntry) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[middleware:logging] Failed to marshal log entry: %v", err)
		return
	}

	if lm.logFile != nil {
		if _, err := lm.logFile.WriteString(string(jsonBytes) + "\n"); err != nil {
			log.Printf("[middleware:logging] Failed to write to log file: %v", err)
		}
	}

	if lm.axiomChannel != nil {
		var event axiom.Event
		if err := json.Unmarshal(jsonBytes, &event); err != nil {
			log.Printf("[middleware:logging] Failed to unmarshal log entry for Axiom: %v", err)
			return
		}

		select {
		case lm.axiomChannel <- event:
		default:
			log.Printf("[middleware:logging] Axiom channel is full, dropping log entry")
		}
	}
}

func (lm *LoggingMiddleware) Close() {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.axiomCancelFunc != nil {
		lm.axiomCancelFunc()
		lm.axiomCancelFunc = nil
	}

	if lm.axiomChannel != nil {
		close(lm.axiomChannel)
		lm.axiomChannel = nil
		lm.axiomClient = nil
	}

	if lm.logFile != nil {
		if err := lm.logFile.Close(); err != nil {
			log.Printf("[middleware:logging] Failed to close log file: %v", err)
		}
		lm.logFile = nil
	}
}

func SetRuleMatch(r *http.Request, ruleID string, action string) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, ContextKeyRuleID, ruleID)
	ctx = context.WithValue(ctx, ContextKeyActionTaken, action)
	*r = *r.WithContext(ctx)
}

func GetStartTime(r *http.Request) time.Time {
	if startTime, ok := r.Context().Value(ContextKeyStartTime).(time.Time); ok {
		return startTime
	}

	return time.Time{}
}
