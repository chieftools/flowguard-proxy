package middleware

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"flowguard/config"
	"flowguard/normalization"

	"github.com/axiomhq/axiom-go/axiom"
	"github.com/axiomhq/axiom-go/axiom/ingest"
)

const (
	ContextKeyRule       contextKey = "matched_rule"
	ContextKeyAction     contextKey = "matched_action"
	ContextKeyStreamID   contextKey = "stream_id"
	ContextKeyStartTime  contextKey = "start_time"
	ContextKeyRuleResult contextKey = "rule_result"
)

type RequestLogEntry struct {
	StreamID  string `json:"stream_id"`
	Timestamp string `json:"timestamp"`

	Host       RequestLogEntryHostInfo        `json:"host"`
	Rule       RequestLogEntryRuleInfo        `json:"rule"`
	Proxy      *RequestLogEntryIPInfo         `json:"proxy,omitempty"`
	Client     RequestLogEntryIPInfo          `json:"client"`
	Request    RequestLogEntryRequestInfo     `json:"request"`
	Response   RequestLogEntryResponseInfo    `json:"response"`
	Cloudflare *RequestLogEntryCloudflareInfo `json:"cloudflare,omitempty"`
}

type RequestLogEntryIPInfo struct {
	IP      string `json:"ip"`
	Country string `json:"country,omitempty"`

	AS *RequestLogEntryIPASInfo `json:"as,omitempty"`
}

type RequestLogEntryTLSInfo struct {
	Cipher  string `json:"cipher,omitempty"`
	Version string `json:"version,omitempty"`
}

type RequestLogEntryHostInfo struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Team    string `json:"team,omitempty"`
	Version string `json:"version,omitempty"`
}

type RequestLogEntryRuleInfo struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Result string `json:"result"`

	Action *RequestLogEntryRuleActionInfo `json:"action,omitempty"`
}

type RequestLogEntryRuleActionInfo struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type RequestLogEntryIPASInfo struct {
	ASN    uint   `json:"num,omitempty"`
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
}

type RequestLogEntryRequestInfo struct {
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers,omitempty"`
	HeaderNames []string          `json:"header_names,omitempty"`
	HTTPVersion string            `json:"http_version"`

	TLS  *RequestLogEntryTLSInfo       `json:"tls,omitempty"`
	URL  RequestLogEntryRequestURLInfo `json:"url"`
	Body *RequestLogEntryBodyInfo      `json:"body,omitempty"`
}

type RequestLogEntryResponseInfo struct {
	Status      int               `json:"status"`
	TimeMS      int64             `json:"time_ms,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	HeaderNames []string          `json:"header_names,omitempty"`

	Body *RequestLogEntryBodyInfo `json:"body,omitempty"`
}

type RequestLogEntryBodyInfo struct {
	Size int64 `json:"body_size,omitempty"`
}

type RequestLogEntryRequestURLInfo struct {
	Full           string `json:"full"`
	Path           string `json:"path"`
	Query          string `json:"query,omitempty"`
	Scheme         string `json:"scheme"`
	Domain         string `json:"domain"`
	NormalizedPath string `json:"normalized_path,omitempty"`
}

type RequestLogEntryCloudflareInfo struct {
	RayID string `json:"ray_id,omitempty"`
}

type LoggingMiddleware struct {
	configMgr          *config.Manager
	logFile            *os.File
	enabled            bool
	version            string
	config             *config.LoggingConfig
	hostInfo           *RequestLogEntryHostInfo
	headerWhitelist    []string
	axiomClient        *axiom.Client
	axiomChannel       chan axiom.Event
	axiomCancelFunc    context.CancelFunc
	axiomChannelDrops  uint64
	axiomChannelResets uint64
	mu                 sync.RWMutex
}

func NewLoggingMiddleware(configMgr *config.Manager) *LoggingMiddleware {
	m := &LoggingMiddleware{
		configMgr: configMgr,
		version:   configMgr.GetVersion(), // Store version once at creation
	}

	m.onConfigChange(configMgr.GetConfig())

	// Set up config change notification
	configMgr.OnChange(m.onConfigChange)

	return m
}

func (lm *LoggingMiddleware) logRequest(r *http.Request, wrapper *ResponseWriterWrapper) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	if !lm.enabled {
		return
	}

	entry := &RequestLogEntry{
		StreamID:  GetStreamID(r),
		Timestamp: time.Now().Format(time.RFC3339),

		Host:       *lm.hostInfo,
		Rule:       getRuleInfo(r),
		Proxy:      getProxyInfo(r),
		Client:     getClientInfo(r),
		Request:    getRequestInfo(r, lm.headerWhitelist),
		Response:   getResponseInfo(r, wrapper, lm.headerWhitelist),
		Cloudflare: getCloudflareInfo(r),
	}

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
			atomic.AddUint64(&lm.axiomChannelDrops, 1)
			drops := atomic.LoadUint64(&lm.axiomChannelDrops)
			if drops%100 == 1 {
				log.Printf("[middleware:logging] Axiom channel is full, total drops: %d", drops)
			}
		}
	}
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
		lm.hostInfo = nil

		return nil
	}

	loggingCfg := cfg.Logging

	lm.enabled = loggingCfg.FilePath != "" || (loggingCfg.AxiomDataset != "" && loggingCfg.AxiomToken != "")
	lm.hostInfo = &RequestLogEntryHostInfo{
		ID:      cfg.Host.ID,
		Name:    cfg.Host.Name,
		Team:    cfg.Host.Team,
		Version: lm.version,
	}
	lm.headerWhitelist = loggingCfg.HeaderWhitelist

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

	go lm.runAxiomIngestion(ctx, loggingCfg.AxiomDataset)

	log.Printf("[middleware:logging] Axiom logging enabled to dataset %s", loggingCfg.AxiomDataset)

	return nil
}

func (lm *LoggingMiddleware) runAxiomIngestion(ctx context.Context, dataset string) {
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
			log.Printf("[middleware:logging] Axiom ingestion stopped (context cancelled)")
			return
		default:
		}

		lm.mu.RLock()
		client := lm.axiomClient
		channel := lm.axiomChannel
		lm.mu.RUnlock()

		if client == nil || channel == nil {
			log.Printf("[middleware:logging] Axiom client or channel is nil, stopping ingestion")
			return
		}

		if time.Since(lastChannelCheck) > channelCheckPeriod {
			currentDrops := atomic.LoadUint64(&lm.axiomChannelDrops)
			dropsInPeriod := currentDrops - lastDropCount

			if dropsInPeriod > maxDropsBeforeReset {
				log.Printf("[middleware:logging] Excessive drops detected (%d in last %v), recreating channel",
					dropsInPeriod, channelCheckPeriod)

				lm.recreateAxiomChannel()
				atomic.AddUint64(&lm.axiomChannelResets, 1)

				lm.mu.RLock()
				channel = lm.axiomChannel
				lm.mu.RUnlock()
			}

			lastDropCount = currentDrops
			lastChannelCheck = time.Now()
		}

		log.Printf("[middleware:logging] Starting Axiom ingestion to dataset %s", dataset)

		ingestionStarted := time.Now()

		// This blocks until context is cancelled or error occurs
		_, err := client.IngestChannel(ctx, dataset, channel, ingest.SetTimestampField("timestamp"))

		ingestionDuration := time.Since(ingestionStarted)

		if ctx.Err() != nil {
			log.Printf("[middleware:logging] Axiom ingestion stopped (main context cancelled)")
			return
		}

		if err != nil {
			// Check if this is just a context cancellation from unknown source
			if errors.Is(err, context.Canceled) {
				log.Printf("[middleware:logging] Axiom ingestion cancelled after %v, reconnecting immediately", ingestionDuration)
				// Don't treat context cancellation as failure - immediately retry
				continue
			}

			// This is a real error
			consecutiveFailures++
			log.Printf("[middleware:logging] Axiom ingestion error (failure #%d) after %v: %v. Retrying in %v", consecutiveFailures, ingestionDuration, err, retryDelay)

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
				log.Printf("[middleware:logging] Axiom ingestion recovered after %d failures", consecutiveFailures)
			}

			log.Printf("[middleware:logging] Axiom ingestion completed normally after %v, reconnecting", ingestionDuration)
			consecutiveFailures = 0
			retryDelay = initialRetryDelay
		}
	}
}

func (lm *LoggingMiddleware) recreateAxiomChannel() {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.axiomChannel != nil {
		oldChannel := lm.axiomChannel
		lm.axiomChannel = make(chan axiom.Event, 10000)

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
					case lm.axiomChannel <- event:
						drained++
					case <-timeout:
						log.Printf("[middleware:logging] Timeout draining old channel, saved %d events", drained)
						close(oldChannel)
						return
					}
				case <-timeout:
					log.Printf("[middleware:logging] Timeout draining old channel, saved %d events", drained)
					close(oldChannel)
					return
				default:
					log.Printf("[middleware:logging] Old channel drained, saved %d events", drained)
					close(oldChannel)
					return
				}
			}
		}()
	}
}

func (lm *LoggingMiddleware) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	lm.mu.RLock()
	enabled := lm.enabled
	lm.mu.RUnlock()

	// Set start time and stream ID in context
	ctx := context.WithValue(r.Context(), ContextKeyStartTime, time.Now())
	ctx = context.WithValue(ctx, ContextKeyStreamID, generateStreamID())
	r = r.WithContext(ctx)

	if !enabled {
		next.ServeHTTP(w, r)
		return
	}

	// Create wrapper to capture response status code
	wrapper := &ResponseWriterWrapper{
		ResponseWriter: w,
		StatusCode:     http.StatusOK,
	}

	// Process the request through the next handler
	next.ServeHTTP(wrapper, r)

	lm.logRequest(r, wrapper)
}

func (lm *LoggingMiddleware) Stop() {
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

func GetStreamID(r *http.Request) string {
	if streamID, ok := r.Context().Value(ContextKeyStreamID).(string); ok {
		return streamID
	}
	return ""
}

func GetStartTime(r *http.Request) time.Time {
	if startTime, ok := r.Context().Value(ContextKeyStartTime).(time.Time); ok {
		return startTime
	}

	return time.Time{}
}

func SetRuleMatch(r *http.Request, rule *config.Rule, action *config.RuleAction, result string) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, ContextKeyRule, rule)
	ctx = context.WithValue(ctx, ContextKeyAction, action)
	ctx = context.WithValue(ctx, ContextKeyRuleResult, result)
	*r = *r.WithContext(ctx)
}

func GetRuleResult(r *http.Request) string {
	if actionTaken, ok := r.Context().Value(ContextKeyRuleResult).(string); ok {
		return actionTaken
	}
	return "proxy"
}

func GetRuleMatched(r *http.Request) *config.Rule {
	if rule, ok := r.Context().Value(ContextKeyRule).(*config.Rule); ok {
		return rule
	}
	return nil
}

func GetActionMatched(r *http.Request) *config.RuleAction {
	if action, ok := r.Context().Value(ContextKeyAction).(*config.RuleAction); ok {
		return action
	}
	return nil
}

func generateStreamID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

func getTLSInfo(r *http.Request) *RequestLogEntryTLSInfo {
	if r.TLS == nil {
		return nil
	}

	return &RequestLogEntryTLSInfo{
		Cipher:  tls.CipherSuiteName(r.TLS.CipherSuite),
		Version: tls.VersionName(r.TLS.Version),
	}
}

func getRuleInfo(r *http.Request) RequestLogEntryRuleInfo {
	info := RequestLogEntryRuleInfo{
		Result: GetRuleResult(r),
	}

	if rule := GetRuleMatched(r); rule != nil {
		info.ID = rule.ID
		info.Name = rule.Name
	}

	if action := GetActionMatched(r); action != nil {
		info.Action = &RequestLogEntryRuleActionInfo{
			ID:   action.ID,
			Name: action.Name,
		}
	}

	return info
}

func getProxyInfo(r *http.Request) *RequestLogEntryIPInfo {
	proxyInfo := RequestLogEntryIPInfo{
		IP: GetProxyIP(r),
	}

	if proxyInfo.IP == "" {
		return nil
	}

	if proxyASN := GetProxyASN(r); proxyASN != nil {
		proxyInfo.AS = &RequestLogEntryIPASInfo{
			ASN:    proxyASN.GetASN(),
			Name:   proxyASN.ASName,
			Domain: proxyASN.ASDomain,
		}
		proxyInfo.Country = proxyASN.CountryCode
	}

	return &proxyInfo
}

func getClientInfo(r *http.Request) RequestLogEntryIPInfo {
	clientInfo := RequestLogEntryIPInfo{
		IP: GetClientIP(r),
	}

	if clientASN := GetClientASN(r); clientASN != nil {
		clientInfo.AS = &RequestLogEntryIPASInfo{
			ASN:    clientASN.GetASN(),
			Name:   clientASN.ASName,
			Domain: clientASN.ASDomain,
		}
		clientInfo.Country = clientASN.CountryCode
	}

	return clientInfo
}

func getRequestInfo(r *http.Request, whitelist []string) RequestLogEntryRequestInfo {
	var bodyInfo *RequestLogEntryBodyInfo = nil
	if r.ContentLength > 0 {
		bodyInfo = &RequestLogEntryBodyInfo{
			Size: r.ContentLength,
		}
	}

	headers, headerNames := simplifyHeaders(r.Header, whitelist)

	// Ensure User-Agent header is always present in the filtered headers
	if _, ok := headers["user-agent"]; !ok {
		headers["user-agent"] = ""
	}

	return RequestLogEntryRequestInfo{
		TLS:  getTLSInfo(r),
		URL:  getRequestURLInfo(r),
		Body: bodyInfo,

		Method:      r.Method,
		Headers:     headers,
		HeaderNames: headerNames,
		HTTPVersion: r.Proto,
	}
}

func getResponseInfo(r *http.Request, wrapper *ResponseWriterWrapper, whitelist []string) RequestLogEntryResponseInfo {
	headers, headerNames := simplifyHeaders(wrapper.Headers, whitelist)

	responseInfo := RequestLogEntryResponseInfo{
		Status:      wrapper.StatusCode,
		Headers:     headers,
		HeaderNames: headerNames,
	}

	startTime := GetStartTime(r)
	if !startTime.IsZero() {
		responseTime := time.Since(startTime)
		if responseTime > 0 {
			responseInfo.TimeMS = responseTime.Milliseconds()
		}
	}

	if wrapper.BodySize > 0 {
		responseInfo.Body = &RequestLogEntryBodyInfo{
			Size: wrapper.BodySize,
		}
	}

	return responseInfo
}

func getRequestURLInfo(r *http.Request) RequestLogEntryRequestURLInfo {
	scheme := r.URL.Scheme
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	domain := r.Host
	if domain == "" {
		domain = r.URL.Host
	}

	fullURL := r.URL.String()
	if !r.URL.IsAbs() && domain != "" {
		fullURL = fmt.Sprintf("%s://%s%s", scheme, domain, r.URL.RequestURI())
	}

	normalizedPath := normalization.NormalizePath(r.URL.Path)
	if normalizedPath == r.URL.Path {
		normalizedPath = ""
	}

	return RequestLogEntryRequestURLInfo{
		Full:           fullURL,
		Path:           r.URL.Path,
		Query:          r.URL.Query().Encode(),
		Scheme:         scheme,
		Domain:         domain,
		NormalizedPath: normalizedPath,
	}
}

func getCloudflareInfo(r *http.Request) *RequestLogEntryCloudflareInfo {
	if r.Header.Get("CF-Ray") == "" {
		return nil
	}

	return &RequestLogEntryCloudflareInfo{
		RayID: r.Header.Get("CF-Ray"),
	}
}

// simplifyHeaders converts headers to a filtered map and list of all header names
// Values are only included for whitelisted headers
func simplifyHeaders(headers map[string][]string, whitelist []string) (map[string]string, []string) {
	simple := make(map[string]string)
	names := make([]string, 0, len(headers))

	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		names = append(names, lowerKey)

		if isHeaderWhitelisted(lowerKey, whitelist) {
			simple[lowerKey] = strings.Join(values, ", ")
		}
	}

	sort.Strings(names)

	return simple, names
}

// isHeaderWhitelisted checks if a header name matches the whitelist
// Supports both exact matches and prefix matches (entries ending with "-")
// Both the header name and the whitelist patterns are expected to be in lower case
func isHeaderWhitelisted(headerName string, whitelist []string) bool {
	// Always include User-Agent header
	if headerName == "user-agent" {
		return true
	}

	if len(whitelist) == 0 {
		return false
	}

	for _, pattern := range whitelist {
		if headerName == pattern {
			return true // exact match
		} else if strings.HasSuffix(pattern, "-") && strings.HasPrefix(headerName, pattern) {
			return true // prefix match
		}
	}

	return false
}
