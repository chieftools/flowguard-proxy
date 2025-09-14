package middleware

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
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
	ContextKeyStreamID    contextKey = "streamID"
	ContextKeyStartTime   contextKey = "startTime"
	ContextKeyActionTaken contextKey = "actionTaken"
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
	IP      string                   `json:"ip"`
	AS      *RequestLogEntryIPASInfo `json:"as,omitempty"`
	Country string                   `json:"country,omitempty"`
}

type RequestLogEntryTLSInfo struct {
	Cipher  string `json:"cipher,omitempty"`
	Version string `json:"version,omitempty"`
}

type RequestLogEntryHostInfo struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
	Team string `json:"team,omitempty"`
}

type RequestLogEntryRuleInfo struct {
	Result string `json:"result"`
	ID     string `json:"id,omitempty"`
}

type RequestLogEntryIPASInfo struct {
	ASN    uint   `json:"num,omitempty"`
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
}

type RequestLogEntryRequestInfo struct {
	TLS *RequestLogEntryTLSInfo       `json:"tls,omitempty"`
	URL RequestLogEntryRequestURLInfo `json:"url"`

	Method        string `json:"method"`
	Referrer      string `json:"referrer,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
	ContentType   string `json:"content_type,omitempty"`
	HTTPVersion   string `json:"http_version"`
	ContentLength string `json:"content_length,omitempty"`
}

type RequestLogEntryResponseInfo struct {
	Status int   `json:"status"`
	TimeMS int64 `json:"time_ms,omitempty"`
}

type RequestLogEntryRequestURLInfo struct {
	Full   string `json:"full"`
	Path   string `json:"path"`
	Query  string `json:"query,omitempty"`
	Scheme string `json:"scheme"`
	Domain string `json:"domain"`
}

type RequestLogEntryCloudflareInfo struct {
	RayID string `json:"ray_id,omitempty"`
}

type LoggingMiddleware struct {
	configMgr       *config.Manager
	logFile         *os.File
	enabled         bool
	config          *config.LoggingConfig
	hostInfo        *RequestLogEntryHostInfo
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

func (lm *LoggingMiddleware) logRequest(r *http.Request, statusCode int) {
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
		Request:    getRequestInfo(r),
		Response:   getResponseInfo(statusCode, GetStartTime(r)),
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
			log.Printf("[middleware:logging] Axiom channel is full, dropping log entry")
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
		ID:   cfg.Host.ID,
		Name: cfg.Host.Name,
		Team: cfg.Host.Team,
	}

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
		ResponseWriter:  w,
		StatusCodeValue: http.StatusOK,
	}

	// Process the request through the next handler
	next.ServeHTTP(wrapper, r)

	lm.logRequest(r, wrapper.StatusCodeValue)
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

func GetStreamID(r *http.Request) string {
	if streamID, ok := r.Context().Value(ContextKeyStreamID).(string); ok {
		return streamID
	}
	return ""
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
	ruleInfo := RequestLogEntryRuleInfo{
		Result: "proxy",
	}

	ctx := r.Context()
	if ruleID, ok := ctx.Value(ContextKeyRuleID).(string); ok {
		ruleInfo.ID = ruleID
	}
	if actionTaken, ok := ctx.Value(ContextKeyActionTaken).(string); ok {
		ruleInfo.Result = actionTaken
	}

	return ruleInfo
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

func getRequestInfo(r *http.Request) RequestLogEntryRequestInfo {
	return RequestLogEntryRequestInfo{
		TLS: getTLSInfo(r),
		URL: getRequestURLInfo(r),

		Method:        r.Method,
		Referrer:      r.Header.Get("Referer"),
		UserAgent:     r.Header.Get("User-Agent"),
		ContentType:   r.Header.Get("Content-Type"),
		HTTPVersion:   r.Proto,
		ContentLength: r.Header.Get("Content-Length"),
	}
}

func getResponseInfo(statusCode int, startTime time.Time) RequestLogEntryResponseInfo {
	responseInfo := RequestLogEntryResponseInfo{
		Status: statusCode,
	}

	if !startTime.IsZero() {
		responseTime := time.Since(startTime)
		if responseTime > 0 {
			responseInfo.TimeMS = responseTime.Milliseconds()
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

	return RequestLogEntryRequestURLInfo{
		Full:   fullURL,
		Path:   r.URL.Path,
		Query:  r.URL.Query().Encode(),
		Scheme: scheme,
		Domain: domain,
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
