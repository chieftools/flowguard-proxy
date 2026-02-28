package middleware

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"flowguard/config"
	"flowguard/logger"
	"flowguard/normalization"

	"github.com/oklog/ulid/v2"
)

const (
	ContextKeyRule              contextKey = "matched_rule"
	ContextKeyAction            contextKey = "matched_action"
	ContextKeyStreamID          contextKey = "stream_id"
	ContextKeyStartTime         contextKey = "start_time"
	ContextKeyRuleResult        contextKey = "rule_result"
	ContextKeyMiddlewareEndTime contextKey = "middleware_end_time"
)

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
	Name    string `json:"name,omitempty"`
	Team    string `json:"team,omitempty"`
	Version string `json:"version"`
}

type RequestLogEntryRuleInfo struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Result string `json:"result"`
	TookUS *int64 `json:"took_us,omitempty"`

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
	configMgr       *config.Manager
	loggerManager   *logger.Manager
	enabled         bool
	version         string
	hostInfo        *RequestLogEntryHostInfo
	headerWhitelist []string
	mu              sync.RWMutex
}

func NewLoggingMiddleware(configMgr *config.Manager) *LoggingMiddleware {
	m := &LoggingMiddleware{
		configMgr:     configMgr,
		loggerManager: logger.NewManager(configMgr.GetUserAgent()),
		version:       configMgr.GetVersion(), // Store version once at creation
	}

	m.onConfigChange(configMgr.GetConfig())

	// Set up config change notification
	configMgr.OnChange(m.onConfigChange)

	return m
}

func (lm *LoggingMiddleware) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	lm.mu.RLock()
	enabled := lm.enabled
	lm.mu.RUnlock()

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
	if err := lm.loggerManager.Close(); err != nil {
		log.Printf("[middleware:logging] Failed to close logger manager: %v", err)
	}
}

func (lm *LoggingMiddleware) logRequest(r *http.Request, wrapper *ResponseWriterWrapper) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	if !lm.enabled {
		return
	}

	timestamp := time.Now()

	entry := &logger.LogEntry{
		Data: map[string]interface{}{
			"stream_id": GetStreamID(r),
			"timestamp": timestamp.Format(time.RFC3339),
			"host":      lm.hostInfo,
			"rule":      getRuleInfo(r),
			"client":    getClientInfo(r),
			"request":   getRequestInfo(r, lm.headerWhitelist),
			"response":  getResponseInfo(r, wrapper, lm.headerWhitelist),
		},
	}

	if proxy := getProxyInfo(r); proxy != nil {
		entry.Data["proxy"] = proxy
	}

	if cloudflare := getCloudflareInfo(r); cloudflare != nil {
		entry.Data["cloudflare"] = cloudflare
	}

	entry.Data["_timestamp"] = timestamp.UnixMicro()
	entry.Data["_id"] = strings.ToLower(ulid.MustNewDefault(timestamp).String())

	lm.loggerManager.Write(entry)
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
		lm.enabled = false
		lm.hostInfo = nil
		// Close all sinks
		if err := lm.loggerManager.Close(); err != nil {
			log.Printf("[middleware:logging] Error closing sinks: %v", err)
		}
		return nil
	}

	loggingCfg := cfg.Logging

	// Update sinks in the logger manager
	// The manager will intelligently detect which sinks have actually changed
	if err := lm.loggerManager.UpdateSinks(loggingCfg.Sinks); err != nil {
		return err
	}

	// Update enabled status
	lm.enabled = lm.loggerManager.HasSinks()

	// Update host info
	if cfg.Host != nil {
		lm.hostInfo = &RequestLogEntryHostInfo{
			ID:      cfg.Host.ID,
			Name:    cfg.Host.Name,
			Team:    cfg.Host.Team,
			Version: lm.version,
		}
	} else {
		lm.hostInfo = &RequestLogEntryHostInfo{
			Version: lm.version,
		}
	}

	// Update header whitelist
	lm.headerWhitelist = loggingCfg.HeaderWhitelist

	if lm.enabled {
		log.Printf("[middleware:logging] Logging enabled with %d sink(s)", lm.loggerManager.SinkCount())
	} else {
		log.Printf("[middleware:logging] Logging disabled (no sinks configured)")
	}

	return nil
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

	// Calculate middleware latency (time from start to when proxy handler begins)
	startTime := GetStartTime(r)
	if middlewareEndTime, ok := r.Context().Value(ContextKeyMiddlewareEndTime).(time.Time); ok && !startTime.IsZero() {
		latency := middlewareEndTime.Sub(startTime)
		if latency > 0 {
			info.TookUS = new(latency.Microseconds())
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
