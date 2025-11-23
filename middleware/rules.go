package middleware

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"flowguard/config"
	"flowguard/normalization"
)

//go:embed static/blocked.html
var blockedHTML []byte

// ConfigProvider interface for accessing configuration
type ConfigProvider interface {
	GetRules() map[string]*config.Rule
	GetSortedRules() []*config.Rule
	GetActions() map[string]*config.RuleAction
}

// IPListManager interface for IP list lookups
type IPListManager interface {
	Contains(listName string, ip string) bool
}

// RulesMiddleware implements dynamic rule-based filtering
type RulesMiddleware struct {
	configMgr     ConfigProvider
	rateLimiter   *RateLimiter
	keyGenerator  *RateLimitKeyGenerator
	ipListManager IPListManager
}

// NewRulesMiddleware creates a new rules-based middleware with integrated rate limiting
func NewRulesMiddleware(configMgr ConfigProvider) *RulesMiddleware {
	return &RulesMiddleware{
		configMgr:    configMgr,
		rateLimiter:  NewRateLimiter(time.Minute * 10), // Stop every 10 minutes
		keyGenerator: NewRateLimitKeyGenerator(),
	}
}

// SetIPListManager sets the IP list manager for iplist rule matching
func (rm *RulesMiddleware) SetIPListManager(manager IPListManager) {
	rm.ipListManager = manager
}

// Handle evaluates the request against all rules using HTTP middleware pattern
func (rm *RulesMiddleware) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	// Get pre-sorted rules for efficient iteration
	rules := rm.configMgr.GetSortedRules()

	// No rules configured, allow by default
	if rules == nil || len(rules) == 0 {
		next.ServeHTTP(w, r)
		return
	}

ruleLoop:
	for _, rule := range rules {
		if rm.matchesRule(r, rule) {
			actions := rm.configMgr.GetActions()

			action, exists := actions[rule.Action]
			if !exists {
				log.Printf("[middleware:rules] Rule %s references unknown action: %s", rule.ID, rule.Action)
				continue
			}

			switch action.Action {
			case "log":
				// Mark the rule as matched and continue processing
				// This allows subsequent rules to override the log action
				SetRuleMatch(r, rule, action, "log")
				continue

			case "allow":
				// Mark the rule as matched and allow the request
				SetRuleMatch(r, rule, action, "proxy")
				break ruleLoop

			case "block":
				blockRequest(w, r, action, rule)
				return

			case "rate_limit":
				// We only support one rate limit match per request
				if GetRuleMatched(r) != nil {
					continue
				}

				allowed, remaining, resetTime := rm.rateLimiter.IsAllowed(
					rm.keyGenerator.GenerateKey(rule.ID, rule, r),
					action.RequestsPerWindow,
					action.WindowSeconds,
				)

				if !allowed {
					w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", action.RequestsPerWindow))
					w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
					w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime.Unix()))
					w.Header().Set("X-RateLimit-Policy", fmt.Sprintf("%d;w=%d", action.RequestsPerWindow, action.WindowSeconds))

					blockRequest(w, r, action, rule)
					return
				}

				// We allow the request, but we mark it as matched but without an action taken
				SetRuleMatch(r, rule, nil, "proxy")
				continue

			default:
				log.Printf("[middleware:rules] Unknown action type: %s", action.Action)
				continue
			}
		}
	}

	// No blocking rules matched, allow the request
	next.ServeHTTP(w, r)
}

// matchesRule checks if a request matches a specific rule
func (rm *RulesMiddleware) matchesRule(r *http.Request, rule *config.Rule) bool {
	if rule.Conditions == nil {
		return false
	}
	return rm.matchesConditions(r, rule.Conditions)
}

// matchesConditions evaluates conditions recursively
func (rm *RulesMiddleware) matchesConditions(r *http.Request, conditions *config.RuleConditions) bool {
	// Determine the operator, defaulting to AND
	operator := conditions.Operator
	if operator == "" {
		operator = "AND"
	}

	// Handle leaf conditions (matches only)
	if len(conditions.Matches) > 0 && len(conditions.Groups) == 0 {
		return rm.evaluateMatches(r, operator, conditions.Matches)
	}

	// Handle group conditions (groups only)
	if len(conditions.Matches) == 0 && len(conditions.Groups) > 0 {
		switch operator {
		case "OR":
			for _, group := range conditions.Groups {
				if rm.matchesConditions(r, &group) {
					return true
				}
			}
			return false
		default:
			// Default to AND for unknown operators
			for _, group := range conditions.Groups {
				if !rm.matchesConditions(r, &group) {
					return false
				}
			}
			return true
		}
	}

	// Handle mixed conditions (both matches and groups)
	if len(conditions.Matches) > 0 && len(conditions.Groups) > 0 {
		matchesResult := rm.evaluateMatches(r, "OR", conditions.Matches)

		switch operator {
		case "OR":
			if matchesResult {
				return true
			}
			for _, group := range conditions.Groups {
				if rm.matchesConditions(r, &group) {
					return true
				}
			}
			return false
		default:
			// Default to AND
			if !matchesResult {
				return false
			}
			for _, group := range conditions.Groups {
				if !rm.matchesConditions(r, &group) {
					return false
				}
			}
			return true
		}
	}

	return false
}

// evaluateMatches evaluates a list of matches with the specified operator
func (rm *RulesMiddleware) evaluateMatches(r *http.Request, operator string, matches []config.MatchCondition) bool {
	if len(matches) == 0 {
		return false
	}

	switch operator {
	case "OR":
		for _, match := range matches {
			if rm.evaluateMatch(r, &match) {
				return true
			}
		}
		return false
	default:
		// Default to AND
		for _, match := range matches {
			if !rm.evaluateMatch(r, &match) {
				return false
			}
		}
		return true
	}
}

// evaluateMatch evaluates a single match condition
func (rm *RulesMiddleware) evaluateMatch(r *http.Request, match *config.MatchCondition) bool {
	var value string

	// Extract the value based on type
	switch match.Type {
	case "domain":
		value = r.Host
	case "path":
		// Use raw path if raw_match is true, otherwise normalize for consistent matching
		if match.RawMatch {
			value = r.URL.Path
		} else {
			// Normalize the path for consistent matching (Cloudflare-style normalization)
			value = normalization.NormalizePath(r.URL.Path)
		}
	case "header":
		// For header type, the Key field contains the header name
		headerName := match.Key
		if headerName == "" {
			log.Printf("[middleware:rules] Header match missing 'key' field for header name")
			return false
		}
		value = r.Header.Get(headerName)
		// For header existence checks
		if match.Match == "exists" {
			return value != ""
		} else if match.Match == "missing" {
			return value == ""
		}
		return rm.matchesStringValue(value, match)
	case "user-agent":
		value = r.Header.Get("User-Agent")
	case "ip":
		clientIP := GetClientIP(r)
		host, _, err := net.SplitHostPort(clientIP)
		if err != nil {
			host = clientIP
		}
		value = host
	case "asn":
		clientASNInfo := GetClientASN(r)
		if clientASNInfo == nil {
			return false
		}
		clientASN := clientASNInfo.GetASN()
		if clientASN == 0 {
			return false
		}
		value = fmt.Sprintf("%d", clientASN)
	case "as-name":
		clientASNInfo := GetClientASN(r)
		if clientASNInfo == nil {
			return false
		}
		value = clientASNInfo.ASName
	case "as-domain":
		clientASNInfo := GetClientASN(r)
		if clientASNInfo == nil {
			return false
		}
		value = clientASNInfo.ASDomain
	case "country":
		clientASNInfo := GetClientASN(r)
		if clientASNInfo == nil {
			return false
		}
		value = clientASNInfo.CountryCode
	case "continent":
		clientASNInfo := GetClientASN(r)
		if clientASNInfo == nil {
			return false
		}
		value = clientASNInfo.ContinentCode
	case "ipset":
		return rm.matchesIPSet(r, match)
	case "iplist":
		return rm.matchesIPList(r, match)
	default:
		log.Printf("[middleware:rules] Unknown match type: %s", match.Type)
		return false
	}

	return rm.matchesStringValue(value, match)
}

// matchesStringValue checks if a string value matches the given criteria
func (rm *RulesMiddleware) matchesStringValue(value string, match *config.MatchCondition) bool {
	// Handle regex matching
	if match.Match == "regex" || match.Match == "not-regex" {
		re := match.GetCompiledRegex()
		if re == nil {
			return false
		}
		matched := re.MatchString(value)
		if match.Match == "not-regex" {
			return !matched
		}
		return matched
	}

	// Apply case-insensitive matching if requested
	compareValue := value
	matchValue := match.Value
	if match.CaseInsensitive {
		compareValue = strings.ToLower(value)
		matchValue = strings.ToLower(match.Value)
	}

	// Handle list-based matches
	if len(match.Values) > 0 {
		switch match.Match {
		case "in":
			for _, v := range match.Values {
				if match.CaseInsensitive {
					if strings.ToLower(v) == compareValue {
						return true
					}
				} else {
					if v == value {
						return true
					}
				}
			}
			return false
		case "not-in":
			for _, v := range match.Values {
				if match.CaseInsensitive {
					if strings.ToLower(v) == compareValue {
						return false
					}
				} else {
					if v == value {
						return false
					}
				}
			}
			return true
		}
	}

	// Handle string matches
	switch match.Match {
	case "equals":
		return compareValue == matchValue
	case "not-equals":
		return compareValue != matchValue
	case "contains":
		return strings.Contains(compareValue, matchValue)
	case "not-contains":
		return !strings.Contains(compareValue, matchValue)
	case "starts-with":
		return strings.HasPrefix(compareValue, matchValue)
	case "not-starts-with":
		return !strings.HasPrefix(compareValue, matchValue)
	case "ends-with":
		return strings.HasSuffix(compareValue, matchValue)
	case "not-ends-with":
		return !strings.HasSuffix(compareValue, matchValue)
	default:
		log.Printf("[middleware:rules] Unknown match type: %s", match.Match)
		return false
	}
}

// matchesIPSet checks if the client IP is in the specified ipset
func (rm *RulesMiddleware) matchesIPSet(r *http.Request, match *config.MatchCondition) bool {
	clientIP := GetClientIP(r)
	host, _, err := net.SplitHostPort(clientIP)
	if err != nil {
		host = clientIP
	}

	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return false
	}

	isIPv4 := parsedIP.To4() != nil

	// Check if IP family matches
	if match.Family != 0 {
		if (match.Family == 4 && !isIPv4) || (match.Family == 6 && isIPv4) {
			return false
		}
	}

	// Test if IP is in the ipset
	cmd := exec.Command("ipset", "test", match.Value, host)
	err = cmd.Run()

	// Handle "in" vs "not-in"
	if match.Match == "not-in" {
		return err != nil // IP is NOT in the set
	}
	return err == nil // IP IS in the set
}

// matchesIPList checks if the client IP is in the specified in-memory IP list
func (rm *RulesMiddleware) matchesIPList(r *http.Request, match *config.MatchCondition) bool {
	// Check if IP list manager is available
	if rm.ipListManager == nil {
		log.Printf("[middleware:rules] IPList manager not initialized, cannot check list %s", match.Value)
		return false
	}

	clientIP := GetClientIP(r)
	host, _, err := net.SplitHostPort(clientIP)
	if err != nil {
		host = clientIP
	}

	// Parse IP to validate it
	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return false
	}

	// Check if IP is in the named list
	contains := rm.ipListManager.Contains(match.Value, host)

	// Handle "in" vs "not-in"
	if match.Match == "not-in" {
		return !contains // IP is NOT in the list
	}
	return contains // IP IS in the list
}

// Stop stops the rate limiter cleanup process
func (rm *RulesMiddleware) Stop() {
	if rm.rateLimiter != nil {
		rm.rateLimiter.Stop()
	}
}

// acceptsHTML checks if the request accepts HTML responses
func acceptsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	// Check if Accept header contains text/html
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

// blockRequest sends a block response based on the action configuration
func blockRequest(w http.ResponseWriter, r *http.Request, action *config.RuleAction, rule *config.Rule) {
	// Set rule match information in context for logging
	SetRuleMatch(r, rule, action, action.Action)

	streamID := GetStreamID(r)

	// Add Via header to blocked responses to match proxied responses and our stream ID
	w.Header().Add("Via", fmt.Sprintf("%d.%d flowguard", r.ProtoMajor, r.ProtoMinor))
	w.Header().Add("FG-Stream", streamID)

	// Use configured status and message, or defaults
	message := action.Message
	if message == "" {
		switch action.Action {
		case "rate_limit":
			message = "Rate limit exceeded"
		default:
			message = "Forbidden"
		}
	}

	status := action.Status
	if status == 0 {
		switch action.Action {
		case "rate_limit":
			status = http.StatusTooManyRequests
		default:
			status = http.StatusForbidden
		}
	}

	if acceptsHTML(r) {
		// Replace placeholders in the HTML template
		html := bytes.ReplaceAll(blockedHTML, []byte("%%STREAM_ID%%"), []byte(streamID))
		html = bytes.ReplaceAll(html, []byte("%%MESSAGE%%"), []byte(message))

		h := w.Header()

		// Delete the Content-Length header, which might be for some other content.
		// Assuming the error string fits in the writer's buffer, we'll figure
		// out the correct Content-Length for it later.
		//
		// We don't delete Content-Encoding, because some middleware sets
		// Content-Encoding: gzip and wraps the ResponseWriter to compress on-the-fly.
		// See https://go.dev/issue/66343.
		h.Del("Content-Length")

		// There might be content type already set, but we reset it to text/html for the error page.
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("X-Content-Type-Options", "nosniff")

		w.WriteHeader(status)

		fmt.Fprintln(w, html)

		return
	}

	// Fall back to plain text response
	http.Error(w, message, status)
}

// RateLimiter manages rate limiting counters using sliding window algorithm
type RateLimiter struct {
	entries       map[string]*RateLimitEntry
	mutex         sync.RWMutex
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// RateLimitEntry represents a sliding window counter for rate limiting
type RateLimitEntry struct {
	timestamps []time.Time // Sliding window of request timestamps
	mutex      sync.RWMutex
}

// NewRateLimiter creates a new rate limiter with automatic cleanup
func NewRateLimiter(cleanupInterval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		entries:     make(map[string]*RateLimitEntry),
		stopCleanup: make(chan struct{}),
	}

	// Start cleanup goroutine
	rl.cleanupTicker = time.NewTicker(cleanupInterval)
	go rl.cleanupLoop()

	return rl
}

// IsAllowed checks if a request should be allowed based on rate limiting
// Returns (allowed, remainingRequests, resetTime)
func (rl *RateLimiter) IsAllowed(key string, maxRequests int, windowSeconds int) (bool, int, time.Time) {
	now := time.Now()
	windowDuration := time.Duration(windowSeconds) * time.Second
	windowStart := now.Add(-windowDuration)

	rl.mutex.RLock()
	entry, exists := rl.entries[key]
	rl.mutex.RUnlock()

	if !exists {
		// Create new entry
		entry = &RateLimitEntry{
			timestamps: make([]time.Time, 0),
		}
		rl.mutex.Lock()
		rl.entries[key] = entry
		rl.mutex.Unlock()
	}

	entry.mutex.Lock()
	defer entry.mutex.Unlock()

	// Remove timestamps outside the current window
	validTimestamps := make([]time.Time, 0, len(entry.timestamps))
	for _, ts := range entry.timestamps {
		if ts.After(windowStart) {
			validTimestamps = append(validTimestamps, ts)
		}
	}
	entry.timestamps = validTimestamps

	currentCount := len(entry.timestamps)

	if currentCount >= maxRequests {
		// Rate limit exceeded
		var resetTime time.Time
		if len(entry.timestamps) > 0 {
			// Reset time is when the oldest request in the window expires
			resetTime = entry.timestamps[0].Add(windowDuration)
		} else {
			resetTime = now.Add(windowDuration)
		}
		return false, 0, resetTime
	}

	// Allow the request and record timestamp
	entry.timestamps = append(entry.timestamps, now)
	remaining := maxRequests - (currentCount + 1)
	resetTime := now.Add(windowDuration)

	return true, remaining, resetTime
}

// cleanupLoop periodically removes expired entries to prevent memory leaks
func (rl *RateLimiter) cleanupLoop() {
	for {
		select {
		case <-rl.cleanupTicker.C:
			rl.cleanup()
		case <-rl.stopCleanup:
			rl.cleanupTicker.Stop()
			return
		}
	}
}

// cleanup removes entries that haven't been accessed recently
func (rl *RateLimiter) cleanup() {
	now := time.Now()
	cleanupThreshold := now.Add(-time.Hour) // Remove entries older than 1 hour

	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	for key, entry := range rl.entries {
		entry.mutex.RLock()
		shouldDelete := len(entry.timestamps) == 0 ||
			(len(entry.timestamps) > 0 && entry.timestamps[len(entry.timestamps)-1].Before(cleanupThreshold))
		entry.mutex.RUnlock()

		if shouldDelete {
			delete(rl.entries, key)
		}
	}
}

// Stop stops the cleanup goroutine
func (rl *RateLimiter) Stop() {
	close(rl.stopCleanup)
}

// GetStats returns current rate limiter statistics
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_keys"] = len(rl.entries)

	activeKeys := 0
	now := time.Now()
	recentThreshold := now.Add(-time.Minute * 5) // Consider active if accessed in last 5 minutes

	for _, entry := range rl.entries {
		entry.mutex.RLock()
		if len(entry.timestamps) > 0 && entry.timestamps[len(entry.timestamps)-1].After(recentThreshold) {
			activeKeys++
		}
		entry.mutex.RUnlock()
	}

	stats["active_keys"] = activeKeys
	return stats
}

// RateLimitKeyGenerator generates unique keys for rate limiting based on rule conditions
type RateLimitKeyGenerator struct{}

// NewRateLimitKeyGenerator creates a new key generator
func NewRateLimitKeyGenerator() *RateLimitKeyGenerator {
	return &RateLimitKeyGenerator{}
}

// GenerateKey creates a unique key for rate limiting based on rule and request context
func (kg *RateLimitKeyGenerator) GenerateKey(ruleID string, rule *config.Rule, r *http.Request) string {
	// Build a deterministic key based on rule conditions and matched values
	var keyParts []string
	keyParts = append(keyParts, "rule:"+ruleID)

	if rule.Conditions != nil {
		kg.extractKeyParts(rule.Conditions, r, &keyParts)
	}

	// Sort key parts for consistent hashing
	sort.Strings(keyParts)

	// Create a hash of all key parts
	h := sha256.New()
	for _, part := range keyParts {
		h.Write([]byte(part))
		h.Write([]byte("|"))
	}

	return fmt.Sprintf("rl_%x", h.Sum(nil)[:16])
}

// extractKeyParts recursively extracts key components from rule conditions
func (kg *RateLimitKeyGenerator) extractKeyParts(conditions *config.RuleConditions, r *http.Request, keyParts *[]string) {
	// Process matches
	for _, match := range conditions.Matches {
		switch match.Type {
		case "domain", "host":
			*keyParts = append(*keyParts, "domain:"+r.Host)
		case "agent", "user-agent":
			agent := r.Header.Get("User-Agent")
			if agent != "" {
				*keyParts = append(*keyParts, "agent:"+agent)
			}
		case "path":
			*keyParts = append(*keyParts, "path:"+r.URL.Path)
		case "header":
			headerName := match.Key
			if headerName != "" {
				headerValue := r.Header.Get(headerName)
				if headerValue != "" {
					*keyParts = append(*keyParts, "header:"+headerName+":"+headerValue)
				}
			}
		case "asn":
			clientASNInfo := GetClientASN(r)
			if clientASNInfo != nil {
				asn := clientASNInfo.GetASN()
				if asn != 0 {
					*keyParts = append(*keyParts, fmt.Sprintf("asn:%d", asn))
				}
			}
		case "ip":
			clientIP := GetClientIP(r)
			if clientIP != "" {
				*keyParts = append(*keyParts, "ip:"+clientIP)
			}
		}
	}

	// Process nested groups
	for _, group := range conditions.Groups {
		kg.extractKeyParts(&group, r, keyParts)
	}
}
