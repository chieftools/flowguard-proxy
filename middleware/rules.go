package middleware

import (
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"

	"http-sec-proxy/config"
)

// RulesMiddleware implements dynamic rule-based filtering
type RulesMiddleware struct {
	configMgr *config.Manager
}

// NewRulesMiddleware creates a new rules-based middleware
func NewRulesMiddleware(configMgr *config.Manager) *RulesMiddleware {
	return &RulesMiddleware{
		configMgr: configMgr,
	}
}

// Process evaluates the request against all rules
func (rm *RulesMiddleware) Process(w http.ResponseWriter, r *http.Request) (bool, int, string) {
	rules := rm.configMgr.GetRules()

	// No rules configured, allow by default
	if rules == nil {
		return true, 0, ""
	}

	for _, rule := range rules.Match {
		if rm.matchesRule(r, rule) {
			action, exists := rules.Actions[rule.Action]
			if !exists {
				log.Printf("[middleware:rules] Rule %s references unknown action: %s", rule.ID, rule.Action)
				continue
			}

			log.Printf("[middleware:rules] Rule %s matched (action: %s) for %s from %s", rule.ID, rule.Action, r.URL.Hostname(), rm.getClientIP(r))

			if action.Action == "block" {
				return false, action.Status, action.Message
			}
		}
	}

	// No rules matched, allow the request
	return true, 0, ""
}

// matchesRule checks if a request matches a specific rule
func (rm *RulesMiddleware) matchesRule(r *http.Request, rule *config.Rule) bool {
	// All criteria within a rule must match (AND logic)

	// Check agent criteria
	if len(rule.Agents) > 0 {
		if !rm.matchesAgentCriteria(r, rule.Agents) {
			return false
		}
	}

	// Check domain criteria
	if len(rule.Domains) > 0 {
		if !rm.matchesDomainCriteria(r, rule.Domains) {
			return false
		}
	}

	// Check path criteria
	if len(rule.Paths) > 0 {
		if !rm.matchesPathCriteria(r, rule.Paths) {
			return false
		}
	}

	// Check IPSet criteria
	if len(rule.IPSet) > 0 {
		if !rm.matchesIPSetCriteria(r, rule.IPSet) {
			return false
		}
	}

	// If we have at least one criteria type and all matched, return true
	return len(rule.Agents) > 0 || len(rule.Domains) > 0 || len(rule.Paths) > 0 || len(rule.IPSet) > 0
}

// matchesAgentCriteria checks if the User-Agent matches any of the criteria
func (rm *RulesMiddleware) matchesAgentCriteria(r *http.Request, criteria []config.MatchCriteria) bool {
	userAgent := r.Header.Get("User-Agent")

	// Any agent criteria can match (OR logic within agent criteria)
	for _, criterion := range criteria {
		if rm.matchesString(userAgent, criterion) {
			return true
		}
	}
	return false
}

// matchesDomainCriteria checks if the domain matches any of the criteria
func (rm *RulesMiddleware) matchesDomainCriteria(r *http.Request, criteria []config.MatchCriteria) bool {
	domain := r.Host

	// Any domain criteria can match (OR logic within domain criteria)
	for _, criterion := range criteria {
		if rm.matchesString(domain, criterion) {
			return true
		}
	}
	return false
}

// matchesPathCriteria checks if the path matches any of the criteria
func (rm *RulesMiddleware) matchesPathCriteria(r *http.Request, criteria []config.MatchCriteria) bool {
	path := r.URL.Path

	// Any path criteria can match (OR logic within path criteria)
	for _, criterion := range criteria {
		if rm.matchesString(path, criterion) {
			return true
		}
	}
	return false
}

// matchesIPSetCriteria checks if the client IP is in any of the specified ipsets
func (rm *RulesMiddleware) matchesIPSetCriteria(r *http.Request, criteria []config.IPSetCriteria) bool {
	clientIP := rm.getClientIP(r)
	host, _, err := net.SplitHostPort(clientIP)
	if err != nil {
		host = clientIP
	}

	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return false
	}

	isIPv4 := parsedIP.To4() != nil

	// Any IPSet criteria can match (OR logic within IPSet criteria)
	for _, criterion := range criteria {
		// Check if IP family matches
		if (criterion.Family == 4 && !isIPv4) || (criterion.Family == 6 && isIPv4) {
			continue
		}

		// Test if IP is in the ipset
		cmd := exec.Command("ipset", "test", criterion.Value, host)
		err := cmd.Run()
		// If IP is in the set (test succeeds), return true
		if err == nil {
			return true
		}
	}
	return false
}

// matchesString checks if a string matches the given criteria
func (rm *RulesMiddleware) matchesString(value string, criterion config.MatchCriteria) bool {
	// Apply case-insensitive matching if requested
	compareValue := value
	criterionValue := criterion.Value
	if criterion.CaseInsensitive {
		compareValue = strings.ToLower(value)
		criterionValue = strings.ToLower(criterion.Value)
	}

	switch criterion.Match {
	case "exact":
		return compareValue == criterionValue
	case "starts-with":
		return strings.HasPrefix(compareValue, criterionValue)
	case "contains":
		return strings.Contains(compareValue, criterionValue)
	default:
		log.Printf("[middleware:rules] Unknown match type: %s", criterion.Match)
		return false
	}
}

// getClientIP extracts the real client IP considering trusted proxies
func (rm *RulesMiddleware) getClientIP(r *http.Request) string {
	// Get the immediate remote address
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	// If the remote IP is from a trusted proxy,
	// then we can trust the X-Forwarded-For or X-Real-IP headers
	if rm.configMgr.IsTrustedProxy(remoteIP) {
		// Check X-Forwarded-For header
		xff := r.Header.Get("X-Forwarded-For")

		if xff != "" {
			// Get the rightmost non-trusted IP from the chain
			ips := strings.Split(xff, ",")

			// Traverse from right to left to find the first non-trusted IP
			for i := len(ips) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(ips[i])
				if !rm.configMgr.IsTrustedProxy(ip) {
					return ip
				}
			}

			// If all IPs in the chain are trusted, use the leftmost one
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}

		// Check X-Real-IP header
		xri := r.Header.Get("X-Real-IP")
		if xri != "" {
			return xri
		}
	}

	// If not from a trusted proxy, or no headers present, use the remote address
	return remoteIP
}
