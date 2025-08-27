package middleware

import (
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"

	"flowguard/config"
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

			clientIP := GetClientIP(r)
			log.Printf("[middleware:rules] Rule %s matched (action: %s) for %s from %s", rule.ID, rule.Action, r.Host, clientIP)

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

	// Check ASN criteria
	if len(rule.ASNs) > 0 {
		if !rm.matchesASNCriteria(r, rule.ASNs) {
			return false
		}
	}

	// If we have at least one criteria type and all matched, return true
	return len(rule.Agents) > 0 || len(rule.Domains) > 0 || len(rule.Paths) > 0 || len(rule.IPSet) > 0 || len(rule.ASNs) > 0
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

// matchesASNCriteria checks if the client's ASN matches any of the specified ASNs
func (rm *RulesMiddleware) matchesASNCriteria(r *http.Request, asns []uint) bool {
	// Get the client ASN from the request context (set by IPLookupMiddleware)
	clientASNInfo := GetClientASN(r)
	if clientASNInfo == nil {
		return false
	}

	clientASN := clientASNInfo.GetASN()
	if clientASNInfo.GetASN() == 0 {
		return false
	}

	// Check if client ASN matches any of the specified ASNs (OR logic)
	for _, asn := range asns {
		if clientASN == asn {
			return true
		}
	}

	return false
}

// matchesString checks if a string matches the given criteria
func (rm *RulesMiddleware) matchesString(value string, criterion config.MatchCriteria) bool {
	if criterion.Match == "regex" {
		re := criterion.GetCompiledRegex()
		if re == nil {
			return false
		}

		return re.MatchString(value)
	}

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
