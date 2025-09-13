package middleware

import (
	"fmt"
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

// Handle evaluates the request against all rules using HTTP middleware pattern
func (rm *RulesMiddleware) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	rules := rm.configMgr.GetRules()

	// No rules configured, allow by default
	if rules == nil {
		next.ServeHTTP(w, r)
		return
	}

	for _, rule := range rules {
		if rm.matchesRule(r, rule) {
			actions := rm.configMgr.GetActions()

			action, exists := actions[rule.Action]
			if !exists {
				log.Printf("[middleware:rules] Rule %s references unknown action: %s", rule.ID, rule.Action)
				continue
			}

			// Set rule match information in context for logging
			SetRuleMatch(r, rule.ID, action.Action)

			if action.Action == "block" {
				// Add Via header to blocked responses to match proxied responses and our stream ID
				w.Header().Add("Via", fmt.Sprintf("%d.%d flowguard", r.ProtoMajor, r.ProtoMinor))
				w.Header().Add("FG-Stream", GetStreamID(r))

				http.Error(w, action.Message, action.Status)

				return
			}
		}
	}

	// No rules matched, allow the request
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
func (rm *RulesMiddleware) matchesConditions(r *http.Request, conditions *config.Conditions) bool {
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
		case "AND":
			for _, group := range conditions.Groups {
				if !rm.matchesConditions(r, &group) {
					return false
				}
			}
			return true
		case "OR":
			for _, group := range conditions.Groups {
				if rm.matchesConditions(r, &group) {
					return true
				}
			}
			return false
		case "NOT":
			// NOT should have exactly one group
			if len(conditions.Groups) == 1 {
				return !rm.matchesConditions(r, &conditions.Groups[0])
			}
			// For NOT with matches, evaluate as NOT(OR(matches))
			if len(conditions.Matches) > 0 {
				return !rm.evaluateMatches(r, "OR", conditions.Matches)
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
		case "AND":
			if !matchesResult {
				return false
			}
			for _, group := range conditions.Groups {
				if !rm.matchesConditions(r, &group) {
					return false
				}
			}
			return true
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
func (rm *RulesMiddleware) evaluateMatches(r *http.Request, operator string, matches []config.Match) bool {
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
	case "NOT":
		for _, match := range matches {
			if rm.evaluateMatch(r, &match) {
				return false
			}
		}
		return true
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
func (rm *RulesMiddleware) evaluateMatch(r *http.Request, match *config.Match) bool {
	var value string

	// Extract the value based on type
	switch match.Type {
	case "path":
		value = r.URL.Path
	case "domain", "host":
		value = r.Host
	case "agent", "user-agent":
		value = r.Header.Get("User-Agent")
	case "header":
		// For header type, the value field contains the header name
		value = r.Header.Get(match.Value)
		// For header existence checks
		if match.Match == "exists" {
			return value != ""
		} else if match.Match == "missing" {
			return value == ""
		}
		return rm.matchesStringValue(value, match)
	case "ipset":
		return rm.matchesIPSet(r, match)
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
	case "ip":
		clientIP := GetClientIP(r)
		host, _, err := net.SplitHostPort(clientIP)
		if err != nil {
			host = clientIP
		}
		value = host
	default:
		log.Printf("[middleware:rules] Unknown match type: %s", match.Type)
		return false
	}

	return rm.matchesStringValue(value, match)
}

// matchesStringValue checks if a string value matches the given criteria
func (rm *RulesMiddleware) matchesStringValue(value string, match *config.Match) bool {
	// Handle regex matching
	if match.Match == "regex" {
		re := match.GetCompiledRegex()
		if re == nil {
			return false
		}
		return re.MatchString(value)
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
	case "not-equals", "does-not-equal":
		return compareValue != matchValue
	case "contains":
		return strings.Contains(compareValue, matchValue)
	case "not-contains", "does-not-contain":
		return !strings.Contains(compareValue, matchValue)
	case "starts-with":
		return strings.HasPrefix(compareValue, matchValue)
	case "not-starts-with", "does-not-start-with":
		return !strings.HasPrefix(compareValue, matchValue)
	case "ends-with":
		return strings.HasSuffix(compareValue, matchValue)
	case "not-ends-with", "does-not-end-with":
		return !strings.HasSuffix(compareValue, matchValue)
	default:
		log.Printf("[middleware:rules] Unknown match type: %s", match.Match)
		return false
	}
}

// matchesIPSet checks if the client IP is in the specified ipset
func (rm *RulesMiddleware) matchesIPSet(r *http.Request, match *config.Match) bool {
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
