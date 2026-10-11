package config

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"flowguard/normalization"
)

// compileConditionRegex recursively compiles regex patterns in conditions
func (m *Manager) compileConditionRegex(cond *RuleConditions) {
	// Compile regex in matches
	for i := range cond.Matches {
		if cond.Matches[i].Match == "regex" || cond.Matches[i].Match == "not-regex" {
			pattern := cond.Matches[i].Value
			if cond.Matches[i].CaseInsensitive || isHostMatchType(cond.Matches[i].Type) {
				pattern = "(?i)" + pattern
			}
			re, err := compileMatchRegex(pattern)
			if err != nil {
				log.Printf("[config] Warning: Invalid regex pattern '%s': %v", cond.Matches[i].Value, err)
			} else {
				cond.Matches[i].compiledRegex = re
			}
		}
	}

	// Recursively compile in groups
	for i := range cond.Groups {
		m.compileConditionRegex(&cond.Groups[i])
	}
}

// normalizeHostMatchValues recursively normalizes the values of domain and
// registerable-domain matches. Request hosts are normalized before matching
// (see normalization.Host), so configured values must be too: exact matches
// get the full host normalization and partial matches are lowercased.
func normalizeHostMatchValues(cond *RuleConditions) {
	for i := range cond.Matches {
		match := &cond.Matches[i]
		if !isHostMatchType(match.Type) || match.Match == "regex" || match.Match == "not-regex" {
			continue
		}

		normalize := strings.ToLower
		switch match.Match {
		case "equals", "not-equals", "in", "not-in":
			normalize = normalization.Host
		}

		match.Value = normalize(match.Value)
		for j := range match.Values {
			match.Values[j] = normalize(match.Values[j])
		}
	}

	for i := range cond.Groups {
		normalizeHostMatchValues(&cond.Groups[i])
	}
}

func isHostMatchType(matchType string) bool {
	return matchType == "domain" || matchType == "registerable-domain"
}

func validateConditionOperators(ruleID string, cond *RuleConditions, path string) error {
	if cond == nil {
		return nil
	}

	operator := normalizeConditionOperator(cond.Operator)
	if operator != "" && !isSupportedConditionOperator(operator) {
		return fmt.Errorf("invalid operator %q in rule %q at %s", cond.Operator, ruleID, path)
	}

	for i := range cond.Groups {
		groupPath := fmt.Sprintf("%s.groups[%d]", path, i)
		if err := validateConditionOperators(ruleID, &cond.Groups[i], groupPath); err != nil {
			return err
		}
	}

	return nil
}

func normalizeConditionOperator(operator string) string {
	return strings.TrimSpace(operator)
}

func isSupportedConditionOperator(operator string) bool {
	return operator == "" || operator == "AND" || operator == "OR" || operator == "NAND" || operator == "NOR"
}

func compileMatchRegex(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(pattern)
}
