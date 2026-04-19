package config

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

// compileConditionRegex recursively compiles regex patterns in conditions
func (m *Manager) compileConditionRegex(cond *RuleConditions) {
	// Compile regex in matches
	for i := range cond.Matches {
		if cond.Matches[i].Match == "regex" {
			pattern := cond.Matches[i].Value
			if cond.Matches[i].CaseInsensitive {
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
