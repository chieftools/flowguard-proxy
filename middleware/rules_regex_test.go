package middleware

import (
	"testing"

	"flowguard/config"
)

func TestRegexStringMatcher(t *testing.T) {
	rm := &RulesMiddleware{}

	tests := []struct {
		name      string
		value     string
		criterion config.MatchCriteria
		expected  bool
	}{
		{
			name:  "Regex matches Chrome 80",
			value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
			criterion: config.MatchCriteria{
				Match: "regex",
				Value: "Chrome/8[0-9]\\.",
			},
			expected: true,
		},
		{
			name:  "Regex matches Chrome 89",
			value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
			criterion: config.MatchCriteria{
				Match: "regex",
				Value: "Chrome/8[0-9]\\.",
			},
			expected: true,
		},
		{
			name:  "Regex does not match Chrome 120",
			value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			criterion: config.MatchCriteria{
				Match: "regex",
				Value: "Chrome/8[0-9]\\.",
			},
			expected: false,
		},
		{
			name:  "Regex does not match Chrome 79",
			value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36",
			criterion: config.MatchCriteria{
				Match: "regex",
				Value: "Chrome/8[0-9]\\.",
			},
			expected: false,
		},
		{
			name:  "Regex does not match Firefox",
			value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
			criterion: config.MatchCriteria{
				Match: "regex",
				Value: "Chrome/8[0-9]\\.",
			},
			expected: false,
		},
		{
			name:  "Regex with case insensitive flag",
			value: "Test PATTERN here",
			criterion: config.MatchCriteria{
				Match:           "regex",
				Value:           "pattern",
				CaseInsensitive: true,
			},
			expected: true,
		},
		{
			name:  "Regex without case insensitive flag",
			value: "Test PATTERN here",
			criterion: config.MatchCriteria{
				Match: "regex",
				Value: "pattern",
			},
			expected: false,
		},
		{
			name:  "Invalid regex pattern",
			value: "Test string",
			criterion: config.MatchCriteria{
				Match: "regex",
				Value: "[invalid(regex",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compile regex before testing
			criterion := tt.criterion
			criterion.CompileRegexIfNeeded()

			result := rm.matchesString(tt.value, criterion)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
