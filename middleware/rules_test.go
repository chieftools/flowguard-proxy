package middleware

import (
	"regexp"
	"testing"

	"flowguard/config"
)

func TestStringMatcher(t *testing.T) {
	rm := &RulesMiddleware{}

	tests := []struct {
		name     string
		value    string
		match    config.Match
		expected bool
	}{
		{
			name:  "Equals match",
			value: "example.com",
			match: config.Match{
				Type:  "domain",
				Match: "equals",
				Value: "example.com",
			},
			expected: true,
		},
		{
			name:  "Not equals match",
			value: "other.com",
			match: config.Match{
				Type:  "domain",
				Match: "not-equals",
				Value: "example.com",
			},
			expected: true,
		},
		{
			name:  "In list match",
			value: "naturel.info",
			match: config.Match{
				Type:   "domain",
				Match:  "in",
				Values: []string{"naturel.info", "www.naturel.info"},
			},
			expected: true,
		},
		{
			name:  "Not in list match",
			value: "other.com",
			match: config.Match{
				Type:   "domain",
				Match:  "not-in",
				Values: []string{"naturel.info", "www.naturel.info"},
			},
			expected: true,
		},
		{
			name:  "Not in list - should fail for listed domain",
			value: "naturel.info",
			match: config.Match{
				Type:   "domain",
				Match:  "not-in",
				Values: []string{"naturel.info", "www.naturel.info"},
			},
			expected: false,
		},
		{
			name:  "Contains match",
			value: "www.example.com",
			match: config.Match{
				Type:  "domain",
				Match: "contains",
				Value: "example",
			},
			expected: true,
		},
		{
			name:  "Starts with match",
			value: "dev.example.com",
			match: config.Match{
				Type:  "domain",
				Match: "starts-with",
				Value: "dev.",
			},
			expected: true,
		},
		{
			name:  "Ends with match",
			value: "api.example.com",
			match: config.Match{
				Type:  "domain",
				Match: "ends-with",
				Value: ".com",
			},
			expected: true,
		},
		{
			name:  "Case insensitive match",
			value: "EXAMPLE.COM",
			match: config.Match{
				Type:            "domain",
				Match:           "equals",
				Value:           "example.com",
				CaseInsensitive: true,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rm.matchesStringValue(tt.value, &tt.match)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRegexMatcher(t *testing.T) {
	rm := &RulesMiddleware{}

	tests := []struct {
		name     string
		value    string
		match    config.Match
		expected bool
	}{
		{
			name:  "Regex matches Chrome 80",
			value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
			match: config.Match{
				Type:  "agent",
				Match: "regex",
				Value: "Chrome/8[0-9]\\.",
			},
			expected: true,
		},
		{
			name:  "Regex matches Chrome 89",
			value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
			match: config.Match{
				Type:  "agent",
				Match: "regex",
				Value: "Chrome/8[0-9]\\.",
			},
			expected: true,
		},
		{
			name:  "Regex does not match Chrome 120",
			value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			match: config.Match{
				Type:  "agent",
				Match: "regex",
				Value: "Chrome/8[0-9]\\.",
			},
			expected: false,
		},
		{
			name:  "Regex with case insensitive flag",
			value: "Test PATTERN here",
			match: config.Match{
				Type:            "agent",
				Match:           "regex",
				Value:           "pattern",
				CaseInsensitive: true,
			},
			expected: true,
		},
		{
			name:  "Regex without case insensitive flag",
			value: "Test PATTERN here",
			match: config.Match{
				Type:  "agent",
				Match: "regex",
				Value: "pattern",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compile regex before testing
			match := tt.match
			if match.Match == "regex" {
				pattern := match.Value
				if match.CaseInsensitive {
					pattern = "(?i)" + pattern
				}
				re, err := regexp.Compile(pattern)
				if err == nil {
					match.SetCompiledRegexInternal(re)
				}
			}

			result := rm.matchesStringValue(tt.value, &match)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

