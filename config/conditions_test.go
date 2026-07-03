package config

import (
	"strings"
	"testing"
)

func TestValidateConditionOperatorsAcceptsSupportedOperators(t *testing.T) {
	tests := []struct {
		name     string
		operator string
	}{
		{name: "missing", operator: ""},
		{name: "and", operator: "AND"},
		{name: "or", operator: "OR"},
		{name: "nand", operator: "NAND"},
		{name: "nor", operator: "NOR"},
		{name: "trimmed", operator: " NOR "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conditions := &RuleConditions{Operator: tt.operator}
			if err := validateConditionOperators("rule-id", conditions, "conditions"); err != nil {
				t.Fatalf("expected operator %q to validate: %v", tt.operator, err)
			}
		})
	}
}

func TestValidateConditionOperatorsRejectsNestedUnsupportedOperator(t *testing.T) {
	conditions := &RuleConditions{
		Operator: "AND",
		Groups: []RuleConditions{
			{
				Operator: "NOT",
			},
		},
	}

	err := validateConditionOperators("rule-id", conditions, "conditions")
	if err == nil {
		t.Fatal("expected nested unsupported operator to be rejected")
	}
	if !strings.Contains(err.Error(), `invalid operator "NOT"`) {
		t.Fatalf("expected invalid operator in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "conditions.groups[0]") {
		t.Fatalf("expected nested path in error, got: %v", err)
	}
}

func TestCompileConditionRegexCompilesNestedConditions(t *testing.T) {
	manager := &Manager{}
	conditions := &RuleConditions{
		Matches: []MatchCondition{
			{
				Match: "regex",
				Value: "^/admin",
			},
			{
				Match: "not-regex",
				Value: "^/internal",
			},
		},
		Groups: []RuleConditions{
			{
				Matches: []MatchCondition{
					{
						Match:           "regex",
						Value:           "bot",
						CaseInsensitive: true,
					},
					{
						Match:           "not-regex",
						Value:           "crawler",
						CaseInsensitive: true,
					},
				},
			},
		},
	}

	manager.compileConditionRegex(conditions)

	if conditions.Matches[0].GetCompiledRegex() == nil {
		t.Fatal("expected top-level regex to compile")
	}
	if !conditions.Matches[0].GetCompiledRegex().MatchString("/admin/panel") {
		t.Fatal("expected top-level regex to match compiled pattern")
	}

	topLevelNotRegex := conditions.Matches[1].GetCompiledRegex()
	if topLevelNotRegex == nil {
		t.Fatal("expected top-level not-regex to compile")
	}
	if !topLevelNotRegex.MatchString("/internal/health") {
		t.Fatal("expected top-level not-regex pattern to compile as regex")
	}

	nestedRegex := conditions.Groups[0].Matches[0].GetCompiledRegex()
	if nestedRegex == nil {
		t.Fatal("expected nested regex to compile")
	}
	if !nestedRegex.MatchString("TestBot/1.0") {
		t.Fatal("expected nested case-insensitive regex to match")
	}

	nestedNotRegex := conditions.Groups[0].Matches[1].GetCompiledRegex()
	if nestedNotRegex == nil {
		t.Fatal("expected nested not-regex to compile")
	}
	if !nestedNotRegex.MatchString("GoogleCrawler/1.0") {
		t.Fatal("expected nested case-insensitive not-regex pattern to compile as regex")
	}
}
