package normalization

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestParseQuery(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected url.Values
	}{
		{"simple", "a=1&b=2", url.Values{"a": {"1"}, "b": {"2"}}},
		{"repeated key", "q=ok&q=evil", url.Values{"q": {"ok", "evil"}}},
		{"plus and escapes", "q=union+select%20%31", url.Values{"q": {"union select 1"}}},
		{"encoded key", "de%62ug=1", url.Values{"debug": {"1"}}},
		{"semicolon in value", "q=1+union+select;", url.Values{"q": {"1 union select;"}}},
		{"semicolon is not a separator", "x=1;debug=1", url.Values{"x": {"1;debug=1"}}},
		{"invalid escape kept literal", "q=%zz'+union+select", url.Values{"q": {"%zz' union select"}}},
		{"truncated escapes", "a=%&b=%2", url.Values{"a": {"%"}, "b": {"%2"}}},
		{"key without value", "debug&x=", url.Values{"debug": {""}, "x": {""}}},
		{"empty pairs skipped", "&&a=1&&", url.Values{"a": {"1"}}},
		{"empty", "", url.Values{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseQuery(tt.input); !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ParseQuery(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseQueryHasNoParameterLimit(t *testing.T) {
	query := "q=evil" + strings.Repeat("&", 10001)
	if got := ParseQuery(query).Get("q"); got != "evil" {
		t.Errorf("expected q to survive more than 10000 separators, got %q", got)
	}
}
