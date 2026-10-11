package normalization

import (
	"reflect"
	"testing"
)

func TestCookieValues(t *testing.T) {
	tests := []struct {
		name     string
		headers  []string
		cookie   string
		expected []string
	}{
		{"simple", []string{"session=abc; theme=dark"}, "session", []string{"abc"}},
		{"repeated across headers", []string{"role=user", "role=admin"}, "role", []string{"user", "admin"}},
		{"backslash kept", []string{`s=a\b; t=ok`}, "s", []string{`a\b`}},
		{"stray quote kept", []string{`s=a"b`}, "s", []string{`a"b`}},
		{"non-ASCII kept", []string{"s=héllo"}, "s", []string{"héllo"}},
		{"quoted value", []string{`u="q"`}, "u", []string{`"q"`, "q"}},
		{"percent-decoded", []string{"q=%3Cscript%3E"}, "q", []string{"%3Cscript%3E", "<script>"}},
		{"invalid escape kept", []string{"q=%zz"}, "q", []string{"%zz"}},
		{"empty value", []string{"flag="}, "flag", []string{""}},
		{"name is case-sensitive", []string{"Session=abc"}, "session", nil},
		{"missing", []string{"other=1"}, "session", nil},
		{"no headers", nil, "session", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CookieValues(tt.headers, tt.cookie); !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("CookieValues(%q, %q) = %q, want %q", tt.headers, tt.cookie, got, tt.expected)
			}
		})
	}
}
