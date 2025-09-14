package normalization

import (
	"testing"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Basic path normalization
		{
			name:     "simple path",
			input:    "/api/v1/users",
			expected: "/api/v1/users",
		},
		{
			name:     "path with trailing slash",
			input:    "/api/v1/users/",
			expected: "/api/v1/users/",
		},

		// Backslash conversion (Cloudflare-specific)
		{
			name:     "convert backslashes",
			input:    "\\api\\v1\\users",
			expected: "/api/v1/users",
		},
		{
			name:     "mixed slashes",
			input:    "/api\\v1/users",
			expected: "/api/v1/users",
		},

		// Successive slash merging (Cloudflare-specific)
		{
			name:     "double slashes",
			input:    "//api//v1//users",
			expected: "/api/v1/users",
		},
		{
			name:     "triple slashes",
			input:    "///api///v1///users///",
			expected: "/api/v1/users/",
		},
		{
			name:     "many consecutive slashes",
			input:    "/////api/////v1/////users",
			expected: "/api/v1/users",
		},

		// Percent decoding of unreserved characters
		{
			name:     "decode unreserved letters",
			input:    "/api%2Fv1%2Fusers",
			expected: "/api%2Fv1%2Fusers", // %2F is '/', which is reserved
		},
		{
			name:     "decode unreserved alphanumeric",
			input:    "/%61%70%69/%76%31", // 'api/v1' encoded
			expected: "/api/v1",
		},
		{
			name:     "decode unreserved special chars",
			input:    "/%2D%2E%5F%7E", // -._~ encoded
			expected: "/-._~",         // all unreserved chars decoded
		},
		{
			name:     "mixed encoded and plain",
			input:    "/api%2Fv1/%75%73%65%72%73", // 'users' encoded
			expected: "/api%2Fv1/users",
		},

		// Uppercase percent encoding
		{
			name:     "lowercase percent encoding",
			input:    "/api%2f%3a%3f",
			expected: "/api%2F%3A%3F",
		},
		{
			name:     "mixed case percent encoding",
			input:    "/api%2F%3a%3F",
			expected: "/api%2F%3A%3F",
		},

		// Dot segment removal (RFC 3986)
		{
			name:     "single dot segments",
			input:    "/api/./v1/./users",
			expected: "/api/v1/users",
		},
		{
			name:     "double dot segments",
			input:    "/api/v1/../users",
			expected: "/api/users",
		},
		{
			name:     "multiple double dot segments",
			input:    "/api/v1/../../users",
			expected: "/users",
		},
		{
			name:     "dot segments at root",
			input:    "/../api/users",
			expected: "/api/users",
		},
		{
			name:     "complex dot segments",
			input:    "/api/./v1/../v2/./users/../items",
			expected: "/api/v2/items",
		},
		{
			name:     "trailing dot segment",
			input:    "/api/v1/.",
			expected: "/api/v1", // dot segment removed, trailing slash from dot segment itself is not preserved
		},
		{
			name:     "trailing double dot",
			input:    "/api/v1/..",
			expected: "/api", // double dot removes v1, no trailing slash unless explicitly there
		},

		// Combined normalization scenarios
		{
			name:     "backslashes and double slashes",
			input:    "\\\\api\\\\v1\\\\users",
			expected: "/api/v1/users",
		},
		{
			name:     "all normalizations combined",
			input:    "\\\\api\\\\./v1//..//%76%32//users",
			expected: "/api/v2/users",
		},
		{
			name:     "percent encoded dots",
			input:    "/api/%2e%2e/v1/%2e/users",
			expected: "/v1/users",
		},

		// Edge cases
		{
			name:     "empty path",
			input:    "",
			expected: "",
		},
		{
			name:     "root only",
			input:    "/",
			expected: "/",
		},
		{
			name:     "multiple slashes only",
			input:    "///",
			expected: "/",
		},
		{
			name:     "dots only",
			input:    "/./././.",
			expected: "/",
		},
		{
			name:     "invalid percent encoding",
			input:    "/api/%ZZ/users",
			expected: "/api/%ZZ/users",
		},
		{
			name:     "incomplete percent encoding",
			input:    "/api/%2",
			expected: "/api/%2",
		},
		{
			name:     "percent at end",
			input:    "/api/users%",
			expected: "/api/users%",
		},

		// Real-world examples
		{
			name:     "wordpress admin path",
			input:    "//wp-admin//admin.php",
			expected: "/wp-admin/admin.php",
		},
		{
			name:     "path traversal attempt",
			input:    "/api/../../../etc/passwd",
			expected: "/etc/passwd",
		},
		{
			name:     "encoded path traversal",
			input:    "/api/%2e%2e/%2e%2e/etc/passwd",
			expected: "/etc/passwd",
		},
		{
			name:     "mixed encoding and traversal",
			input:    "\\api\\..\\%2e%2e\\config",
			expected: "/config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePath(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Full URL normalization
		{
			name:     "simple URL",
			input:    "http://example.com/api/v1",
			expected: "http://example.com/api/v1",
		},
		{
			name:     "URL with double slashes",
			input:    "http://example.com//api//v1",
			expected: "http://example.com/api/v1",
		},
		{
			name:     "URL with backslashes",
			input:    "http://example.com\\api\\v1",
			expected: "http://example.com/api/v1",
		},
		{
			name:     "URL with dot segments",
			input:    "http://example.com/api/../v1",
			expected: "http://example.com/v1",
		},
		{
			name:     "URL with query string",
			input:    "http://example.com//api//v1?param=value",
			expected: "http://example.com/api/v1?param=value",
		},
		{
			name:     "URL with fragment",
			input:    "http://example.com//api//v1#section",
			expected: "http://example.com/api/v1#section",
		},
		{
			name:     "URL with encoded characters",
			input:    "http://example.com/%61%70%69/v1",
			expected: "http://example.com/api/v1",
		},
		{
			name:     "HTTPS URL",
			input:    "https://example.com\\\\api\\\\v1",
			expected: "https://example.com/api/v1",
		},
		{
			name:     "URL with port",
			input:    "http://example.com:8080//api//v1",
			expected: "http://example.com:8080/api/v1",
		},
		{
			name:     "URL with authentication",
			input:    "http://user:pass@example.com//api//v1",
			expected: "http://user:pass@example.com/api/v1",
		},

		// Path-only inputs (fallback behavior)
		{
			name:     "path only with normalization",
			input:    "//api//v1/../v2",
			expected: "/api/v2",
		},
		{
			name:     "relative path",
			input:    "api//v1//../v2",
			expected: "api/v2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeURL(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestPercentDecoding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Test each unreserved character
		{
			name:     "lowercase letters",
			input:    "%61%62%63", // abc
			expected: "abc",
		},
		{
			name:     "uppercase letters",
			input:    "%41%42%43", // ABC
			expected: "ABC",
		},
		{
			name:     "digits",
			input:    "%30%31%32", // 012
			expected: "012",
		},
		{
			name:     "hyphen",
			input:    "%2D",
			expected: "-",
		},
		{
			name:     "period",
			input:    "%2E",
			expected: ".",
		},
		{
			name:     "underscore",
			input:    "%5F",
			expected: "_",
		},
		{
			name:     "tilde lowercase",
			input:    "%7e",
			expected: "%7E", // Should be uppercase
		},
		{
			name:     "tilde uppercase",
			input:    "%7E",
			expected: "%7E", // Our test expects decoded
		},

		// Reserved characters should NOT be decoded
		{
			name:     "forward slash",
			input:    "%2F",
			expected: "%2F",
		},
		{
			name:     "question mark",
			input:    "%3F",
			expected: "%3F",
		},
		{
			name:     "hash",
			input:    "%23",
			expected: "%23",
		},
		{
			name:     "colon",
			input:    "%3A",
			expected: "%3A",
		},
		{
			name:     "at sign",
			input:    "%40",
			expected: "%40",
		},
		{
			name:     "equals",
			input:    "%3D",
			expected: "%3D",
		},
		{
			name:     "ampersand",
			input:    "%26",
			expected: "%26",
		},
	}

	// Fix the tilde test expectations
	tests[6].expected = "~" // tilde should be decoded
	tests[7].expected = "~" // tilde should be decoded

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := percentDecodeUnreserved(tt.input)
			if result != tt.expected {
				t.Errorf("percentDecodeUnreserved(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDotSegmentRemoval(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// RFC 3986 examples
		{
			name:     "single dot",
			input:    "/a/./b",
			expected: "/a/b",
		},
		{
			name:     "double dot",
			input:    "/a/b/../c",
			expected: "/a/c",
		},
		{
			name:     "multiple dots",
			input:    "/a/b/c/./../../g",
			expected: "/a/g",
		},
		{
			name:     "beyond root",
			input:    "/../a",
			expected: "/a",
		},
		{
			name:     "relative with dots",
			input:    "a/./b/../c",
			expected: "a/c",
		},
		{
			name:     "relative beyond start",
			input:    "../a",
			expected: "../a",
		},
		{
			name:     "complex relative",
			input:    "a/b/../../c",
			expected: "c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeDotSegments(tt.input)
			if result != tt.expected {
				t.Errorf("removeDotSegments(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func BenchmarkNormalizePath(b *testing.B) {
	testPaths := []string{
		"/api/v1/users",
		"//api//v1//users",
		"\\api\\v1\\users",
		"/api/../v1/./users",
		"/api/%61%70%69/v1",
		"//api\\\\v1/../v2//users",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, path := range testPaths {
			_ = NormalizePath(path)
		}
	}
}
