package middleware

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"go.chief.tools/flowguard-proxy/config"
)

func newBodyRequest(method string, body string) *http.Request {
	req := httptest.NewRequest(method, "https://example.com/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	return req
}

func TestBodyMatcher(t *testing.T) {
	rm := &RulesMiddleware{}
	multipart := "--x\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n1\r\n--x--\r\n"

	tests := []struct {
		name     string
		body     string
		match    config.MatchCondition
		expected bool
	}{
		{
			name:     "contains",
			body:     multipart,
			match:    config.MatchCondition{Type: "body", Match: "contains", Value: "PHP_SESSION_UPLOAD_PROGRESS"},
			expected: true,
		},
		{
			name:     "contains case insensitive",
			body:     multipart,
			match:    config.MatchCondition{Type: "body", Match: "contains", Value: "php_session_upload_progress", CaseInsensitive: true},
			expected: true,
		},
		{
			name:     "not contains",
			body:     multipart,
			match:    config.MatchCondition{Type: "body", Match: "not-contains", Value: "PHP_SESSION_UPLOAD_PROGRESS"},
			expected: false,
		},
		{
			name:     "exists",
			body:     multipart,
			match:    config.MatchCondition{Type: "body", Match: "exists"},
			expected: true,
		},
		{
			name:     "missing without body",
			body:     "",
			match:    config.MatchCondition{Type: "body", Match: "missing"},
			expected: true,
		},
		{
			name:     "not truncated",
			body:     multipart,
			match:    config.MatchCondition{Type: "body-truncated", Match: "equals", Value: "false"},
			expected: true,
		},
		{
			name:     "truncated",
			body:     strings.Repeat("a", maxBodyInspectionBytes+1),
			match:    config.MatchCondition{Type: "body-truncated", Match: "equals", Value: "true"},
			expected: true,
		},
		{
			name:     "exactly the limit is not truncated",
			body:     strings.Repeat("a", maxBodyInspectionBytes),
			match:    config.MatchCondition{Type: "body-truncated", Match: "equals", Value: "false"},
			expected: true,
		},
		{
			name:     "content past the limit is not inspected",
			body:     strings.Repeat("a", maxBodyInspectionBytes) + "PHP_SESSION_UPLOAD_PROGRESS",
			match:    config.MatchCondition{Type: "body", Match: "contains", Value: "PHP_SESSION_UPLOAD_PROGRESS"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newBodyRequest(http.MethodPost, tt.body)
			if result := rm.evaluateMatch(req, &tt.match); result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestBodyMatcherRegex(t *testing.T) {
	rm := &RulesMiddleware{}
	match := config.MatchCondition{Type: "body", Match: "regex", Value: `(?s)name="php_session_upload_progress".*--x--`}
	match.SetCompiledRegexInternal(regexp.MustCompile("(?i)" + match.Value))

	req := newBodyRequest(http.MethodPost, "--x\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n1\r\n--x--\r\n")
	if !rm.evaluateMatch(req, &match) {
		t.Fatal("expected regex to match the body")
	}
}

func TestBodyIsForwardedUnchanged(t *testing.T) {
	small := "--x\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nhello\r\n--x--\r\n"
	large := strings.Repeat("0123456789", maxBodyInspectionBytes/5)

	for name, body := range map[string]string{"small": small, "truncated": large} {
		t.Run(name, func(t *testing.T) {
			rm := NewRulesMiddleware(&MockConfigProvider{
				rules: map[string]*config.Rule{
					"body": {
						ID:     "body",
						Action: "log",
						Conditions: &config.RuleConditions{
							Operator: "OR",
							Matches: []config.MatchCondition{
								{Type: "body", Match: "contains", Value: "never-present"},
								{Type: "body-truncated", Match: "equals", Value: "never"},
							},
						},
					},
				},
				actions: map[string]*config.RuleAction{"log": {Action: "log"}},
			})
			defer rm.Stop()

			for _, contentLength := range []int64{int64(len(body)), -1} {
				req := newBodyRequest(http.MethodPost, body)
				req.ContentLength = contentLength

				var forwarded string
				rm.Handle(httptest.NewRecorder(), req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					data, err := io.ReadAll(r.Body)
					if err != nil {
						t.Fatalf("read forwarded body: %v", err)
					}
					forwarded = string(data)
				}))

				if forwarded != body {
					t.Fatalf("content length %d: forwarded %d bytes, want %d unchanged", contentLength, len(forwarded), len(body))
				}
			}
		})
	}
}

func TestBodyIsOnlyReadWhenMatcherIsEvaluated(t *testing.T) {
	rm := &RulesMiddleware{}
	req := newBodyRequest(http.MethodPost, "payload")
	original := req.Body

	matches := []config.MatchCondition{
		{Type: "method", Match: "equals", Value: http.MethodPut},
		{Type: "body", Match: "contains", Value: "payload"},
	}
	if rm.evaluateMatches(req, "AND", matches) {
		t.Fatal("expected no match")
	}
	if req.Body != original {
		t.Fatal("body was read although an earlier condition failed")
	}
}

func TestBodyIsNotReadForConnect(t *testing.T) {
	rm := &RulesMiddleware{}
	req := newBodyRequest(http.MethodConnect, "tunnel")
	original := req.Body

	if rm.evaluateMatch(req, &config.MatchCondition{Type: "body", Match: "exists"}) {
		t.Fatal("expected CONNECT body to be treated as empty")
	}
	if req.Body != original {
		t.Fatal("CONNECT body was read")
	}
}

func TestBodyReadErrorIsForwarded(t *testing.T) {
	readErr := errors.New("client went away")
	req := httptest.NewRequest(http.MethodPost, "https://example.com/upload", nil)
	req.Body = io.NopCloser(io.MultiReader(strings.NewReader("partial"), errorReader{err: readErr}))
	req.ContentLength = 100

	rm := &RulesMiddleware{}
	if !rm.evaluateMatch(req, &config.MatchCondition{Type: "body", Match: "equals", Value: "partial"}) {
		t.Fatal("expected the bytes read before the error to be inspected")
	}

	data, err := io.ReadAll(req.Body)
	if string(data) != "partial" || !errors.Is(err, readErr) {
		t.Fatalf("forwarded %q, %v; want %q, %v", data, err, "partial", readErr)
	}
}

func TestReadBodyPrefixStaysWithinLimit(t *testing.T) {
	const limit = maxBodyInspectionBytes + 1
	body := strings.Repeat("a", 4*maxBodyInspectionBytes)

	for _, contentLength := range []int64{int64(len(body)), -1} {
		buf, err := readBodyPrefix(strings.NewReader(body), contentLength, limit)
		if err != nil {
			t.Fatal(err)
		}
		if len(buf) != limit || cap(buf) > limit {
			t.Fatalf("content length %d: read %d bytes into capacity %d, want %d within %d", contentLength, len(buf), cap(buf), limit, limit)
		}
	}

	buf, err := readBodyPrefix(strings.NewReader("short"), 5, limit)
	if err != nil || string(buf) != "short" || cap(buf) != 6 {
		t.Fatalf("read %q with capacity %d, %v; want %q with capacity 6", buf, cap(buf), err, "short")
	}
}
