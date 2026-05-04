package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"flowguard/config"
)

func TestRequestInfoIncludesJA4Fingerprint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req = WithJA4Fingerprint(req, "t13d0101h2_hash_hash")

	info := getRequestInfo(req, nil)
	if info.Fingerprint == nil {
		t.Fatal("expected fingerprint info")
	}
	if info.Fingerprint.JA4 != "t13d0101h2_hash_hash" {
		t.Fatalf("unexpected JA4 fingerprint: %q", info.Fingerprint.JA4)
	}
}

func TestRequestInfoOmitsEmptyFingerprint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)

	info := getRequestInfo(req, nil)
	if info.Fingerprint != nil {
		t.Fatalf("expected no fingerprint info, got %#v", info.Fingerprint)
	}
}

func TestFingerprintJA4RuleMatching(t *testing.T) {
	rm := &RulesMiddleware{}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req = req.WithContext(ContextWithJA4Fingerprint(context.Background(), "t13d1516h2_8daaf6152771_02713d6af862"))

	tests := []struct {
		name  string
		match config.MatchCondition
		want  bool
	}{
		{
			name: "equals",
			match: config.MatchCondition{
				Type:  "fingerprint-ja4",
				Match: "equals",
				Value: "t13d1516h2_8daaf6152771_02713d6af862",
			},
			want: true,
		},
		{
			name: "starts with",
			match: config.MatchCondition{
				Type:  "fingerprint-ja4",
				Match: "starts-with",
				Value: "t13d1516h2_",
			},
			want: true,
		},
		{
			name: "ends with",
			match: config.MatchCondition{
				Type:  "fingerprint-ja4",
				Match: "ends-with",
				Value: "_02713d6af862",
			},
			want: true,
		},
		{
			name: "does not match",
			match: config.MatchCondition{
				Type:  "fingerprint-ja4",
				Match: "equals",
				Value: "other",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rm.evaluateMatch(req, &tt.match); got != tt.want {
				t.Fatalf("unexpected match result: got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFingerprintJA4RateLimitKeyUsesFingerprint(t *testing.T) {
	kg := NewRateLimitKeyGenerator()
	rule := &config.Rule{
		ID: "rate-by-ja4",
		Conditions: &config.RuleConditions{
			Matches: []config.MatchCondition{
				{Type: "fingerprint-ja4", Match: "equals", Value: "ignored"},
			},
		},
	}

	req1 := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req1 = WithJA4Fingerprint(req1, "ja4-one")
	req2 := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req2 = WithJA4Fingerprint(req2, "ja4-two")

	if kg.GenerateKey(rule.ID, rule, req1) == kg.GenerateKey(rule.ID, rule, req2) {
		t.Fatal("expected different rate limit keys for different JA4 fingerprints")
	}
}
