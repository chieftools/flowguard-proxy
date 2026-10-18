package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTraceUpstreamAttemptsCountsRoundTrips(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	r := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	r = r.WithContext(ContextWithUpstreamTelemetry(r.Context()))
	BeginUpstream(r, 1)
	traced := TraceUpstreamAttempts(r)

	for range 2 {
		outbound, err := http.NewRequestWithContext(traced.Context(), http.MethodGet, upstream.URL, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := upstream.Client().Do(outbound)
		if err != nil {
			t.Fatalf("upstream request: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	FinishUpstream(r, "success")

	snapshot := GetUpstreamSnapshot(r)
	if snapshot.Attempts != 2 || snapshot.Outcome != "success" || snapshot.ActiveRequests != 1 {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
}

func TestTraceUpstreamAttemptsWithoutRoundTrip(t *testing.T) {
	ctx := ContextWithUpstreamTelemetry(context.Background())
	r := httptest.NewRequest(http.MethodGet, "https://example.test/", nil).WithContext(ctx)
	TraceUpstreamAttempts(r)

	if snapshot := GetUpstreamSnapshot(r); snapshot.Attempts != 0 {
		t.Fatalf("expected no attempts without a round trip, got %#v", snapshot)
	}
}
