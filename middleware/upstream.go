package middleware

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

type upstreamTelemetryContextKey struct{}

type UpstreamSnapshot struct {
	ActiveRequests int64  `json:"active_requests"`
	Attempts       int    `json:"attempts"`
	WaitMS         int64  `json:"wait_ms,omitempty"`
	ConnectMS      int64  `json:"connect_ms,omitempty"`
	TLSMS          int64  `json:"tls_ms,omitempty"`
	TTFBMS         int64  `json:"ttfb_ms,omitempty"`
	BodyMS         int64  `json:"body_ms,omitempty"`
	TotalMS        int64  `json:"total_ms,omitempty"`
	Outcome        string `json:"outcome,omitempty"`
}

type upstreamTelemetry struct {
	mu             sync.Mutex
	startedAt      time.Time
	firstByteAt    time.Time
	waitStartedAt  time.Time
	connectStarted time.Time
	tlsStartedAt   time.Time
	snapshot       UpstreamSnapshot
}

func ContextWithUpstreamTelemetry(ctx context.Context) context.Context {
	return context.WithValue(ctx, upstreamTelemetryContextKey{}, &upstreamTelemetry{})
}

func BeginUpstream(r *http.Request, activeRequests int64) {
	telemetry := upstreamTelemetryForRequest(r)
	if telemetry == nil {
		return
	}

	telemetry.mu.Lock()
	telemetry.startedAt = time.Now()
	telemetry.snapshot.ActiveRequests = activeRequests
	telemetry.mu.Unlock()
}

func TraceUpstreamAttempt(r *http.Request) *http.Request {
	telemetry := upstreamTelemetryForRequest(r)
	if telemetry == nil {
		return r
	}

	telemetry.mu.Lock()
	telemetry.snapshot.Attempts++
	telemetry.mu.Unlock()

	trace := &httptrace.ClientTrace{
		GetConn: func(string) {
			telemetry.mu.Lock()
			telemetry.waitStartedAt = time.Now()
			telemetry.mu.Unlock()
		},
		GotConn: func(httptrace.GotConnInfo) {
			telemetry.mu.Lock()
			if !telemetry.waitStartedAt.IsZero() {
				telemetry.snapshot.WaitMS += time.Since(telemetry.waitStartedAt).Milliseconds()
				telemetry.waitStartedAt = time.Time{}
			}
			telemetry.mu.Unlock()
		},
		ConnectStart: func(string, string) {
			telemetry.mu.Lock()
			telemetry.connectStarted = time.Now()
			telemetry.mu.Unlock()
		},
		ConnectDone: func(string, string, error) {
			telemetry.mu.Lock()
			if !telemetry.connectStarted.IsZero() {
				telemetry.snapshot.ConnectMS += time.Since(telemetry.connectStarted).Milliseconds()
				telemetry.connectStarted = time.Time{}
			}
			telemetry.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			telemetry.mu.Lock()
			telemetry.tlsStartedAt = time.Now()
			telemetry.mu.Unlock()
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			telemetry.mu.Lock()
			if !telemetry.tlsStartedAt.IsZero() {
				telemetry.snapshot.TLSMS += time.Since(telemetry.tlsStartedAt).Milliseconds()
				telemetry.tlsStartedAt = time.Time{}
			}
			telemetry.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			telemetry.mu.Lock()
			telemetry.firstByteAt = time.Now()
			if !telemetry.startedAt.IsZero() {
				telemetry.snapshot.TTFBMS = telemetry.firstByteAt.Sub(telemetry.startedAt).Milliseconds()
			}
			telemetry.mu.Unlock()
		},
	}

	return r.WithContext(httptrace.WithClientTrace(r.Context(), trace))
}

func FinishUpstream(r *http.Request, outcome string) {
	telemetry := upstreamTelemetryForRequest(r)
	if telemetry == nil {
		return
	}

	now := time.Now()
	telemetry.mu.Lock()
	telemetry.snapshot.Outcome = outcome
	if !telemetry.startedAt.IsZero() {
		telemetry.snapshot.TotalMS = now.Sub(telemetry.startedAt).Milliseconds()
	}
	if !telemetry.firstByteAt.IsZero() {
		telemetry.snapshot.BodyMS = now.Sub(telemetry.firstByteAt).Milliseconds()
	}
	telemetry.mu.Unlock()
}

func GetUpstreamSnapshot(r *http.Request) *UpstreamSnapshot {
	telemetry := upstreamTelemetryForRequest(r)
	if telemetry == nil {
		return nil
	}

	telemetry.mu.Lock()
	defer telemetry.mu.Unlock()

	snapshot := telemetry.snapshot

	return &snapshot
}

func upstreamTelemetryForRequest(r *http.Request) *upstreamTelemetry {
	if r == nil {
		return nil
	}

	telemetry, _ := r.Context().Value(upstreamTelemetryContextKey{}).(*upstreamTelemetry)

	return telemetry
}
