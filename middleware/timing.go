package middleware

import (
	"context"
	"net/http"
	"time"
)

// TimingMiddleware captures precise timing for the entire middleware stack
// This middleware should be added FIRST to the chain so it measures all middleware processing
type TimingMiddleware struct{}

func NewTimingMiddleware() *TimingMiddleware {
	return &TimingMiddleware{}
}

func (tm *TimingMiddleware) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	// Capture start time when entering the first middleware
	startTime := time.Now()
	ctx := context.WithValue(r.Context(), ContextKeyStartTime, startTime)
	ctx = context.WithValue(ctx, ContextKeyStreamID, generateStreamID())
	ctx = context.WithValue(ctx, ContextKeyMiddlewareEndTime, &middlewareTiming{})
	ctx = contextWithRequestLogState(ctx)

	// Run the rest of the chain; it records the end time right before the
	// final handler (the proxy) starts
	next.ServeHTTP(w, r.WithContext(ctx))
}

// middlewareTiming holds when the middleware chain handed the request to its
// final handler. It is a pointer in the context so middleware that log after
// the request, holding the request as they received it, can read it.
type middlewareTiming struct {
	end time.Time
}

// markMiddlewareEnd records that the middleware chain finished with r.
func markMiddlewareEnd(r *http.Request) {
	if timing, ok := r.Context().Value(ContextKeyMiddlewareEndTime).(*middlewareTiming); ok && timing.end.IsZero() {
		timing.end = time.Now()
	}
}

// GetMiddlewareEndTime returns when the middleware chain handed r to its final
// handler, or the zero time when it did not, such as for a blocked request.
func GetMiddlewareEndTime(r *http.Request) time.Time {
	if timing, ok := r.Context().Value(ContextKeyMiddlewareEndTime).(*middlewareTiming); ok {
		return timing.end
	}
	return time.Time{}
}

func (tm *TimingMiddleware) Stop() {
	// No cleanup needed
}
