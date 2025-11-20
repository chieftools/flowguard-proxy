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
	r = r.WithContext(ctx)

	// Wrap the next handler to capture end time right before proxy executes
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture end time just before the proxy handler begins
		endTime := time.Now()
		ctx := context.WithValue(r.Context(), ContextKeyMiddlewareEndTime, endTime)
		r = r.WithContext(ctx)

		// Call the final handler (proxy)
		next.ServeHTTP(w, r)
	})

	// Execute all middleware in the chain
	wrappedHandler.ServeHTTP(w, r)
}

func (tm *TimingMiddleware) Stop() {
	// No cleanup needed
}
