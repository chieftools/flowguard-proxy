package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type middlewareFunc func(w http.ResponseWriter, r *http.Request, next http.Handler)

func (f middlewareFunc) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	f(w, r, next)
}

func (f middlewareFunc) Stop() {}

func TestTimingMiddlewareRecordsWhenTheMiddlewareFinished(t *testing.T) {
	var start, end, lastMiddlewareDone, finalStarted time.Time

	chain := NewChain()
	chain.Add(NewTimingMiddleware())
	// Like the logging middleware, read the timing after the request, from
	// the request as this middleware received it.
	chain.Add(middlewareFunc(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		next.ServeHTTP(w, r)
		start, end = GetStartTime(r), GetMiddlewareEndTime(r)
	}))
	chain.Add(middlewareFunc(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		time.Sleep(time.Millisecond)
		lastMiddlewareDone = time.Now()
		next.ServeHTTP(w, r)
	}))

	chain.ServeHTTPWithHandler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		finalStarted = time.Now()
	}))

	if start.IsZero() || end.IsZero() {
		t.Fatalf("start %v, end %v; want both recorded", start, end)
	}
	if end.Before(lastMiddlewareDone) || end.After(finalStarted) {
		t.Fatalf("middleware end %v, want between the last middleware finishing (%v) and the final handler starting (%v)", end, lastMiddlewareDone, finalStarted)
	}
}
