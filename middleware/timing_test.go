package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.chief.tools/flowguard-proxy/config"
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

func TestRuleDecisionsAreSharedByEveryCopyOfTheRequest(t *testing.T) {
	rule := &config.Rule{ID: "rule-1"}
	action := &config.RuleAction{ID: "action-1", Action: "log"}
	var observed *http.Request

	chain := NewChain()
	chain.Add(NewTimingMiddleware())
	chain.Add(middlewareFunc(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		observed = r
		next.ServeHTTP(w, r)
	}))
	chain.Add(middlewareFunc(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		// A later middleware works on its own copy of the request.
		copied := r.WithContext(context.WithValue(r.Context(), contextKey("copy"), true))
		SetRuleMatch(copied, rule, action, "log")
		SetRateLimitApplied(copied)
		next.ServeHTTP(w, copied)
	}))
	chain.ServeHTTPWithHandler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	if GetRuleMatched(observed) != rule || GetActionMatched(observed) != action || GetRuleResult(observed) != "log" || !GetRateLimitApplied(observed) {
		t.Fatal("expected decisions recorded on a later copy of the request to be visible from an earlier one")
	}

	bare := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	SetChallengeMatched(bare)
	if !GetChallengeMatched(bare) || GetRuleResult(bare) != "proxy" {
		t.Fatal("expected decisions on a request without timing middleware to be recorded")
	}
}
