package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.chief.tools/flowguard-proxy/config"
	"go.chief.tools/flowguard-proxy/logger"
)

func TestLoggingMiddlewareServesRequestsWhileARemovedSinkFlushes(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	defer close(release)

	lm := &LoggingMiddleware{
		loggerManager: logger.NewManager("FlowGuard/test"),
		version:       "test",
	}
	defer lm.loggerManager.Close()
	if err := lm.updateLogOutput(&config.Config{Logging: &config.LoggingConfig{
		Sinks: map[string]map[string]interface{}{"blocked": {"type": "loki", "url": backend.URL}},
	}}); err != nil {
		t.Fatalf("add sink: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	lm.Handle(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil), next)

	// Removing the sink closes it, which waits for the blocked backend.
	go func() {
		_ = lm.updateLogOutput(&config.Config{Logging: &config.LoggingConfig{}})
	}()
	time.Sleep(50 * time.Millisecond)

	served := make(chan struct{})
	go func() {
		lm.Handle(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil), next)
		close(served)
	}()

	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("request waited for the removed sink to flush")
	}
}
