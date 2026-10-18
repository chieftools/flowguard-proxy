package middleware

import (
	"testing"

	"go.chief.tools/flowguard-proxy/config"
	"go.chief.tools/flowguard-proxy/instance"
	"go.chief.tools/flowguard-proxy/logger"
)

func TestLoggingMiddlewareLogsTheInstanceOfAManagedServer(t *testing.T) {
	lm := &LoggingMiddleware{
		loggerManager: logger.NewManager("FlowGuard/test"),
		version:       "test",
	}

	if err := lm.updateLogOutput(&config.Config{
		Host:    &config.HostConfig{ID: "server_synthetic-a", Name: "Synthetic edge", Team: "synthetic"},
		Logging: &config.LoggingConfig{},
	}); err != nil {
		t.Fatalf("update log output: %v", err)
	}

	if lm.hostInfo == nil || lm.hostInfo.ID != "server_synthetic-a" || lm.hostInfo.Instance != instance.ID() {
		t.Fatalf("host info = %+v, want server_synthetic-a on instance %s", lm.hostInfo, instance.ID())
	}
}
