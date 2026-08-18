package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"flowguard/certmanager"
	"flowguard/config"
	"flowguard/fail2ban"
	"flowguard/middleware"
	"flowguard/updater"
)

func boolPtr(v bool) *bool {
	return &v
}

func writeProxyTestConfig(t *testing.T, cfg config.Config) string {
	t.Helper()

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return configPath
}

func newProxyTestConfigManager(t *testing.T, cfg config.Config) *config.Manager {
	t.Helper()

	configMgr, err := config.NewManager(writeProxyTestConfig(t, cfg), "FlowGuard/test", "test", "", false)
	if err != nil {
		t.Fatalf("new config manager: %v", err)
	}

	return configMgr
}

func newProxyTestConfig() *Config {
	return &Config{
		HTTPPort:   "0",
		HTTPSPort:  "0",
		BindAddrs:  []string{"127.0.0.1"},
		NoRedirect: true,
	}
}

func TestNewManagerAllowsReadableNginxConfigWithoutCertificates(t *testing.T) {
	nginxConfigPath := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(nginxConfigPath, []byte("events {}\nhttp {}\n"), 0o644); err != nil {
		t.Fatalf("write nginx config: %v", err)
	}

	configMgr := newProxyTestConfigManager(t, config.Config{
		Host: &config.HostConfig{
			NginxConfigPath: nginxConfigPath,
		},
	})

	injectedUpdater := &updater.Updater{}
	proxyConfig := newProxyTestConfig()
	proxyConfig.Updater = injectedUpdater
	manager, err := NewManager(configMgr, proxyConfig)
	if err != nil {
		configMgr.Stop()
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(func() {
		if err := manager.Shutdown(); err != nil {
			t.Fatalf("shutdown manager: %v", err)
		}
	})

	if got := manager.certManager.HostnameCount(); got != 0 {
		t.Fatalf("expected no certificates to be loaded, got %d hostnames", got)
	}
	if manager.updater != injectedUpdater {
		t.Fatal("expected manager to reuse the configured updater")
	}
}

type blockingInitialFail2BanRunner struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockingInitialFail2BanRunner) CombinedOutput(ctx context.Context, _ string, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	switch joined {
	case "status":
		r.once.Do(func() { close(r.started) })
		select {
		case <-r.release:
			return []byte("Status\n`- Jail list: request-limit"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	case "get request-limit banip":
		return []byte("198.51.100.157"), nil
	default:
		return nil, errors.New("unexpected command: " + joined)
	}
}

func TestStartWaitsForInitialFail2BanSnapshotBeforeOpeningListeners(t *testing.T) {
	nginxConfigPath := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(nginxConfigPath, []byte("events {}\nhttp {}\n"), 0o644); err != nil {
		t.Fatalf("write nginx config: %v", err)
	}
	configMgr := newProxyTestConfigManager(t, config.Config{
		Host:     &config.HostConfig{NginxConfigPath: nginxConfigPath},
		Fail2Ban: &config.Fail2BanConfig{Enabled: true},
		Server: &config.ServerConfig{Protocols: &config.ProtocolsConfig{
			HTTP1: boolPtr(true),
			HTTP2: boolPtr(false),
			HTTP3: boolPtr(false),
		}},
	})
	proxyConfig := newProxyTestConfig()
	proxyConfig.Updater = &updater.Updater{}
	manager, err := NewManager(configMgr, proxyConfig)
	if err != nil {
		configMgr.Stop()
		t.Fatalf("new manager: %v", err)
	}

	eventPath := filepath.Join(t.TempDir(), "occupied-event-path")
	if err := os.WriteFile(eventPath, []byte("reserved"), 0o600); err != nil {
		t.Fatalf("create occupied event path: %v", err)
	}
	runner := &blockingInitialFail2BanRunner{started: make(chan struct{}), release: make(chan struct{})}
	manager.fail2banManager = fail2ban.NewManager(fail2ban.Options{
		ClientPath:      "fail2ban-client",
		FlowGuardPath:   "/usr/bin/flowguard",
		EventSocketPath: eventPath,
		GOOS:            "linux",
		CommandTimeout:  time.Second,
		Runner:          runner,
	})

	startResult := make(chan error, 1)
	startResultConsumed := false
	var releaseOnce sync.Once
	releaseInitialQuery := func() { releaseOnce.Do(func() { close(runner.release) }) }
	t.Cleanup(func() {
		releaseInitialQuery()
		if !startResultConsumed {
			select {
			case <-startResult:
			case <-time.After(3 * time.Second):
				t.Errorf("proxy startup did not finish during cleanup")
			}
		}
		if shutdownErr := manager.Shutdown(); shutdownErr != nil {
			t.Errorf("shutdown manager: %v", shutdownErr)
		}
	})
	go func() { startResult <- manager.Start() }()

	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("initial Fail2Ban query did not start")
	}
	select {
	case startErr := <-startResult:
		startResultConsumed = true
		t.Fatalf("proxy startup returned before the initial snapshot: %v", startErr)
	default:
	}
	manager.serverMu.Lock()
	listenerCount := len(manager.servers)
	manager.serverMu.Unlock()
	if listenerCount != 0 {
		t.Fatalf("opened %d proxy listeners before the initial snapshot", listenerCount)
	}

	releaseInitialQuery()
	select {
	case startErr := <-startResult:
		startResultConsumed = true
		if startErr != nil {
			t.Fatalf("start manager: %v", startErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy startup did not finish after the initial snapshot")
	}
	if got := manager.fail2banManager.MatchingJails("198.51.100.157"); len(got) != 1 || got[0] != "request-limit" {
		t.Fatalf("initial Fail2Ban snapshot was not active at startup: %#v", got)
	}
}

func TestNewManagerRejectsEmptyCertificateDirectory(t *testing.T) {
	configMgr := newProxyTestConfigManager(t, config.Config{
		Host: &config.HostConfig{
			CertPath: t.TempDir(),
		},
	})

	manager, err := NewManager(configMgr, newProxyTestConfig())
	if err == nil {
		t.Cleanup(func() {
			if shutdownErr := manager.Shutdown(); shutdownErr != nil {
				t.Fatalf("shutdown manager: %v", shutdownErr)
			}
		})
		t.Fatal("expected empty certificate directory to be rejected")
	}
	configMgr.Stop()
	if !strings.Contains(err.Error(), "no valid certificates found in cert_path=") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewManagerRejectsUnreadableTraefikACMEStorage(t *testing.T) {
	acmePath := filepath.Join(t.TempDir(), "missing-acme.json")
	configMgr := newProxyTestConfigManager(t, config.Config{
		Host: &config.HostConfig{
			ACMEPath: acmePath,
		},
	})

	manager, err := NewManager(configMgr, newProxyTestConfig())
	if err == nil {
		t.Cleanup(func() {
			if shutdownErr := manager.Shutdown(); shutdownErr != nil {
				t.Fatalf("shutdown manager: %v", shutdownErr)
			}
		})
		t.Fatal("expected unreadable ACME storage to be rejected")
	}
	configMgr.Stop()
	if !strings.Contains(err.Error(), "acme_path=") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewManagerRejectsUnreadableNginxConfigWithoutCertificates(t *testing.T) {
	configMgr := newProxyTestConfigManager(t, config.Config{
		Host: &config.HostConfig{
			NginxConfigPath: filepath.Join(t.TempDir(), "missing.conf"),
		},
	})

	manager, err := NewManager(configMgr, newProxyTestConfig())
	if err == nil {
		t.Cleanup(func() {
			if shutdownErr := manager.Shutdown(); shutdownErr != nil {
				t.Fatalf("shutdown manager: %v", shutdownErr)
			}
		})
		t.Fatal("expected unreadable nginx config to be rejected")
	}
	configMgr.Stop()
	if !strings.Contains(err.Error(), "nginx_config_path=") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProtocolConfigChangeRestartsListeners(t *testing.T) {
	initialProtocols := config.ProtocolSettings{HTTP1: true, HTTP2: true, HTTP3: false}
	manager := &Manager{
		config: &Config{
			HTTPPort:   "0",
			HTTPSPort:  "0",
			BindAddrs:  []string{"127.0.0.1"},
			NoRedirect: true,
			Protocols:  initialProtocols,
		},
		certManager:     certmanager.New(certmanager.Config{}),
		middlewareChain: middleware.NewChain(),
		serveErrChan:    make(chan error, 4),
	}
	t.Cleanup(func() {
		manager.serverMu.Lock()
		servers := manager.servers
		manager.servers = nil
		manager.serverMu.Unlock()
		manager.stopServers(servers)
		manager.certManager.Stop()
		manager.middlewareChain.Stop()
	})

	servers, err := manager.startServers(initialProtocols, false)
	if err != nil {
		t.Fatalf("start initial servers: %v", err)
	}
	manager.servers = servers
	if len(manager.servers) != 2 {
		t.Fatalf("expected initial HTTP and HTTPS servers, got %d", len(manager.servers))
	}

	manager.handleServerConfigChange(&config.Config{
		Server: &config.ServerConfig{
			Protocols: &config.ProtocolsConfig{
				HTTP1: boolPtr(false),
				HTTP2: boolPtr(true),
				HTTP3: boolPtr(false),
			},
		},
	})

	if manager.config.Protocols.HTTP1 || !manager.config.Protocols.HTTP2 || manager.config.Protocols.HTTP3 {
		t.Fatalf("unexpected protocol state after reload: %+v", manager.config.Protocols)
	}
	if len(manager.servers) != 1 {
		t.Fatalf("expected only HTTPS server after disabling HTTP/1, got %d", len(manager.servers))
	}
	if manager.servers[0].config.scheme != "https" {
		t.Fatalf("expected remaining server to be HTTPS, got %s", manager.servers[0].config.scheme)
	}
}

func TestFormatProxyStartupSummary(t *testing.T) {
	tests := []struct {
		name             string
		servers          []*Server
		bindAddressCount int
		want             string
	}{
		{
			name: "dual stack HTTP and HTTPS",
			servers: []*Server{
				{config: &ServerConfig{scheme: "http"}},
				{config: &ServerConfig{scheme: "https"}},
				{config: &ServerConfig{scheme: "http"}},
				{config: &ServerConfig{scheme: "https"}},
			},
			bindAddressCount: 2,
			want:             "Started 4 proxy endpoints across 2 bind addresses (2 HTTP, 2 HTTPS)",
		},
		{
			name:             "single HTTPS endpoint",
			servers:          []*Server{{config: &ServerConfig{scheme: "https"}}},
			bindAddressCount: 1,
			want:             "Started 1 proxy endpoint across 1 bind address (1 HTTPS)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatProxyStartupSummary(tt.servers, tt.bindAddressCount); got != tt.want {
				t.Fatalf("formatProxyStartupSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatBindAddresses(t *testing.T) {
	tests := []struct {
		name         string
		addresses    []string
		autoDetected bool
		want         string
	}{
		{
			name:         "auto-detected dual stack",
			addresses:    []string{"185.208.210.215", "2a0b:3c40:15:0:185:208:210:215"},
			autoDetected: true,
			want:         "Bind addresses (2, auto-detected): 185.208.210.215, 2a0b:3c40:15:0:185:208:210:215",
		},
		{
			name:      "configured single address",
			addresses: []string{"192.0.2.10"},
			want:      "Bind addresses (1, configured): 192.0.2.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatBindAddresses(tt.addresses, tt.autoDetected); got != tt.want {
				t.Fatalf("formatBindAddresses() = %q, want %q", got, tt.want)
			}
		})
	}
}
