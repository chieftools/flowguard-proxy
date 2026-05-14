package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"flowguard/certmanager"
	"flowguard/config"
	"flowguard/middleware"
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

	manager, err := NewManager(configMgr, newProxyTestConfig())
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
