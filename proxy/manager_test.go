package proxy

import (
	"testing"

	"flowguard/certmanager"
	"flowguard/config"
	"flowguard/middleware"
)

func boolPtr(v bool) *bool {
	return &v
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
