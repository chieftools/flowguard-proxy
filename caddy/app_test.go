package flowguardcaddy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

func TestCaddyfileAdaptsAllModules(t *testing.T) {
	input := `{
	flowguard {
		config /etc/flowguard/config.json
		key fgsvr_test
		cache_dir /var/cache/flowguard
		verbose
	}
	servers {
		listener_wrappers {
			flowguard
			tls
		}
	}
}

example.test {
	flowguard
	respond "ok"
}
`
	adapted, warnings, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("adapt Caddyfile: %v", err)
	}
	if len(warnings) > 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	var cfg struct {
		Apps struct {
			FlowGuard App `json:"flowguard"`
			HTTP      struct {
				Servers map[string]struct {
					ListenerWrappers []map[string]any `json:"listener_wrappers"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(adapted, &cfg); err != nil {
		t.Fatalf("decode adapted config: %v", err)
	}

	app := cfg.Apps.FlowGuard
	if app.Config != "/etc/flowguard/config.json" || app.Key != "fgsvr_test" || app.CacheDir != "/var/cache/flowguard" || !app.Verbose {
		t.Fatalf("unexpected flowguard app config: %+v", app)
	}
	for name, server := range cfg.Apps.HTTP.Servers {
		if len(server.ListenerWrappers) != 2 || server.ListenerWrappers[0]["wrapper"] != "flowguard" || server.ListenerWrappers[1]["wrapper"] != "tls" {
			t.Fatalf("server %s listener wrappers = %v", name, server.ListenerWrappers)
		}
	}

	// The site's route must run the handler before the response.
	routes := string(adapted)
	handlerAt := strings.Index(routes, `"handler":"flowguard"`)
	respondAt := strings.Index(routes, `"handler":"static_response"`)
	if handlerAt < 0 || respondAt < 0 || handlerAt > respondAt {
		t.Fatalf("expected the flowguard handler before respond in %s", adapted)
	}
}

func TestCaddyfileRejectsUnknownOptions(t *testing.T) {
	for _, input := range []string{
		"{\n\tflowguard {\n\t\tunknown\n\t}\n}\n",
		"example.test {\n\tflowguard extra\n}\n",
	} {
		if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil); err == nil {
			t.Errorf("expected an error for %q", input)
		}
	}
}

func TestAppSharesEngineAcrossReloads(t *testing.T) {
	configPath, _ := writeTestConfig(t)

	provision := func() *App {
		t.Helper()
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		t.Cleanup(cancel)
		app := &App{Config: configPath, CacheDir: t.TempDir()}
		if err := app.Provision(ctx); err != nil {
			t.Fatalf("provision: %v", err)
		}
		return app
	}

	// Caddy provisions and starts the new configuration before it stops and
	// cleans up the old one.
	first := provision()
	if err := first.Start(); err != nil {
		t.Fatalf("start first: %v", err)
	}
	second := provision()
	if err := second.Start(); err != nil {
		t.Fatalf("start second: %v", err)
	}
	if first.Engine() != second.Engine() {
		t.Fatal("expected the reloaded configuration to reuse the running engine")
	}

	if err := first.Stop(); err != nil {
		t.Fatalf("stop first: %v", err)
	}
	if err := first.Cleanup(); err != nil {
		t.Fatalf("cleanup first: %v", err)
	}
	if refs, ok := engines.References(configPath); !ok || refs != 1 {
		t.Fatalf("references after reload = %d (exists %v), want 1", refs, ok)
	}

	if err := second.Stop(); err != nil {
		t.Fatalf("stop second: %v", err)
	}
	if err := second.Cleanup(); err != nil {
		t.Fatalf("cleanup second: %v", err)
	}
	if _, ok := engines.References(configPath); ok {
		t.Fatal("expected the engine to be released after its last configuration")
	}
}

func TestAppConfigPathDefaults(t *testing.T) {
	if got := (&App{}).configPath(); got != DefaultConfigPath {
		t.Fatalf("config path without key = %q, want %q", got, DefaultConfigPath)
	}
	if got := (&App{Key: "fgsvr_test"}).configPath(); !strings.HasPrefix(got, caddy.AppDataDir()) {
		t.Fatalf("config path with key = %q, want it under %q", got, caddy.AppDataDir())
	}
	if got := (&App{Key: "fgsvr_test", Config: "/srv/flowguard.json"}).configPath(); got != "/srv/flowguard.json" {
		t.Fatalf("config path with key and config = %q", got)
	}
}
