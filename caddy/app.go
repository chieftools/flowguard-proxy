// Package flowguardcaddy runs FlowGuard inside Caddy. Caddy listens,
// terminates TLS and proxies; FlowGuard evaluates rules, logs requests and
// stays connected to the control panel.
//
// It provides three modules: the "flowguard" app, which runs the engine, the
// "flowguard" HTTP handler, which filters requests in a site's routes, and the
// "flowguard" listener wrapper, which adds JA4 fingerprints.
package flowguardcaddy

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"

	"go.chief.tools/flowguard-proxy/api"
	"go.chief.tools/flowguard-proxy/config"
	"go.chief.tools/flowguard-proxy/engine"
)

const (
	// DefaultConfigPath is where `flowguard setup` stores the configuration.
	DefaultConfigPath = "/etc/flowguard/config.json"

	// HeartbeatCapability tells the control panel the host runs FlowGuard in
	// Caddy, so it has no FlowGuard listeners, certificates or firewall.
	HeartbeatCapability = "caddy"

	// FirewallStatusUnmanaged is the firewall status Caddy hosts report:
	// FlowGuard does not redirect traffic, Caddy receives it directly.
	FirewallStatusUnmanaged = "unmanaged"
)

func init() {
	caddy.RegisterModule(App{})
}

// engines shares one engine per configuration file across Caddy config
// reloads. Caddy provisions the new configuration before cleaning up the old
// one, so the reference count never reaches zero during a reload, and rate
// limits, log buffers, IP lists and the panel connection carry over.
var engines = caddy.NewUsagePool()

// App runs the FlowGuard engine. Without a `flowguard` global option, it
// reads the configuration that `flowguard setup` wrote to DefaultConfigPath.
type App struct {
	// Config is the path of the FlowGuard configuration file. With Key, the
	// configuration is fetched into this file. It defaults to
	// DefaultConfigPath, or with Key to flowguard/config.json in Caddy's data
	// directory.
	Config string `json:"config,omitempty"`

	// Key is the host key from the FlowGuard control panel (fgsvr_...). When
	// set, FlowGuard fetches the configuration itself unless Config already
	// holds the configuration for this key, so `flowguard setup` is not needed.
	Key string `json:"key,omitempty"`

	// CacheDir stores downloaded IP lists and the IP database. It defaults to
	// flowguard/cache in Caddy's data directory.
	CacheDir string `json:"cache_dir,omitempty"`

	// Verbose enables FlowGuard's verbose logging. Like the other options, a
	// change applies when Caddy restarts, not on a config reload.
	Verbose bool `json:"verbose,omitempty"`

	pooled *pooledEngine
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "flowguard",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision loads the configuration, fetching it first when a key is set, and
// takes a reference on the engine for it.
func (a *App) Provision(_ caddy.Context) error {
	configPath := a.configPath()
	cacheDir := a.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(caddy.AppDataDir(), "flowguard", "cache")
	}

	if a.Key != "" {
		if err := config.Bootstrap(configPath, a.Key, userAgent()); err != nil {
			return fmt.Errorf("fetching FlowGuard configuration into %s: %w", configPath, err)
		}
	}

	value, _, err := engines.LoadOrNew(configPath, func() (caddy.Destructor, error) {
		configMgr, err := config.NewManager(configPath, userAgent(), version(), cacheDir, a.Verbose)
		if err != nil {
			// Caddy usually runs as its own user, which cannot read the
			// configuration `flowguard setup` wrote, nor save updates to it.
			if a.Key == "" && errors.Is(err, fs.ErrPermission) {
				return nil, fmt.Errorf("loading FlowGuard configuration from %s: %w; or set key in the flowguard global option to keep the configuration in Caddy's data directory", configPath, err)
			}
			return nil, fmt.Errorf("loading FlowGuard configuration from %s: %w", configPath, err)
		}
		if err := configMgr.RefreshFromAPI(false); err != nil {
			log.Printf("[config] Warning: Failed to refresh configuration from API: %v", err)
		}

		return &pooledEngine{
			engine: engine.New(configMgr, engine.Options{
				Verbose:   a.Verbose,
				Version:   version(),
				Heartbeat: heartbeatDetails,
			}),
		}, nil
	})
	if err != nil {
		return err
	}

	a.pooled = value.(*pooledEngine)
	return nil
}

// Start starts the engine the first time any configuration that uses it starts.
func (a *App) Start() error {
	a.pooled.start()
	return nil
}

// Stop leaves the engine running: it stops when its last configuration is
// cleaned up, after Caddy has drained that configuration's requests.
func (a *App) Stop() error {
	return nil
}

// Cleanup releases this configuration's reference on the engine.
func (a *App) Cleanup() error {
	if a.pooled == nil {
		return nil
	}

	_, err := engines.Delete(a.configPath())
	return err
}

// Engine returns the engine that filters requests for this configuration.
func (a *App) Engine() *engine.Engine {
	return a.pooled.engine
}

func (a *App) configPath() string {
	if a.Config != "" {
		return a.Config
	}
	if a.Key != "" {
		return filepath.Join(caddy.AppDataDir(), "flowguard", "config.json")
	}

	return DefaultConfigPath
}

type pooledEngine struct {
	engine    *engine.Engine
	startOnce sync.Once
}

func (p *pooledEngine) start() {
	p.startOnce.Do(func() {
		p.engine.Start()
		p.engine.StartPanel()
	})
}

// Destruct stops the engine once no configuration uses it.
func (p *pooledEngine) Destruct() error {
	p.engine.Stop()
	return nil
}

func heartbeatDetails() engine.HeartbeatDetails {
	return engine.HeartbeatDetails{
		Capabilities: []string{HeartbeatCapability},
		Firewall:     api.FirewallHeartbeat{Status: FirewallStatusUnmanaged},
	}
}

// version returns the plugin's module version, as xcaddy built it.
func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}

	for _, dep := range info.Deps {
		if dep.Path == "go.chief.tools/flowguard-proxy/caddy" {
			if dep.Replace != nil || dep.Version == "" || dep.Version == "(devel)" {
				return "dev"
			}
			return strings.TrimPrefix(dep.Version, "v")
		}
	}

	return "dev"
}

func userAgent() string {
	return fmt.Sprintf("FlowGuard/%s", version())
}

// Interface guards
var (
	_ caddy.App          = (*App)(nil)
	_ caddy.Provisioner  = (*App)(nil)
	_ caddy.CleanerUpper = (*App)(nil)
)
