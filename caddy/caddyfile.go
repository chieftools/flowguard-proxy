package flowguardcaddy

import (
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("flowguard", parseGlobalOption)
	httpcaddyfile.RegisterHandlerDirective("flowguard", parseHandlerDirective)
	// Run early so rules see the request before Caddy rewrites it, after the
	// directives that only set variables or log options.
	httpcaddyfile.RegisterDirectiveOrder("flowguard", httpcaddyfile.Before, "header")
}

// parseGlobalOption parses the flowguard global option:
//
//	flowguard {
//		config    <path>
//		key       <host key>
//		cache_dir <path>
//		verbose
//	}
func parseGlobalOption(d *caddyfile.Dispenser, _ any) (any, error) {
	app := new(App)
	if err := app.UnmarshalCaddyfile(d); err != nil {
		return nil, err
	}

	return httpcaddyfile.App{
		Name:  "flowguard",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

// UnmarshalCaddyfile sets up the app from Caddyfile tokens.
func (a *App) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume option name
	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "config":
			if !d.AllArgs(&a.Config) {
				return d.ArgErr()
			}
		case "key":
			if !d.AllArgs(&a.Key) {
				return d.ArgErr()
			}
		case "cache_dir":
			if !d.AllArgs(&a.CacheDir) {
				return d.ArgErr()
			}
		case "verbose":
			if d.NextArg() {
				return d.ArgErr()
			}
			a.Verbose = true
		default:
			return d.Errf("unrecognized flowguard option '%s'", d.Val())
		}
	}

	return nil
}

// parseHandlerDirective parses the flowguard directive, which takes no
// arguments:
//
//	flowguard
func parseHandlerDirective(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	handler := new(Handler)
	if err := handler.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}

	return handler, nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	if d.NextArg() || d.NextBlock(0) {
		return d.Err("flowguard takes no arguments; configure it with the flowguard global option")
	}

	return nil
}

// UnmarshalCaddyfile sets up the listener wrapper from Caddyfile tokens. It
// takes no arguments.
func (lw *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name
	if d.NextArg() || d.NextBlock(0) {
		return d.Err("the flowguard listener wrapper takes no arguments")
	}

	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*App)(nil)
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)
