package flowguardcaddy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"go.chief.tools/flowguard-proxy/engine"
	"go.chief.tools/flowguard-proxy/middleware"
)

func init() {
	caddy.RegisterModule(Handler{})
}

type connContextKey struct{}

// Handler filters requests through FlowGuard: it evaluates the rules, logs
// the request and response, and passes allowed requests to the next handler.
type Handler struct {
	engine         *engine.Engine
	activeUpstream *atomic.Int64
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.flowguard",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision gets the engine from the flowguard app, which Caddy starts with
// its defaults when no flowguard global option is configured, and tracks the
// server's connections for connection info and JA4.
func (h *Handler) Provision(ctx caddy.Context) error {
	appValue, err := ctx.App("flowguard")
	if err != nil {
		return fmt.Errorf("loading flowguard app: %w", err)
	}
	h.engine = appValue.(*App).Engine()
	h.activeUpstream = new(atomic.Int64)

	if server, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server); ok && server != nil {
		server.RegisterConnContext(connContext)
	}

	return nil
}

// connContext attaches the connection's info once per connection, even when
// several flowguard handlers on the same server registered it.
func connContext(ctx context.Context, conn net.Conn) context.Context {
	if _, ok := ctx.Value(connContextKey{}).(bool); ok {
		return ctx
	}

	ctx = context.WithValue(ctx, connContextKey{}, true)
	ctx = middleware.ContextWithConnectionInfo(ctx)
	if fc := fingerprintConnFrom(conn); fc != nil {
		ctx = context.WithValue(ctx, fingerprintConnContextKey{}, fc)
	}

	return ctx
}

type fingerprintConnContextKey struct{}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if fc, ok := r.Context().Value(fingerprintConnContextKey{}).(*fingerprintConn); ok {
		if ja4 := fc.JA4(); ja4 != "" {
			r = middleware.WithJA4Fingerprint(r, ja4)
		}
	}

	finishConnectionRequest := middleware.BeginConnectionRequest(r)
	defer finishConnectionRequest()

	r = r.WithContext(middleware.ContextWithUpstreamTelemetry(r.Context()))

	var nextErr error
	h.engine.Chain().ServeHTTPWithHandler(w, r, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextErr = h.serveNext(w, r, next)
	}))

	return nextErr
}

// serveNext runs the rest of Caddy's route for a request the rules allowed.
func (h *Handler) serveNext(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	streamID := middleware.GetStreamID(r)
	headers := h.engine.ConfigManager().GetConfig().UpstreamHeaderSettings()

	// Clients must not be able to send these to the backend themselves.
	r.Header.Del("FG-Stream")
	r.Header.Del("FG-IPCountry")
	if headers.StreamID {
		r.Header.Set("FG-Stream", streamID)
	}
	if headers.IPCountry {
		r.Header.Set("FG-IPCountry", clientCountryCode(r))
	}
	middleware.AddStreamIDHeader(w.Header(), r)

	active := h.activeUpstream.Add(1)
	defer h.activeUpstream.Add(-1)
	middleware.BeginUpstream(r, active)
	err := next.ServeHTTP(w, middleware.TraceUpstreamAttempts(r))
	middleware.FinishUpstream(r, upstreamOutcome(r, err))

	// Caddy writes the error response after this handler returns, so the
	// request log would otherwise show the status of an unwritten response.
	if err != nil {
		middleware.RecordResponseStatus(r, errorStatus(err))
	}

	return err
}

// errorStatus returns the status Caddy responds with for err.
func errorStatus(err error) int {
	var handlerErr caddyhttp.HandlerError
	if errors.As(err, &handlerErr) && handlerErr.StatusCode != 0 {
		return handlerErr.StatusCode
	}

	return http.StatusInternalServerError
}

func upstreamOutcome(r *http.Request, err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, context.Canceled) || errors.Is(r.Context().Err(), context.Canceled):
		return "client_canceled"
	case errorStatus(err) == http.StatusGatewayTimeout:
		return "timeout"
	default:
		return "upstream_error"
	}
}

// clientCountryCode returns the client's ISO 3166-1 alpha-2 country code, or
// "XX" when it is unknown.
func clientCountryCode(r *http.Request) string {
	if asn := middleware.GetClientASN(r); asn != nil && asn.CountryCode != "" {
		return strings.ToUpper(asn.CountryCode)
	}
	return "XX"
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
