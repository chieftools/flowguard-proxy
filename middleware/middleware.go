package middleware

import (
	"bufio"
	"net"
	"net/http"
)

// Middleware represents middleware that can wrap the entire HTTP request/response cycle
type Middleware interface {
	Handle(w http.ResponseWriter, r *http.Request, next http.Handler)
	Stop()
}

// Chain manages a chain of middleware processors
type Chain struct {
	middlewares []Middleware
}

// NewChain creates a new middleware chain
func NewChain() *Chain {
	return &Chain{
		middlewares: make([]Middleware, 0),
	}
}

// Add adds a middleware to the chain
func (mc *Chain) Add(m Middleware) {
	mc.middlewares = append(mc.middlewares, m)
}

// ServeHTTP makes Chain implement http.Handler interface
func (mc *Chain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mc.ServeHTTPWithHandler(w, r, nil)
}

// ServeHTTPWithHandler processes the request through middleware chain, then the final handler
func (mc *Chain) ServeHTTPWithHandler(w http.ResponseWriter, r *http.Request, finalHandler http.Handler) {
	// Start with the final handler
	handler := finalHandler
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No final handler, just return
		})
	}

	// Build the middleware chain by wrapping handlers
	// We iterate backwards so that the first middleware added becomes the outermost wrapper
	// This means the first added middleware executes first and completes last (wrap pattern)
	for i := len(mc.middlewares) - 1; i >= 0; i-- {
		middleware := mc.middlewares[i]
		currentHandler := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			middleware.Handle(w, r, currentHandler)
		})
	}

	// Execute the final wrapped handler
	handler.ServeHTTP(w, r)
}

// Stop calls Stop on all middlewares in the chain
func (mc *Chain) Stop() {
	for _, m := range mc.middlewares {
		m.Stop()
	}
}

// ResponseWriterWrapper wraps http.ResponseWriter to capture status code, content type, and body size
type ResponseWriterWrapper struct {
	http.ResponseWriter

	BodySize    int64
	StatusCode  int
	ContentType string
}

func (w *ResponseWriterWrapper) Write(data []byte) (int, error) {
	// Capture content type if not already captured and WriteHeader wasn't called
	if w.ContentType == "" {
		if ct := w.Header().Get("Content-Type"); ct != "" {
			w.ContentType = ct
		}
	}

	n, err := w.ResponseWriter.Write(data)
	if n > 0 {
		w.BodySize += int64(n)
	}
	return n, err
}

func (w *ResponseWriterWrapper) WriteHeader(statusCode int) {
	w.StatusCode = statusCode
	// Capture content type if set
	if ct := w.Header().Get("Content-Type"); ct != "" {
		w.ContentType = ct
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

// Hijack implements http.Hijacker interface to support WebSocket upgrades
// This method delegates to the underlying ResponseWriter if it supports hijacking
func (w *ResponseWriterWrapper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}
