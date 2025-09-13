package middleware

import (
	"net/http"
)

// Middleware represents middleware that can wrap the entire HTTP request/response cycle
type Middleware interface {
	Handle(w http.ResponseWriter, r *http.Request, next http.Handler)
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

// ResponseWriterWrapper wraps http.ResponseWriter to capture status code
type ResponseWriterWrapper struct {
	http.ResponseWriter
	StatusCodeValue int
}

func (w *ResponseWriterWrapper) WriteHeader(statusCode int) {
	w.StatusCodeValue = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *ResponseWriterWrapper) StatusCode() int {
	if w.StatusCodeValue == 0 {
		return http.StatusInternalServerError
	}

	return w.StatusCodeValue
}
