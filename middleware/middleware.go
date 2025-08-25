package middleware

import (
	"net/http"
)

// Middleware represents a security middleware that can allow or deny requests
type Middleware interface {
	Process(w http.ResponseWriter, r *http.Request) (bool, int, string)
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

// Process runs through all middleware and returns false if any denies the request
func (mc *Chain) Process(w http.ResponseWriter, r *http.Request) bool {
	for _, m := range mc.middlewares {
		allowed, statusCode, message := m.Process(w, r)
		if !allowed {
			http.Error(w, message, statusCode)
			return false
		}
	}
	return true
}
