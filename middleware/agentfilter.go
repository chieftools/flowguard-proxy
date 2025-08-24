package middleware

import (
	"log"
	"net/http"
)

// AgentFilter implements User-Agent based filtering
type AgentFilter struct{}

// NewAgentFilter creates a new IP filter middleware
func NewAgentFilter() *AgentFilter {
	return &AgentFilter{}
}

// Process checks if the client IP is allowed
func (m *AgentFilter) Process(w http.ResponseWriter, r *http.Request) (bool, int, string) {
	agent := r.Header.Get("User-Agent")

	if agent == "" {
		log.Printf("[middleware:agentfilter] blocked request with empty user agent for %s", r.Host)
		return false, http.StatusBadRequest, "Bad Request"
	}

	return true, 0, ""
}
