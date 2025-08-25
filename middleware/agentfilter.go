package middleware

import (
	"log"
	"net/http"
)

var blacklistedAgents = []string{
	"",
	"Go-http-client/1.1",
	"Go-http-client/2.0",
	"Typhoeus - https://github.com/typhoeus/typhoeus",
	"Mozilla/5.0 (compatible; Let's Encrypt prevalidation check; +https://www.antagonist.nl)",
}

// AgentFilter implements User-Agent based filtering
type AgentFilter struct{}

// NewAgentFilter creates a new IP filter middleware
func NewAgentFilter() *AgentFilter {
	return &AgentFilter{}
}

// Process checks if the client IP is allowed
func (m *AgentFilter) Process(w http.ResponseWriter, r *http.Request) (bool, int, string) {
	agent := r.Header.Get("User-Agent")

	for _, blocked := range blacklistedAgents {
		if agent == blocked {
			log.Printf("[middleware:agentfilter] blocked request with user agent '%s' for %s", agent, r.Host)
			return false, http.StatusForbidden, "Forbidden"
		}
	}

	return true, 0, ""
}
