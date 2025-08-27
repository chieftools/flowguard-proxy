package middleware

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"flowguard/config"

	"github.com/oschwald/maxminddb-golang"
)

// Context keys for storing IP information
type contextKey string

const (
	ContextKeyClientIP      contextKey = "clientIP"
	ContextKeyClientASNInfo contextKey = "clientASNInfo"
	ContextKeyProxyIP       contextKey = "proxyIP"
	ContextKeyProxyASNInfo  contextKey = "proxyASNInfo"
	ContextKeyIsProxied     contextKey = "isProxied"
)

// ASNInfo holds ASN information from the MMDB database
type ASNInfo struct {
	Network       string `maxminddb:"network"`
	Country       string `maxminddb:"country"`
	CountryCode   string `maxminddb:"country_code"`
	Continent     string `maxminddb:"continent"`
	ContinentCode string `maxminddb:"continent_code"`
	ASN           string `maxminddb:"asn"`
	ASName        string `maxminddb:"as_name"`
	ASDomain      string `maxminddb:"as_domain"`
}

// IPInfo holds IP information
type IPInfo struct {
	IP  string
	ASN *ASNInfo
}

// IPLookupMiddleware enriches requests with IP and ASN information
type IPLookupMiddleware struct {
	configMgr *config.Manager
	asnDB     *maxminddb.Reader
	dbPath    string
	mu        sync.RWMutex
}

// NewIPLookupMiddleware creates a new IP enrichment middleware
func NewIPLookupMiddleware(configMgr *config.Manager) (*IPLookupMiddleware, error) {
	m := &IPLookupMiddleware{
		configMgr: configMgr,
	}

	// Load the ASN database
	if err := m.loadASNDatabase(); err != nil {
		// Don't fail if database is not available, just log warning
		log.Printf("[middleware:iplookup] Warning: IP database not available: %v", err)
		// Return middleware anyway - it will work without ASN lookups
		return m, nil
	}

	return m, nil
}

// loadASNDatabase loads or reloads the MaxMind ASN database
func (m *IPLookupMiddleware) loadASNDatabase() error {
	// Get database path from config manager
	dbPath, err := m.configMgr.GetIPDatabasePath()
	if err != nil {
		return fmt.Errorf("failed to get database path: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Close existing database if open
	if m.asnDB != nil {
		// Check if path changed
		if m.dbPath == dbPath {
			// Same path, no need to reload
			return nil
		}
		m.asnDB.Close()
	}

	// Open the MMDB file
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open MMDB file: %w", err)
	}

	m.asnDB = db
	m.dbPath = dbPath
	log.Printf("[middleware:iplookup] Loaded ASN database from %s", dbPath)
	return nil
}

// Process enriches the request with IP and ASN information
func (m *IPLookupMiddleware) Process(w http.ResponseWriter, r *http.Request) (bool, int, string) {
	// Extract the real client IP considering trusted proxies
	clientIP, proxyIP := m.extractIPs(r)

	// Create a new context with IP information
	ctx := r.Context()

	// Store client IP
	ctx = context.WithValue(ctx, ContextKeyClientIP, clientIP)

	// Lookup ASN for client IP
	if clientASNInfo := m.lookupASN(clientIP); clientASNInfo != nil {
		ctx = context.WithValue(ctx, ContextKeyClientASNInfo, clientASNInfo)
	}

	// If request came through a proxy, store proxy information
	if proxyIP != "" {
		ctx = context.WithValue(ctx, ContextKeyIsProxied, true)
		ctx = context.WithValue(ctx, ContextKeyProxyIP, proxyIP)

		// Lookup ASN for proxy IP
		if proxyASNInfo := m.lookupASN(proxyIP); proxyASNInfo != nil {
			ctx = context.WithValue(ctx, ContextKeyProxyASNInfo, proxyASNInfo)
		}
	} else {
		ctx = context.WithValue(ctx, ContextKeyIsProxied, false)
	}

	// Update the request with the new context
	*r = *r.WithContext(ctx)

	// Always allow - this middleware only enriches, doesn't block
	return true, 0, ""
}

// extractIPs extracts the real client IP and proxy IP (if applicable) from the request
func (m *IPLookupMiddleware) extractIPs(r *http.Request) (clientIP string, proxyIP string) {
	// Get the immediate remote address
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	// Check if the request came through a trusted proxy
	if m.configMgr != nil && m.configMgr.IsTrustedProxy(remoteIP) {
		proxyIP = remoteIP

		// Check X-Forwarded-For header
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			// Get the rightmost non-trusted IP from the chain
			ips := strings.Split(xff, ",")

			// Traverse from right to left to find the first non-trusted IP
			for i := len(ips) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(ips[i])
				if !m.configMgr.IsTrustedProxy(ip) {
					clientIP = ip
					return clientIP, proxyIP
				}
			}

			// If all IPs in the chain are trusted, use the leftmost one
			if len(ips) > 0 {
				clientIP = strings.TrimSpace(ips[0])
				return clientIP, proxyIP
			}
		}

		// Check X-Real-IP header
		xri := r.Header.Get("X-Real-IP")
		if xri != "" {
			clientIP = xri
			return clientIP, proxyIP
		}

		// Fallback to remote IP if no headers present
		clientIP = remoteIP
		proxyIP = ""
	} else {
		// Not from a trusted proxy, use the remote address as client IP
		clientIP = remoteIP
		proxyIP = ""
	}

	return clientIP, proxyIP
}

// lookupASN looks up ASN information for an IP address
func (m *IPLookupMiddleware) lookupASN(ipStr string) *ASNInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.asnDB == nil {
		return nil
	}

	// Parse the IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// Lookup ASN information
	var asn ASNInfo
	err := m.asnDB.Lookup(ip, &asn)
	if err != nil {
		// Silently ignore lookup errors (IP might not be in database)
		return nil
	}

	// Return nil if no ASN found
	if asn.ASN == "" {
		return nil
	}

	return &asn
}

// ReloadDatabase reloads the ASN database (useful for periodic updates)
func (m *IPLookupMiddleware) ReloadDatabase() {
	if err := m.loadASNDatabase(); err != nil {
		log.Printf("[middleware:iplookup] Failed to reload ASN database: %v", err)
	}
}

// Close closes the ASN database
func (m *IPLookupMiddleware) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.asnDB != nil {
		m.asnDB.Close()
		m.asnDB = nil
	}
}

// GetClientIP extracts the client IP from the request context
func GetClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(ContextKeyClientIP).(string); ok {
		return ip
	}
	return ""
}

// GetClientASN extracts the client ASN from the request context
func GetClientASN(r *http.Request) *ASNInfo {
	if asn, ok := r.Context().Value(ContextKeyClientASNInfo).(*ASNInfo); ok {
		return asn
	}
	return nil
}

// GetProxyIP extracts the proxy IP from the request context
func GetProxyIP(r *http.Request) string {
	if ip, ok := r.Context().Value(ContextKeyProxyIP).(string); ok {
		return ip
	}
	return ""
}

// GetProxyASN extracts the proxy ASN from the request context
func GetProxyASN(r *http.Request) *ASNInfo {
	if asn, ok := r.Context().Value(ContextKeyProxyASNInfo).(*ASNInfo); ok {
		return asn
	}
	return nil
}

// IsProxied checks if the request came through a proxy
func IsProxied(r *http.Request) bool {
	if proxied, ok := r.Context().Value(ContextKeyIsProxied).(bool); ok {
		return proxied
	}
	return false
}
