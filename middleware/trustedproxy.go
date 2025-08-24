package middleware

import (
	"bufio"
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TrustedProxyManager manages dynamically loaded trusted proxy IP ranges
type TrustedProxyManager struct {
	urls            []string
	httpClient      *http.Client
	trustedNets     []*net.IPNet
	refreshInterval time.Duration
	stopCh          chan struct{}
	mu              sync.RWMutex
	wg              sync.WaitGroup
}

// NewTrustedProxyManager creates a new trusted proxy manager
func NewTrustedProxyManager(urls []string, refreshInterval time.Duration) *TrustedProxyManager {
	if refreshInterval <= 0 {
		refreshInterval = 12 * time.Hour
	}

	return &TrustedProxyManager{
		urls:            urls,
		stopCh:          make(chan struct{}),
		refreshInterval: refreshInterval,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Start initializes the trusted proxy list and starts the refresh goroutine
func (tpm *TrustedProxyManager) Start() error {
	// Load initial lists
	if err := tpm.refresh(); err != nil {
		return err
	}

	// Start background refresh goroutine
	tpm.wg.Add(1)
	go tpm.refreshLoop()

	return nil
}

// Stop stops the refresh goroutine
func (tpm *TrustedProxyManager) Stop() {
	close(tpm.stopCh)
	tpm.wg.Wait()
}

// IsTrustedProxy checks if an IP is from a trusted proxy
func (tpm *TrustedProxyManager) IsTrustedProxy(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	tpm.mu.RLock()
	defer tpm.mu.RUnlock()

	for _, trustedNet := range tpm.trustedNets {
		if trustedNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// GetTrustedNets returns a copy of the current trusted networks
func (tpm *TrustedProxyManager) GetTrustedNets() []*net.IPNet {
	tpm.mu.RLock()
	defer tpm.mu.RUnlock()

	result := make([]*net.IPNet, len(tpm.trustedNets))
	copy(result, tpm.trustedNets)
	return result
}

// refreshLoop runs the refresh process on a schedule
func (tpm *TrustedProxyManager) refreshLoop() {
	defer tpm.wg.Done()

	ticker := time.NewTicker(tpm.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := tpm.refresh(); err != nil {
				log.Printf("[trustedproxy] Failed to refresh trusted proxy lists: %v", err)
			}
		case <-tpm.stopCh:
			return
		}
	}
}

// refresh fetches and updates the trusted proxy lists
func (tpm *TrustedProxyManager) refresh() error {
	var allNets []*net.IPNet

	for _, url := range tpm.urls {
		nets, err := tpm.fetchIPList(url)
		if err != nil {
			log.Printf("[trustedproxy] Failed to fetch IP list from %s: %v", url, err)
			continue
		}
		allNets = append(allNets, nets...)
	}

	if len(allNets) == 0 && len(tpm.urls) > 0 {
		log.Printf("[trustedproxy] Warning: No IP ranges loaded from any URL")
	}

	tpm.mu.Lock()
	tpm.trustedNets = allNets
	tpm.mu.Unlock()

	log.Printf("[trustedproxy] Loaded %d trusted proxy IP ranges", len(allNets))
	return nil
}

// fetchIPList fetches an IP list from a URL
func (tpm *TrustedProxyManager) fetchIPList(url string) ([]*net.IPNet, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := tpm.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var nets []*net.IPNet
	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Try to parse as CIDR first
		_, ipNet, err := net.ParseCIDR(line)
		if err == nil {
			nets = append(nets, ipNet)
			continue
		}

		// Try to parse as single IP
		ip := net.ParseIP(line)
		if ip != nil {
			// Convert single IP to CIDR
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: mask})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return nets, nil
}
