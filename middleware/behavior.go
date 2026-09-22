package middleware

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"flowguard/normalization"
)

const (
	behaviorWindowSeconds = 60
	maxBehaviorKeys       = 100_000
	maxCardinalityKeys    = 100_000
)

type behaviorSnapshotContextKey struct{}

type BehaviorSnapshot struct {
	Client      ClientBehaviorSnapshot      `json:"client"`
	Fingerprint FingerprintBehaviorSnapshot `json:"fingerprint,omitempty"`
	Server      ServerBehaviorSnapshot      `json:"server"`
}

type ClientBehaviorSnapshot struct {
	Requests1S         uint64 `json:"requests_1s"`
	Requests10S        uint64 `json:"requests_10s"`
	Requests60S        uint64 `json:"requests_60s"`
	PathRequests10S    uint64 `json:"path_requests_10s"`
	PathRequests60S    uint64 `json:"path_requests_60s"`
	ConcurrentRequests int64  `json:"concurrent_requests"`
}

type FingerprintBehaviorSnapshot struct {
	Requests10S     uint64 `json:"requests_10s,omitempty"`
	Requests60S     uint64 `json:"requests_60s,omitempty"`
	UniqueIPs60S    int    `json:"unique_ips_60s,omitempty"`
	UniqueASNs60S   int    `json:"unique_asns_60s,omitempty"`
	UniqueCountries int    `json:"unique_countries_60s,omitempty"`
}

type ServerBehaviorSnapshot struct {
	DomainRequests10S     uint64 `json:"domain_requests_10s"`
	DomainRequests60S     uint64 `json:"domain_requests_60s"`
	DomainPathRequests10S uint64 `json:"domain_path_requests_10s"`
	DomainPathRequests60S uint64 `json:"domain_path_requests_60s"`
}

type behaviorWindow struct {
	counts   [behaviorWindowSeconds]uint64
	lastSeen int64
}

func (w *behaviorWindow) add(now int64) {
	if w.lastSeen == 0 || now-w.lastSeen >= behaviorWindowSeconds {
		clear(w.counts[:])
	} else {
		for second := w.lastSeen + 1; second <= now; second++ {
			w.counts[int(second%behaviorWindowSeconds)] = 0
		}
	}
	index := int(now % behaviorWindowSeconds)
	w.counts[index]++
	w.lastSeen = now
}

func (w *behaviorWindow) total(now int64, seconds int64) uint64 {
	var total uint64
	for offset := int64(0); offset < seconds; offset++ {
		total += w.counts[int((now-offset)%behaviorWindowSeconds)]
	}
	return total
}

type fingerprintCardinality struct {
	clients         map[string]int64
	asns            map[string]int64
	countries       map[string]int64
	lastCountedAt   int64
	uniqueClients   int
	uniqueASNs      int
	uniqueCountries int
}

type BehaviorTracker struct {
	mu                  sync.Mutex
	client              map[string]*behaviorWindow
	clientPath          map[string]*behaviorWindow
	fingerprint         map[string]*behaviorWindow
	domain              map[string]*behaviorWindow
	domainPath          map[string]*behaviorWindow
	clientInFlight      map[string]int64
	cardinality         map[string]*fingerprintCardinality
	cardinalityKeyCount int
	requestCount        uint64
}

func NewBehaviorTracker() *BehaviorTracker {
	return &BehaviorTracker{
		client:         make(map[string]*behaviorWindow),
		clientPath:     make(map[string]*behaviorWindow),
		fingerprint:    make(map[string]*behaviorWindow),
		domain:         make(map[string]*behaviorWindow),
		domainPath:     make(map[string]*behaviorWindow),
		clientInFlight: make(map[string]int64),
		cardinality:    make(map[string]*fingerprintCardinality),
	}
}

func (t *BehaviorTracker) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	now := time.Now().Unix()
	clientIP := GetClientIP(r)
	ja4 := GetJA4Fingerprint(r)
	domain := behaviorDomain(r.Host)
	path := normalization.NormalizePath(r.URL.Path)
	clientPathKey := ""
	if clientIP != "" {
		clientPathKey = clientIP + "\x00" + path
	}

	t.mu.Lock()
	t.requestCount++
	if t.requestCount%1024 == 0 {
		t.cleanup(now)
	}

	clientWindow := t.add(t.client, clientIP, now)
	clientPathWindow := t.add(t.clientPath, clientPathKey, now)
	fingerprintWindow := t.add(t.fingerprint, ja4, now)
	domainWindow := t.add(t.domain, domain, now)
	domainPathWindow := t.add(t.domainPath, domain+"\x00"+path, now)

	if clientIP != "" {
		t.clientInFlight[clientIP]++
	}

	snapshot := &BehaviorSnapshot{
		Client: ClientBehaviorSnapshot{
			Requests1S:         windowTotal(clientWindow, now, 1),
			Requests10S:        windowTotal(clientWindow, now, 10),
			Requests60S:        windowTotal(clientWindow, now, 60),
			PathRequests10S:    windowTotal(clientPathWindow, now, 10),
			PathRequests60S:    windowTotal(clientPathWindow, now, 60),
			ConcurrentRequests: t.clientInFlight[clientIP],
		},
		Server: ServerBehaviorSnapshot{
			DomainRequests10S:     windowTotal(domainWindow, now, 10),
			DomainRequests60S:     windowTotal(domainWindow, now, 60),
			DomainPathRequests10S: windowTotal(domainPathWindow, now, 10),
			DomainPathRequests60S: windowTotal(domainPathWindow, now, 60),
		},
	}

	if ja4 != "" {
		cardinality := t.cardinalityFor(ja4)
		if cardinality != nil {
			if t.recordCardinality(cardinality.clients, clientIP, now) && cardinality.lastCountedAt == now {
				cardinality.uniqueClients++
			}
			if asn := GetClientASN(r); asn != nil {
				if t.recordCardinality(cardinality.asns, asn.ASN, now) && cardinality.lastCountedAt == now {
					cardinality.uniqueASNs++
				}
				if t.recordCardinality(cardinality.countries, asn.CountryCode, now) && cardinality.lastCountedAt == now {
					cardinality.uniqueCountries++
				}
			}
		}
		snapshot.Fingerprint = FingerprintBehaviorSnapshot{
			Requests10S: windowTotal(fingerprintWindow, now, 10),
			Requests60S: windowTotal(fingerprintWindow, now, 60),
		}
		if cardinality != nil {
			snapshot.Fingerprint.UniqueIPs60S,
				snapshot.Fingerprint.UniqueASNs60S,
				snapshot.Fingerprint.UniqueCountries = cardinalityCounts(cardinality, now)
		}
	}
	t.mu.Unlock()

	r = r.WithContext(context.WithValue(r.Context(), behaviorSnapshotContextKey{}, snapshot))
	defer t.finish(clientIP)
	next.ServeHTTP(w, r)
}

func (t *BehaviorTracker) Stop() {}

func GetBehaviorSnapshot(r *http.Request) *BehaviorSnapshot {
	if r == nil {
		return nil
	}
	snapshot, _ := r.Context().Value(behaviorSnapshotContextKey{}).(*BehaviorSnapshot)
	return snapshot
}

func BehaviorMetric(r *http.Request, key string) (float64, bool) {
	snapshot := GetBehaviorSnapshot(r)
	if snapshot == nil {
		return 0, false
	}

	switch key {
	case "client.requests_1s":
		return float64(snapshot.Client.Requests1S), true
	case "client.requests_10s":
		return float64(snapshot.Client.Requests10S), true
	case "client.requests_60s":
		return float64(snapshot.Client.Requests60S), true
	case "client.path_requests_10s":
		return float64(snapshot.Client.PathRequests10S), true
	case "client.path_requests_60s":
		return float64(snapshot.Client.PathRequests60S), true
	case "client.concurrent_requests":
		return float64(snapshot.Client.ConcurrentRequests), true
	case "fingerprint.requests_10s":
		return float64(snapshot.Fingerprint.Requests10S), true
	case "fingerprint.requests_60s":
		return float64(snapshot.Fingerprint.Requests60S), true
	case "fingerprint.unique_ips_60s":
		return float64(snapshot.Fingerprint.UniqueIPs60S), true
	case "fingerprint.unique_asns_60s":
		return float64(snapshot.Fingerprint.UniqueASNs60S), true
	case "fingerprint.unique_countries_60s":
		return float64(snapshot.Fingerprint.UniqueCountries), true
	// Retain the 0.22.0 global keys while deployed configurations migrate.
	case "server.domain_requests_10s", "global.domain_requests_10s":
		return float64(snapshot.Server.DomainRequests10S), true
	case "server.domain_requests_60s", "global.domain_requests_60s":
		return float64(snapshot.Server.DomainRequests60S), true
	case "server.domain_path_requests_10s", "global.path_requests_10s":
		return float64(snapshot.Server.DomainPathRequests10S), true
	case "server.domain_path_requests_60s", "global.path_requests_60s":
		return float64(snapshot.Server.DomainPathRequests60S), true
	default:
		return 0, false
	}
}

func (t *BehaviorTracker) add(windows map[string]*behaviorWindow, key string, now int64) *behaviorWindow {
	if key == "" {
		return nil
	}
	window := windows[key]
	if window == nil {
		if t.totalWindowKeys() >= maxBehaviorKeys {
			return nil
		}
		window = &behaviorWindow{}
		windows[key] = window
	}
	window.add(now)
	return window
}

func (t *BehaviorTracker) totalWindowKeys() int {
	return len(t.client) + len(t.clientPath) + len(t.fingerprint) + len(t.domain) + len(t.domainPath)
}

func (t *BehaviorTracker) cardinalityFor(ja4 string) *fingerprintCardinality {
	entry := t.cardinality[ja4]
	if entry == nil {
		if len(t.cardinality) >= maxBehaviorKeys {
			return nil
		}
		entry = &fingerprintCardinality{
			clients:   make(map[string]int64),
			asns:      make(map[string]int64),
			countries: make(map[string]int64),
		}
		t.cardinality[ja4] = entry
	}
	return entry
}

func (t *BehaviorTracker) recordCardinality(values map[string]int64, value string, now int64) bool {
	if value == "" {
		return false
	}
	_, exists := values[value]
	if !exists {
		if t.cardinalityKeyCount >= maxCardinalityKeys {
			return false
		}
		t.cardinalityKeyCount++
	}
	values[value] = now

	return !exists
}

func activeCardinality(values map[string]int64, now int64) int {
	count := 0
	for _, lastSeen := range values {
		if lastSeen > now-behaviorWindowSeconds {
			count++
		}
	}
	return count
}

func cardinalityCounts(entry *fingerprintCardinality, now int64) (int, int, int) {
	if entry.lastCountedAt == now {
		return entry.uniqueClients, entry.uniqueASNs, entry.uniqueCountries
	}

	entry.lastCountedAt = now
	entry.uniqueClients = activeCardinality(entry.clients, now)
	entry.uniqueASNs = activeCardinality(entry.asns, now)
	entry.uniqueCountries = activeCardinality(entry.countries, now)

	return entry.uniqueClients, entry.uniqueASNs, entry.uniqueCountries
}

func windowTotal(window *behaviorWindow, now int64, seconds int64) uint64 {
	if window == nil {
		return 0
	}
	return window.total(now, seconds)
}

func (t *BehaviorTracker) finish(clientIP string) {
	if clientIP == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.clientInFlight[clientIP]--
	if t.clientInFlight[clientIP] <= 0 {
		delete(t.clientInFlight, clientIP)
	}
}

func (t *BehaviorTracker) cleanup(now int64) {
	for _, windows := range []map[string]*behaviorWindow{t.client, t.clientPath, t.fingerprint, t.domain, t.domainPath} {
		for key, window := range windows {
			if window.lastSeen <= now-behaviorWindowSeconds {
				delete(windows, key)
			}
		}
	}

	for fingerprint, entry := range t.cardinality {
		for _, values := range []map[string]int64{entry.clients, entry.asns, entry.countries} {
			for value, lastSeen := range values {
				if lastSeen <= now-behaviorWindowSeconds {
					delete(values, value)
					t.cardinalityKeyCount--
				}
			}
		}
		if len(entry.clients) == 0 && len(entry.asns) == 0 && len(entry.countries) == 0 {
			delete(t.cardinality, fingerprint)
		}
	}
}

func behaviorNumber(value string) (float64, bool) {
	number, err := strconv.ParseFloat(value, 64)
	return number, err == nil
}

func behaviorDomain(host string) string {
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		host = hostname
	}

	return strings.ToLower(host)
}
