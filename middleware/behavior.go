package middleware

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"go.chief.tools/flowguard-proxy/normalization"
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

// behaviorExpiryBatch caps how many expired entries one request removes from
// each list, so a burst of expiries is spread over the following requests
// instead of stalling one of them.
const behaviorExpiryBatch = 256

type fingerprintCardinality struct {
	clients   *recencyList[struct{}]
	asns      *recencyList[struct{}]
	countries *recencyList[struct{}]
}

type BehaviorTracker struct {
	mu                  sync.Mutex
	now                 func() time.Time
	client              *recencyList[behaviorWindow]
	clientPath          *recencyList[behaviorWindow]
	fingerprint         *recencyList[behaviorWindow]
	domain              *recencyList[behaviorWindow]
	domainPath          *recencyList[behaviorWindow]
	clientInFlight      map[string]int64
	cardinality         *recencyList[*fingerprintCardinality]
	cardinalityKeyCount int
}

func NewBehaviorTracker() *BehaviorTracker {
	return &BehaviorTracker{
		now:            time.Now,
		client:         newRecencyList[behaviorWindow](),
		clientPath:     newRecencyList[behaviorWindow](),
		fingerprint:    newRecencyList[behaviorWindow](),
		domain:         newRecencyList[behaviorWindow](),
		domainPath:     newRecencyList[behaviorWindow](),
		clientInFlight: make(map[string]int64),
		cardinality:    newRecencyList[*fingerprintCardinality](),
	}
}

func (t *BehaviorTracker) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	now := t.now().Unix()
	clientIP := clientBucketKey(GetClientIP(r))
	ja4 := GetJA4Fingerprint(r)
	domain := normalization.Host(r.Host)
	path := normalization.NormalizePath(r.URL.Path)
	clientPathKey := ""
	if clientIP != "" {
		clientPathKey = clientIP + "\x00" + path
	}

	t.mu.Lock()
	t.expire(now)

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
		snapshot.Fingerprint = FingerprintBehaviorSnapshot{
			Requests10S: windowTotal(fingerprintWindow, now, 10),
			Requests60S: windowTotal(fingerprintWindow, now, 60),
		}
		if cardinality := t.cardinalityFor(ja4, now); cardinality != nil {
			t.recordCardinality(cardinality.clients, clientIP, now)
			if asn := GetClientASN(r); asn != nil {
				t.recordCardinality(cardinality.asns, asn.ASN, now)
				t.recordCardinality(cardinality.countries, asn.CountryCode, now)
			}
			snapshot.Fingerprint.UniqueIPs60S = cardinality.clients.len()
			snapshot.Fingerprint.UniqueASNs60S = cardinality.asns.len()
			snapshot.Fingerprint.UniqueCountries = cardinality.countries.len()
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

func (t *BehaviorTracker) add(windows *recencyList[behaviorWindow], key string, now int64) *behaviorWindow {
	if key == "" {
		return nil
	}
	entry := windows.get(key)
	if entry == nil {
		if t.totalWindowKeys() >= maxBehaviorKeys {
			return nil
		}
		entry = windows.insert(key, now)
	} else {
		windows.touch(entry, now)
	}
	entry.value.add(now)
	return &entry.value
}

func (t *BehaviorTracker) totalWindowKeys() int {
	return t.client.len() + t.clientPath.len() + t.fingerprint.len() + t.domain.len() + t.domainPath.len()
}

// cardinalityFor returns the fingerprint's clients, ASNs and countries, with
// those not seen in the last minute removed.
func (t *BehaviorTracker) cardinalityFor(ja4 string, now int64) *fingerprintCardinality {
	entry := t.cardinality.get(ja4)
	if entry == nil {
		if t.cardinality.len() >= maxBehaviorKeys {
			return nil
		}
		entry = t.cardinality.insert(ja4, now)
		entry.value = &fingerprintCardinality{
			clients:   newRecencyList[struct{}](),
			asns:      newRecencyList[struct{}](),
			countries: newRecencyList[struct{}](),
		}
		return entry.value
	}

	// Remove every expired value, not a batch, so the unique counts read from
	// the list lengths stay exact.
	t.cardinality.touch(entry, now)
	cutoff := now - behaviorWindowSeconds
	for _, values := range []*recencyList[struct{}]{entry.value.clients, entry.value.asns, entry.value.countries} {
		t.cardinalityKeyCount -= values.expire(cutoff, values.len(), nil)
	}
	return entry.value
}

func (t *BehaviorTracker) recordCardinality(values *recencyList[struct{}], value string, now int64) {
	if value == "" {
		return
	}
	if entry := values.get(value); entry != nil {
		values.touch(entry, now)
		return
	}
	if t.cardinalityKeyCount >= maxCardinalityKeys {
		return
	}
	values.insert(value, now)
	t.cardinalityKeyCount++
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

// expire removes windows and fingerprints not seen in the last minute, oldest
// first, so it only visits the entries it removes.
func (t *BehaviorTracker) expire(now int64) {
	cutoff := now - behaviorWindowSeconds
	for _, windows := range []*recencyList[behaviorWindow]{t.client, t.clientPath, t.fingerprint, t.domain, t.domainPath} {
		windows.expire(cutoff, behaviorExpiryBatch, nil)
	}
	t.cardinality.expire(cutoff, behaviorExpiryBatch, func(entry *recencyEntry[*fingerprintCardinality]) {
		cardinality := entry.value
		t.cardinalityKeyCount -= cardinality.clients.len() + cardinality.asns.len() + cardinality.countries.len()
	})
}

func behaviorNumber(value string) (float64, bool) {
	number, err := strconv.ParseFloat(value, 64)
	return number, err == nil
}
