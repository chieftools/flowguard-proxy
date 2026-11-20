package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"go.chief.tools/flowguard-proxy/config"
)

func TestBehaviorTrackerRecordsRollingClientAndFingerprintSignals(t *testing.T) {
	tracker := NewBehaviorTracker()
	var snapshots []*BehaviorSnapshot
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		snapshots = append(snapshots, GetBehaviorSnapshot(r))
	})

	requests := []struct {
		ip      string
		asn     string
		country string
	}{
		{ip: "192.0.2.10", asn: "64501", country: "XZ"},
		{ip: "192.0.2.10", asn: "64501", country: "XZ"},
		{ip: "198.51.100.20", asn: "64502", country: "XY"},
	}

	for _, item := range requests {
		req := httptest.NewRequest(http.MethodGet, "https://edge.example.test/landing", nil)
		ctx := context.WithValue(req.Context(), ContextKeyClientIP, item.ip)
		ctx = context.WithValue(ctx, ContextKeyClientASNInfo, &ASNInfo{ASN: item.asn, CountryCode: item.country})
		req = WithJA4Fingerprint(req.WithContext(ctx), "t13d-synthetic")
		tracker.Handle(httptest.NewRecorder(), req, next)
	}

	last := snapshots[len(snapshots)-1]
	if last.Client.Requests10S != 1 || last.Client.PathRequests10S != 1 {
		t.Fatalf("unexpected per-client counters: %+v", last.Client)
	}
	if last.Server.DomainRequests10S != 3 || last.Server.DomainPathRequests10S != 3 {
		t.Fatalf("unexpected server counters: %+v", last.Server)
	}
	if last.Fingerprint.Requests10S != 3 || last.Fingerprint.UniqueIPs60S != 2 || last.Fingerprint.UniqueASNs60S != 2 || last.Fingerprint.UniqueCountries != 2 {
		t.Fatalf("unexpected fingerprint counters: %+v", last.Fingerprint)
	}
}

func TestBehaviorMetricSupportsServerScopeAndGlobalAliases(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://edge.example.test/", nil)
	req = req.WithContext(context.WithValue(req.Context(), behaviorSnapshotContextKey{}, &BehaviorSnapshot{
		Server: ServerBehaviorSnapshot{
			DomainRequests10S:     21,
			DomainPathRequests10S: 13,
		},
	}))

	tests := map[string]float64{
		"server.domain_requests_10s":      21,
		"server.domain_path_requests_10s": 13,
		"global.domain_requests_10s":      21,
		"global.path_requests_10s":        13,
	}

	for key, expected := range tests {
		t.Run(key, func(t *testing.T) {
			actual, found := BehaviorMetric(req, key)
			if !found || actual != expected {
				t.Fatalf("expected %s to return %v, got %v (found %v)", key, expected, actual, found)
			}
		})
	}
}

func TestBehaviorMatcherComparesRollingMetrics(t *testing.T) {
	rm := &RulesMiddleware{}
	req := httptest.NewRequest(http.MethodGet, "https://edge.example.test/", nil)
	req = req.WithContext(context.WithValue(req.Context(), behaviorSnapshotContextKey{}, &BehaviorSnapshot{
		Client: ClientBehaviorSnapshot{Requests10S: 14},
	}))

	if !rm.evaluateMatch(req, &config.MatchCondition{
		Type:  "behavior",
		Key:   "client.requests_10s",
		Match: "greater-than",
		Value: "10",
	}) {
		t.Fatal("expected behavioral threshold to match")
	}
	if rm.evaluateMatch(req, &config.MatchCondition{
		Type:  "behavior",
		Key:   "client.requests_10s",
		Match: "less-than-or-equal",
		Value: "10",
	}) {
		t.Fatal("expected behavioral threshold not to match")
	}
}

func TestBehaviorTrackerGroupsIPv6ClientsBySlash64(t *testing.T) {
	tracker := NewBehaviorTracker()
	var last *BehaviorSnapshot
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		last = GetBehaviorSnapshot(r)
	})

	for _, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2:ffff::3"} {
		req := httptest.NewRequest(http.MethodGet, "https://edge.example.test/landing", nil)
		req = WithJA4Fingerprint(req.WithContext(context.WithValue(req.Context(), ContextKeyClientIP, ip)), "t13d-synthetic")
		tracker.Handle(httptest.NewRecorder(), req, next)
	}

	if last.Client.Requests10S != 3 {
		t.Fatalf("expected addresses in one /64 to share client counters, got %+v", last.Client)
	}
	if last.Fingerprint.UniqueIPs60S != 1 {
		t.Fatalf("expected one /64 to count as one unique client, got %+v", last.Fingerprint)
	}
}

func TestBehaviorTrackerExpiresQuietClientsAndFingerprints(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	tracker := NewBehaviorTracker()
	tracker.now = func() time.Time { return clock }
	var last *BehaviorSnapshot
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		last = GetBehaviorSnapshot(r)
	})
	request := func(ip, ja4 string) {
		req := httptest.NewRequest(http.MethodGet, "https://edge.example.test/landing", nil)
		ctx := context.WithValue(req.Context(), ContextKeyClientIP, ip)
		ctx = context.WithValue(ctx, ContextKeyClientASNInfo, &ASNInfo{ASN: "AS-" + ip, CountryCode: "XZ"})
		tracker.Handle(httptest.NewRecorder(), WithJA4Fingerprint(req.WithContext(ctx), ja4), next)
	}

	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		request(ip, "t13d-busy")
	}
	request("198.51.100.9", "t13d-quiet")
	clock = clock.Add(30 * time.Second)
	request("192.0.2.4", "t13d-busy")
	clock = clock.Add(31 * time.Second)
	request("192.0.2.5", "t13d-busy")

	if last.Fingerprint.UniqueIPs60S != 2 || last.Fingerprint.UniqueASNs60S != 2 {
		t.Fatalf("fingerprint counters = %+v, want only the 2 clients seen in the last minute", last.Fingerprint)
	}
	if tracker.client.len() != 2 || tracker.client.get("192.0.2.1") != nil {
		t.Fatalf("tracked clients = %d, want the 3 quiet clients removed", tracker.client.len())
	}
	if tracker.cardinality.get("t13d-quiet") != nil {
		t.Fatal("expected the quiet fingerprint to be removed")
	}
	// Two clients and two ASNs plus one country, for the busy fingerprint only.
	if tracker.cardinalityKeyCount != 5 {
		t.Fatalf("cardinality key count = %d, want 5", tracker.cardinalityKeyCount)
	}

	clock = clock.Add(time.Second)
	request("192.0.2.1", "t13d-busy")
	if last.Client.Requests60S != 1 {
		t.Fatalf("returning client requests_60s = %d, want 1", last.Client.Requests60S)
	}
}

func TestRecencyListExpiresOldestEntriesFirst(t *testing.T) {
	list := newRecencyList[struct{}]()
	list.insert("a", 10)
	list.insert("b", 20)
	list.insert("c", 30)
	list.touch(list.get("a"), 40)

	var removed []string
	record := func(entry *recencyEntry[struct{}]) { removed = append(removed, entry.key) }

	if count := list.expire(35, 1, record); count != 1 || !slices.Equal(removed, []string{"b"}) {
		t.Fatalf("expire with limit 1 removed %v (%d), want [b]", removed, count)
	}
	if count := list.expire(35, 10, record); count != 1 || !slices.Equal(removed, []string{"b", "c"}) {
		t.Fatalf("expire removed %v (%d), want [b c]", removed, count)
	}
	if list.len() != 1 || list.get("a") == nil {
		t.Fatalf("remaining entries = %d, want only the touched entry a", list.len())
	}
	if count := list.expire(40, 10, nil); count != 1 || list.len() != 0 || list.newest != nil || list.oldest != nil {
		t.Fatalf("expire of the last entry removed %d and left %d entries", count, list.len())
	}
}

func TestBehaviorTrackerKeepsExpiringAfterTheClockStepsBack(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	tracker := NewBehaviorTracker()
	tracker.now = func() time.Time { return clock }
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	request := func(ip string) {
		req := httptest.NewRequest(http.MethodGet, "https://edge.example.test/", nil)
		req = req.WithContext(context.WithValue(req.Context(), ContextKeyClientIP, ip))
		tracker.Handle(httptest.NewRecorder(), req, next)
	}

	request("192.0.2.1")
	clock = clock.Add(-time.Hour)
	request("192.0.2.2")
	if first, second := tracker.client.get("192.0.2.1"), tracker.client.get("192.0.2.2"); second.lastSeen < first.lastSeen {
		t.Fatalf("client seen after the clock stepped back has time %d, before %d", second.lastSeen, first.lastSeen)
	}

	clock = clock.Add(time.Hour + 61*time.Second)
	request("192.0.2.3")
	if tracker.client.len() != 1 || tracker.client.get("192.0.2.3") == nil {
		t.Fatalf("tracked clients = %d, want only the latest after a minute", tracker.client.len())
	}
}
