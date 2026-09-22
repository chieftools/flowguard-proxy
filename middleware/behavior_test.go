package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"flowguard/config"
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
