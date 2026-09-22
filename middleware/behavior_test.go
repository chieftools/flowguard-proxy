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
	if last.Global.DomainRequests10S != 3 || last.Global.PathRequests10S != 3 {
		t.Fatalf("unexpected global counters: %+v", last.Global)
	}
	if last.Fingerprint.Requests10S != 3 || last.Fingerprint.UniqueIPs60S != 2 || last.Fingerprint.UniqueASNs60S != 2 || last.Fingerprint.UniqueCountries != 2 {
		t.Fatalf("unexpected fingerprint counters: %+v", last.Fingerprint)
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
