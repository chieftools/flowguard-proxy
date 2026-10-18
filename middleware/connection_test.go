package middleware

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestConnectionInfoTracksRequestsAndConcurrency(t *testing.T) {
	ctx := ContextWithConnectionInfo(context.Background())
	first := httptest.NewRequest("GET", "https://service.example.test/", nil).WithContext(ctx)
	second := httptest.NewRequest("GET", "https://service.example.test/", nil).WithContext(ctx)

	finishFirst := BeginConnectionRequest(first)
	finishSecond := BeginConnectionRequest(second)

	snapshot := GetConnectionSnapshot(first)
	if snapshot == nil {
		t.Fatal("expected a connection snapshot")
	}
	if snapshot.ID == "" || snapshot.Requests != 2 || snapshot.InFlight != 2 || snapshot.PeakInFlight != 2 {
		t.Fatalf("unexpected active snapshot: %#v", snapshot)
	}

	finishSecond()
	finishFirst()
	snapshot = GetConnectionSnapshot(first)
	if snapshot.InFlight != 0 || snapshot.PeakInFlight != 2 {
		t.Fatalf("unexpected completed snapshot: %#v", snapshot)
	}
}

func TestRequestInfoIncludesPrivacySafeCookieAndHeaderSignals(t *testing.T) {
	req := httptest.NewRequest("GET", "https://service.example.test/", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Add("Cookie", "synthetic_session=private; preference=compact")

	info := getRequestInfo(req, []string{"accept"})
	if !info.HasCookie {
		t.Fatal("expected cookie presence to be recorded")
	}
	if len(info.CookieNames) != 2 || info.CookieNames[0] != "preference" || info.CookieNames[1] != "synthetic_session" {
		t.Fatalf("unexpected cookie names: %#v", info.CookieNames)
	}
	if info.HeaderSetHash == "" {
		t.Fatal("expected a header-set fingerprint")
	}
}

func TestClientInfoIncludesPrivacySafeNetworkPrefix(t *testing.T) {
	req := httptest.NewRequest("GET", "https://service.example.test/", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyClientIP, "198.51.100.73"))

	info := getClientInfo(req)
	if info.NetworkPrefix != "198.51.100.0/24" {
		t.Fatalf("network prefix = %q, want 198.51.100.0/24", info.NetworkPrefix)
	}
}
