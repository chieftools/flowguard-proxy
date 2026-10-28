package api

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type backoffTestServer struct {
	requests int
	status   int
	header   http.Header
	now      time.Time
	client   *Client
}

func newBackoffTestServer(t *testing.T) *backoffTestServer {
	t.Helper()

	server := &backoffTestServer{status: http.StatusOK, now: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	server.client = NewClient("fgsvr_synthetic", "flowguard-test")
	server.client.baseURL = "https://flowguard.test"
	server.client.now = func() time.Time { return server.now }
	server.client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			server.requests++
			header := server.header
			if header == nil {
				header = make(http.Header)
			}
			return &http.Response{
				StatusCode: server.status,
				Header:     header,
				Body:       io.NopCloser(strings.NewReader(`{}`)),
			}, nil
		}),
	}
	return server
}

func (s *backoffTestServer) heartbeat() error {
	return s.client.SendHeartbeat(HeartbeatPayload{})
}

func assertBackingOff(t *testing.T, err error) {
	t.Helper()

	var backoff *BackoffError
	if !errors.As(err, &backoff) {
		t.Fatalf("expected a BackoffError, got %v", err)
	}
}

func TestUnauthorizedPausesRequestsForAnHour(t *testing.T) {
	server := newBackoffTestServer(t)
	server.status = http.StatusUnauthorized

	if err := server.heartbeat(); err == nil {
		t.Fatal("expected the 401 to be returned")
	}
	assertBackingOff(t, server.heartbeat())
	if server.requests != 1 {
		t.Fatalf("expected one request while backing off, got %d", server.requests)
	}

	server.now = server.now.Add(maximumBackoff)
	server.status = http.StatusOK
	if err := server.heartbeat(); err != nil {
		t.Fatalf("expected the request after the backoff to succeed, got %v", err)
	}
	if server.requests != 2 {
		t.Fatalf("expected a request after the backoff, got %d", server.requests)
	}
}

func TestUpgradeRequiredPausesRequests(t *testing.T) {
	server := newBackoffTestServer(t)
	server.status = http.StatusUpgradeRequired

	_ = server.heartbeat()
	assertBackingOff(t, server.heartbeat())
}

func TestRetryAfterPausesRequestsUntilItPasses(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		server := newBackoffTestServer(t)
		server.status = status
		server.header = http.Header{"Retry-After": []string{"120"}}

		_ = server.heartbeat()
		server.now = server.now.Add(119 * time.Second)
		assertBackingOff(t, server.heartbeat())

		server.now = server.now.Add(time.Second)
		server.status = http.StatusOK
		if err := server.heartbeat(); err != nil {
			t.Fatalf("%d: expected the request after Retry-After to succeed, got %v", status, err)
		}
		if err := server.heartbeat(); err != nil {
			t.Fatalf("%d: expected a success to end the backoff, got %v", status, err)
		}
		if server.requests != 3 {
			t.Fatalf("%d: expected three requests, got %d", status, server.requests)
		}
	}
}

func TestRetryAfterIsCappedAtAnHour(t *testing.T) {
	server := newBackoffTestServer(t)
	server.status = http.StatusTooManyRequests
	server.header = http.Header{"Retry-After": []string{"86400"}}

	_ = server.heartbeat()
	server.now = server.now.Add(maximumBackoff)
	server.status = http.StatusOK
	if err := server.heartbeat(); err != nil {
		t.Fatalf("expected the backoff to end after an hour, got %v", err)
	}
}

func TestServiceUnavailableWithoutRetryAfterDoesNotPause(t *testing.T) {
	server := newBackoffTestServer(t)
	server.status = http.StatusServiceUnavailable

	_ = server.heartbeat()
	_ = server.heartbeat()
	if server.requests != 2 {
		t.Fatalf("expected both requests to be sent, got %d", server.requests)
	}
}

func TestNewHostKeyEndsBackoff(t *testing.T) {
	server := newBackoffTestServer(t)
	server.status = http.StatusUnauthorized
	_ = server.heartbeat()

	server.client.SetIdentity("fgsvr_synthetic", "flowguard-test-reloaded")
	assertBackingOff(t, server.heartbeat())

	server.client.SetIdentity("fgsvr_synthetic_new", "flowguard-test-reloaded")
	server.status = http.StatusOK
	if err := server.heartbeat(); err != nil {
		t.Fatalf("expected a new host key to be tried right away, got %v", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		value string
		want  time.Duration
		ok    bool
	}{
		{"30", 30 * time.Second, true},
		{"0", 0, true},
		{"-1", 0, false},
		{"", 0, false},
		{"soon", 0, false},
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second, true},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0, true},
	}
	for _, tc := range cases {
		got, ok := parseRetryAfter(tc.value, now)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseRetryAfter(%q) = %s, %v; want %s, %v", tc.value, got, ok, tc.want, tc.ok)
		}
	}
}
