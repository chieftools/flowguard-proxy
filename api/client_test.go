package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestSendHeartbeatIncludesFirewallPayload(t *testing.T) {
	tests := []FirewallHeartbeat{
		{Status: "healthy", LastCheckedAt: 100},
		{Status: "degraded", LastCheckedAt: 101, LastRepairedAt: 99, MissingRuleCount: 2, LastError: "repair failed"},
		{Status: "disabled"},
	}

	for _, firewall := range tests {
		t.Run(firewall.Status, func(t *testing.T) {
			var received HeartbeatPayload

			client := NewClient("host-key", "flowguard-test")
			client.baseURL = "https://flowguard.test"
			client.httpClient = &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.Method != http.MethodPost {
						t.Fatalf("unexpected method: %s", r.Method)
					}
					if r.URL.Path != "/api/v1/heartbeat" {
						t.Fatalf("unexpected path: %s", r.URL.Path)
					}

					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Fatalf("read request body: %v", err)
					}
					if err := json.Unmarshal(body, &received); err != nil {
						t.Fatalf("decode heartbeat: %v", err)
					}

					return &http.Response{
						StatusCode: http.StatusNoContent,
						Body:       io.NopCloser(bytes.NewReader(nil)),
						Header:     make(http.Header),
					}, nil
				}),
			}

			payload := HeartbeatPayload{
				OS:            "linux",
				Arch:          "amd64",
				Version:       "1.2.3",
				StartedAt:     123,
				HostnameCount: 2,
				BindAddresses: []string{"203.0.113.10"},
				Firewall:      firewall,
			}

			if err := client.SendHeartbeat(payload); err != nil {
				t.Fatalf("SendHeartbeat: %v", err)
			}

			if received.Firewall != firewall {
				t.Fatalf("expected firewall payload %#v, got %#v", firewall, received.Firewall)
			}
			if len(received.BindAddresses) != 1 || received.BindAddresses[0] != "203.0.113.10" {
				t.Fatalf("unexpected bind addresses: %#v", received.BindAddresses)
			}
		})
	}
}
