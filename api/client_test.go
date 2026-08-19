package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type trackingResponseBody struct {
	reads  int
	closes int
}

func (b *trackingResponseBody) Read([]byte) (int, error) {
	b.reads++
	return 0, io.EOF
}

func (b *trackingResponseBody) Close() error {
	b.closes++
	return nil
}

func TestPatchConfigPathsSendsNestedHostPayload(t *testing.T) {
	var received struct {
		Host struct {
			CertPath        string `json:"cert_path,omitempty"`
			NginxConfigPath string `json:"nginx_config_path,omitempty"`
		} `json:"host"`
	}

	client := NewClient("host-key", "flowguard-test")
	client.baseURL = "https://flowguard.test"
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPatch {
				t.Fatalf("unexpected method: %s", r.Method)
			}
			if r.URL.Path != "/api/v1/config" {
				t.Fatalf("unexpected path: %s", r.URL.Path)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer host-key" {
				t.Fatalf("unexpected authorization header: %s", got)
			}
			if got := r.Header.Get("User-Agent"); got != "flowguard-test" {
				t.Fatalf("unexpected user-agent header: %s", got)
			}
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Fatalf("unexpected content-type header: %s", got)
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			if err := json.Unmarshal(body, &received); err != nil {
				t.Fatalf("decode patch payload: %v", err)
			}

			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(bytes.NewReader(nil)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	err := client.PatchConfigPaths("/opt/psa/var/certificates", "/etc/nginx/nginx.conf")
	if err != nil {
		t.Fatalf("PatchConfigPaths: %v", err)
	}

	if received.Host.CertPath != "/opt/psa/var/certificates" {
		t.Fatalf("unexpected cert path: %s", received.Host.CertPath)
	}
	if received.Host.NginxConfigPath != "/etc/nginx/nginx.conf" {
		t.Fatalf("unexpected nginx config path: %s", received.Host.NginxConfigPath)
	}
}

func TestPatchConfigPathsOmitsEmptyFields(t *testing.T) {
	var received map[string]map[string]string

	client := NewClient("host-key", "flowguard-test")
	client.baseURL = "https://flowguard.test"
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			if err := json.Unmarshal(body, &received); err != nil {
				t.Fatalf("decode patch payload: %v", err)
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(nil)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	err := client.PatchConfigPaths("/certs", "")
	if err != nil {
		t.Fatalf("PatchConfigPaths: %v", err)
	}

	if received["host"]["cert_path"] != "/certs" {
		t.Fatalf("unexpected cert path: %#v", received)
	}
	if _, exists := received["host"]["nginx_config_path"]; exists {
		t.Fatalf("expected nginx_config_path to be omitted: %#v", received)
	}
}

func TestPatchConfigPathsRejectsEmptyPayload(t *testing.T) {
	client := NewClient("host-key", "flowguard-test")

	err := client.PatchConfigPaths("", "")
	if err == nil {
		t.Fatal("expected empty payload to be rejected")
	}
	if !strings.Contains(err.Error(), "at least one configuration path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPatchConfigPathsReturnsAPIError(t *testing.T) {
	client := NewClient("host-key", "flowguard-test")
	client.baseURL = "https://flowguard.test"
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUnprocessableEntity,
				Body:       io.NopCloser(strings.NewReader(`{"message":"invalid path"}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	err := client.PatchConfigPaths("/missing", "")
	if err == nil {
		t.Fatal("expected API error")
	}
	if !strings.Contains(err.Error(), "invalid path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPatchConfigSendsSetupConfiguration(t *testing.T) {
	var received map[string]any

	client := NewClient("host-key", "flowguard-test")
	client.baseURL = "https://flowguard.test"
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			if err := json.Unmarshal(body, &received); err != nil {
				t.Fatalf("decode patch payload: %v", err)
			}

			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(bytes.NewReader(nil)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	advertiseHTTP3 := false
	err := client.PatchConfig(ConfigPatch{
		Host: &HostConfigPatch{
			ACMEPath:        "/etc/traefik/acme.json",
			NginxConfigPath: "/etc/nginx/nginx.conf",
		},
		Server: &ServerConfigPatch{
			Protocols:      &ProtocolsConfigPatch{HTTP1: true, HTTP2: true, HTTP3: true},
			AdvertiseHTTP3: &advertiseHTTP3,
			Upstream: &UpstreamConfigPatch{
				ClientIPMode: "transparent",
				Transparent: &TransparentUpstreamConfigPatch{
					AddressPairs: []AddressPairConfigPatch{{IPv4: "192.0.2.10", IPv6: "2001:db8::10"}},
				},
			},
		},
		Fail2Ban: &Fail2BanConfigPatch{Enabled: true},
	})
	if err != nil {
		t.Fatalf("PatchConfig: %v", err)
	}

	host := received["host"].(map[string]any)
	if host["nginx_config_path"] != "/etc/nginx/nginx.conf" {
		t.Fatalf("unexpected host payload: %#v", host)
	}
	if host["acme_path"] != "/etc/traefik/acme.json" {
		t.Fatalf("unexpected host payload: %#v", host)
	}
	server := received["server"].(map[string]any)
	protocols := server["protocols"].(map[string]any)
	if protocols["http1"] != true || protocols["http2"] != true || protocols["http3"] != true {
		t.Fatalf("unexpected protocol payload: %#v", protocols)
	}
	if server["advertise_http3"] != false {
		t.Fatalf("unexpected advertise_http3 payload: %#v", server)
	}
	upstream := server["upstream"].(map[string]any)
	if upstream["client_ip_mode"] != "transparent" {
		t.Fatalf("unexpected upstream payload: %#v", upstream)
	}
	transparent := upstream["transparent"].(map[string]any)
	pairs := transparent["address_pairs"].([]any)
	if len(pairs) != 1 {
		t.Fatalf("unexpected address pairs: %#v", pairs)
	}
	fail2banConfig := received["fail2ban"].(map[string]any)
	if fail2banConfig["enabled"] != true {
		t.Fatalf("unexpected Fail2Ban payload: %#v", fail2banConfig)
	}
}

func TestPatchConfigAcceptsFail2BanOnlyPayload(t *testing.T) {
	var received map[string]any
	client := NewClient("host-key", "flowguard-test")
	client.baseURL = "https://flowguard.test"
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			if err := json.Unmarshal(body, &received); err != nil {
				t.Fatalf("decode patch payload: %v", err)
			}
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
		}),
	}

	if err := client.PatchConfig(ConfigPatch{Fail2Ban: &Fail2BanConfigPatch{Enabled: false}}); err != nil {
		t.Fatalf("PatchConfig: %v", err)
	}
	if len(received) != 1 {
		t.Fatalf("unexpected payload: %#v", received)
	}
	fail2banConfig, ok := received["fail2ban"].(map[string]any)
	if !ok || fail2banConfig["enabled"] != false {
		t.Fatalf("unexpected Fail2Ban payload: %#v", received)
	}
}

func TestPatchConfigRejectsEmptyPayload(t *testing.T) {
	client := NewClient("host-key", "flowguard-test")
	if err := client.PatchConfig(ConfigPatch{}); err == nil || !strings.Contains(err.Error(), "at least one configuration field") {
		t.Fatalf("unexpected empty-payload error: %v", err)
	}
}

func TestPatchConfigSendsEmptyTransparentAddressPairs(t *testing.T) {
	var received struct {
		Server struct {
			Upstream struct {
				Transparent struct {
					AddressPairs []AddressPairConfigPatch `json:"address_pairs"`
				} `json:"transparent"`
			} `json:"upstream"`
		} `json:"server"`
	}

	client := NewClient("host-key", "flowguard-test")
	client.baseURL = "https://flowguard.test"
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			if err := json.Unmarshal(body, &received); err != nil {
				t.Fatalf("decode patch payload: %v", err)
			}
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
		}),
	}

	err := client.PatchConfig(ConfigPatch{
		Server: &ServerConfigPatch{
			Upstream: &UpstreamConfigPatch{
				ClientIPMode: "transparent",
				Transparent:  &TransparentUpstreamConfigPatch{AddressPairs: []AddressPairConfigPatch{}},
			},
		},
	})
	if err != nil {
		t.Fatalf("PatchConfig: %v", err)
	}
	if received.Server.Upstream.Transparent.AddressPairs == nil {
		t.Fatal("expected address_pairs to be present as an empty array")
	}
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

func TestSendHeartbeatClosesResponseWithoutExplicitDrain(t *testing.T) {
	body := &trackingResponseBody{}
	client := NewClient("host-key", "flowguard-test")
	client.baseURL = "https://flowguard.test"
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       body,
				Header:     make(http.Header),
			}, nil
		}),
	}

	if err := client.SendHeartbeat(HeartbeatPayload{}); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	if body.reads != 0 {
		t.Fatalf("expected no explicit response drain, got %d reads", body.reads)
	}
	if body.closes != 1 {
		t.Fatalf("expected response body to close once, got %d", body.closes)
	}
}
