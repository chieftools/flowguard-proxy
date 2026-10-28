package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type channelAuthRequest struct {
	url           string
	authorization string
	socketID      string
	channel       string
}

func newChannelAuthClient(t *testing.T, status int, body string) (*Client, *[]channelAuthRequest) {
	t.Helper()

	var requests []channelAuthRequest
	client := NewClient("fgsvr_synthetic", "flowguard-test")
	client.baseURL = "https://flowguard.test"
	client.httpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse form: %v", err)
			}
			requests = append(requests, channelAuthRequest{
				url:           r.URL.String(),
				authorization: r.Header.Get("Authorization"),
				socketID:      r.PostForm.Get("socket_id"),
				channel:       r.PostForm.Get("channel_name"),
			})
			return &http.Response{
				StatusCode: status,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		}),
	}
	return client, &requests
}

func TestAuthorizeChannelUsesAuthURLOnControlPanel(t *testing.T) {
	client, requests := newChannelAuthClient(t, http.StatusOK, `{"auth":"key:signature"}`)

	auth, err := client.AuthorizeChannel("https://flowguard.test/proxy/v1/broadcasting/auth", "1.2", "private-server.1")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if auth != "key:signature" {
		t.Fatalf("auth = %q, want key:signature", auth)
	}

	want := channelAuthRequest{
		url:           "https://flowguard.test/proxy/v1/broadcasting/auth",
		authorization: "Bearer fgsvr_synthetic",
		socketID:      "1.2",
		channel:       "private-server.1",
	}
	if len(*requests) != 1 || (*requests)[0] != want {
		t.Fatalf("requests = %+v, want %+v", *requests, want)
	}
}

func TestAuthorizeChannelOnlySendsHostKeyToControlPanel(t *testing.T) {
	for _, authURL := range []string{
		"",
		"https://realtime.example/auth",
		"http://flowguard.test/proxy/v1/broadcasting/auth",
		"https://flowguard.test:8443/proxy/v1/broadcasting/auth",
		"https://user@flowguard.test/proxy/v1/broadcasting/auth",
		"://invalid",
	} {
		client, requests := newChannelAuthClient(t, http.StatusOK, `{"auth":"key:signature"}`)

		if _, err := client.AuthorizeChannel(authURL, "1.2", "private-server.1"); err != nil {
			t.Fatalf("authorize with %q: %v", authURL, err)
		}
		if len(*requests) != 1 || (*requests)[0].url != "https://flowguard.test/proxy/v1/broadcasting/auth" {
			t.Fatalf("auth URL %q sent requests %+v, want only the control panel endpoint", authURL, *requests)
		}
	}
}

func TestAuthorizeChannelRejectsMissingSignature(t *testing.T) {
	client, _ := newChannelAuthClient(t, http.StatusOK, `{}`)

	if _, err := client.AuthorizeChannel("", "1.2", "private-server.1"); err == nil {
		t.Fatal("expected an error for an answer without a signature")
	}
}

func TestAuthorizeChannelPausesWithOtherRequests(t *testing.T) {
	client, requests := newChannelAuthClient(t, http.StatusUnauthorized, `{}`)

	if _, err := client.AuthorizeChannel("", "1.2", "private-server.1"); err == nil {
		t.Fatal("expected the rejected host key to fail")
	}
	_, err := client.AuthorizeChannel("", "1.2", "private-server.1")
	assertBackingOff(t, err)
	if len(*requests) != 1 {
		t.Fatalf("expected one request before the pause, got %d", len(*requests))
	}
}
