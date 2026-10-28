package pusher

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type realtimeTestServer struct {
	server          *httptest.Server
	sendEstablished bool
	options         realtimeTestServerOptions
	dials           atomic.Int32
	accepts         atomic.Int32
	subscribes      atomic.Int32
	closeCodes      chan int
	userAgents      chan string
}

type realtimeTestServerOptions struct {
	// rejectDials fails this many websocket handshakes before accepting.
	rejectDials int32
	// activityTimeout is sent in connection_established, in seconds.
	activityTimeout int
	// subscribeReply returns the reply to a pusher:subscribe on the given
	// accepted connection, or nil to not reply.
	subscribeReply func(accept int32, channel string) *Message
	// dropFirstConnection closes the first accepted connection after
	// replying to its subscribe.
	dropFirstConnection bool
}

type pusherRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn pusherRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func newRealtimeTestServer(t *testing.T, sendEstablished bool) *realtimeTestServer {
	t.Helper()

	return newRealtimeTestServerWithOptions(t, sendEstablished, realtimeTestServerOptions{})
}

func newRealtimeTestServerWithOptions(t *testing.T, sendEstablished bool, options realtimeTestServerOptions) *realtimeTestServer {
	t.Helper()

	if options.activityTimeout == 0 {
		options.activityTimeout = 60
	}

	rts := &realtimeTestServer{
		sendEstablished: sendEstablished,
		options:         options,
		closeCodes:      make(chan int, 10),
		userAgents:      make(chan string, 10),
	}

	upgrader := websocket.Upgrader{}
	rts.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rts.dials.Add(1) <= rts.options.rejectDials {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("failed to upgrade websocket: %v", err)
			return
		}
		defer conn.Close()

		select {
		case rts.userAgents <- r.UserAgent():
		default:
		}

		acceptNumber := rts.accepts.Add(1)

		if rts.sendEstablished {
			if err := conn.WriteJSON(connectionEstablishedMessageWithTimeout(fmt.Sprintf("%d.1", acceptNumber), rts.options.activityTimeout)); err != nil {
				t.Errorf("failed to write connection established message: %v", err)
				return
			}
		}

		for {
			var msg Message
			if err := conn.ReadJSON(&msg); err != nil {
				var closeErr *websocket.CloseError
				if errors.As(err, &closeErr) {
					rts.closeCodes <- closeErr.Code
				} else {
					rts.closeCodes <- -1
				}
				return
			}

			if msg.Event != "pusher:subscribe" {
				continue
			}
			rts.subscribes.Add(1)
			if rts.options.subscribeReply == nil {
				continue
			}

			var data struct {
				Channel string `json:"channel"`
			}
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				t.Errorf("failed to decode subscribe message: %v", err)
				return
			}
			if reply := rts.options.subscribeReply(acceptNumber, data.Channel); reply != nil {
				if err := conn.WriteJSON(reply); err != nil {
					return
				}
			}
			if acceptNumber == 1 && rts.options.dropFirstConnection {
				return
			}
		}
	}))

	t.Cleanup(func() {
		rts.server.CloseClientConnections()
		rts.server.Close()
	})

	return rts
}

func (s *realtimeTestServer) config(t *testing.T, channel string) *Config {
	t.Helper()

	serverURL, err := url.Parse(s.server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	host, portValue, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatalf("failed to split server host and port: %v", err)
	}

	port, err := strconv.Atoi(portValue)
	if err != nil {
		t.Fatalf("failed to parse server port: %v", err)
	}

	return &Config{
		Key:     "app-key",
		Host:    host,
		Port:    port,
		Channel: channel,
	}
}

func connectionEstablishedMessage(socketID string) Message {
	return connectionEstablishedMessageWithTimeout(socketID, 60)
}

func connectionEstablishedMessageWithTimeout(socketID string, activityTimeout int) Message {
	data, _ := json.Marshal(fmt.Sprintf(`{"socket_id":"%s","activity_timeout":%d}`, socketID, activityTimeout))
	return Message{
		Event: "pusher:connection_established",
		Data:  data,
	}
}

func subscriptionSucceeded(channel string) *Message {
	return &Message{Event: "pusher_internal:subscription_succeeded", Channel: channel, Data: json.RawMessage(`"{}"`)}
}

// newFastClient returns a client with timeouts short enough for tests.
func newFastClient(cfg *Config) *Client {
	client := NewClient(cfg, "flowguard-test", "host-key", false)
	client.reconnectBaseDelay = 20 * time.Millisecond
	client.reconnectMaxDelay = 50 * time.Millisecond
	client.subscriptionTimeout = 200 * time.Millisecond
	client.pongTimeout = 100 * time.Millisecond
	return client
}

func newAuthServer(t *testing.T, failures int32) (*httptest.Server, *atomic.Int32) {
	t.Helper()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) <= failures {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `{"auth":"app-key:signature"}`)
	}))
	t.Cleanup(server.Close)

	return server, &requests
}

func waitForSubscribed(t *testing.T, client *Client) {
	t.Helper()

	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		if client.IsSubscribed() {
			return
		}

		select {
		case <-deadline:
			t.Fatalf("timed out waiting for client to be subscribed")
		case <-ticker.C:
		}
	}
}

func TestStartRetriesFailedInitialConnect(t *testing.T) {
	server := newRealtimeTestServerWithOptions(t, true, realtimeTestServerOptions{
		rejectDials: 2,
		subscribeReply: func(_ int32, channel string) *Message {
			return subscriptionSucceeded(channel)
		},
	})
	client := newFastClient(server.config(t, "public-test"))
	t.Cleanup(client.Disconnect)

	client.Start()

	waitForSubscribed(t, client)
	if got := server.dials.Load(); got != 3 {
		t.Fatalf("expected two rejected dials and one accepted dial, got %d dials", got)
	}
}

func TestFailedChannelAuthReconnects(t *testing.T) {
	authServer, authRequests := newAuthServer(t, 1)
	server := newRealtimeTestServerWithOptions(t, true, realtimeTestServerOptions{
		subscribeReply: func(_ int32, channel string) *Message {
			return subscriptionSucceeded(channel)
		},
	})
	cfg := server.config(t, "private-test")
	cfg.AuthURL = authServer.URL
	client := newFastClient(cfg)
	t.Cleanup(client.Disconnect)

	client.Start()

	if code := waitForCloseCode(t, server); code != websocket.ClosePolicyViolation {
		t.Fatalf("expected the unsubscribed connection to close with code %d, got %d", websocket.ClosePolicyViolation, code)
	}
	waitForSubscribed(t, client)
	if got := authRequests.Load(); got != 2 {
		t.Fatalf("expected one failed and one successful auth request, got %d", got)
	}
	if got := server.accepts.Load(); got != 2 {
		t.Fatalf("expected a second connection after the failed auth, got %d", got)
	}
}

func TestSubscriptionErrorReconnects(t *testing.T) {
	server := newRealtimeTestServerWithOptions(t, true, realtimeTestServerOptions{
		subscribeReply: func(accept int32, channel string) *Message {
			if accept == 1 {
				return &Message{Event: "pusher:subscription_error", Channel: channel, Data: json.RawMessage(`"{\"status\":403}"`)}
			}
			return subscriptionSucceeded(channel)
		},
	})
	client := newFastClient(server.config(t, "public-test"))
	t.Cleanup(client.Disconnect)

	client.Start()

	if code := waitForCloseCode(t, server); code != websocket.ClosePolicyViolation {
		t.Fatalf("expected the rejected connection to close with code %d, got %d", websocket.ClosePolicyViolation, code)
	}
	waitForSubscribed(t, client)
}

func TestUnconfirmedSubscriptionReconnects(t *testing.T) {
	server := newRealtimeTestServerWithOptions(t, true, realtimeTestServerOptions{
		subscribeReply: func(accept int32, channel string) *Message {
			if accept == 1 {
				return nil
			}
			return subscriptionSucceeded(channel)
		},
	})
	client := newFastClient(server.config(t, "public-test"))
	t.Cleanup(client.Disconnect)

	client.Start()

	waitForSubscribed(t, client)
	if got := server.accepts.Load(); got != 2 {
		t.Fatalf("expected a second connection after the unconfirmed subscription, got %d", got)
	}
}

func TestSilentConnectionReconnects(t *testing.T) {
	// The test server never answers pings, so the read deadline of the
	// activity timeout plus the pong timeout expires.
	server := newRealtimeTestServerWithOptions(t, true, realtimeTestServerOptions{
		activityTimeout: 1,
		subscribeReply: func(_ int32, channel string) *Message {
			return subscriptionSucceeded(channel)
		},
	})
	client := newFastClient(server.config(t, "public-test"))
	t.Cleanup(client.Disconnect)

	client.Start()

	waitForAccepts(t, server, 2)
}

func TestOnSubscribedRunsAfterEachSubscription(t *testing.T) {
	server := newRealtimeTestServerWithOptions(t, true, realtimeTestServerOptions{
		subscribeReply: func(_ int32, channel string) *Message {
			return subscriptionSucceeded(channel)
		},
		dropFirstConnection: true,
	})
	client := newFastClient(server.config(t, "public-test"))
	t.Cleanup(client.Disconnect)

	subscribed := make(chan struct{}, 10)
	client.OnSubscribed(func() { subscribed <- struct{}{} })

	client.Start()
	waitForSubscription := func() {
		t.Helper()
		select {
		case <-subscribed:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for the subscribed handler")
		}
	}
	waitForSubscription()
	waitForSubscription()
	if got := server.accepts.Load(); got != 2 {
		t.Fatalf("expected the handler to run once per connection, got %d connections", got)
	}
}

func TestSubscriptionToOtherChannelIsIgnored(t *testing.T) {
	server := newRealtimeTestServerWithOptions(t, true, realtimeTestServerOptions{
		subscribeReply: func(_ int32, _ string) *Message {
			return subscriptionSucceeded("public-other")
		},
	})
	client := newFastClient(server.config(t, "public-test"))
	client.subscriptionTimeout = time.Minute
	t.Cleanup(client.Disconnect)

	client.Start()
	waitForConnected(t, client)

	deadline := time.Now().Add(2 * time.Second)
	for server.subscribes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if client.IsSubscribed() {
		t.Fatal("expected a subscription confirmation for another channel to be ignored")
	}
}

func TestReconnectDelayBacksOffUntilSubscribed(t *testing.T) {
	client := NewClient(&Config{}, "flowguard-test", "host-key", false)

	for attempts, ceiling := range []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second} {
		client.reconnectAttempts = attempts
		for range 100 {
			if delay := client.reconnectDelayLocked(); delay < ceiling/2 || delay > ceiling {
				t.Fatalf("attempt %d: delay %s outside [%s, %s]", attempts, delay, ceiling/2, ceiling)
			}
		}
	}

	client.reconnectAttempts = 1000
	if delay := client.reconnectDelayLocked(); delay < defaultReconnectMaxDelay/2 || delay > defaultReconnectMaxDelay {
		t.Fatalf("expected capped delay, got %s", delay)
	}
}

func TestGenerateChannelAuthReusesHTTPClient(t *testing.T) {
	client := NewClient(&Config{}, "flowguard-test", "host-key", false)
	var requests atomic.Int32
	sharedClient := &http.Client{
		Transport: pusherRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests.Add(1)
			if req.UserAgent() != "FlowGuard/99.0.0 server/synthetic-a" {
				t.Errorf("unexpected user agent: %q", req.UserAgent())
			}
			if got := req.Header.Get("Authorization"); got != "Bearer host-key" {
				t.Fatalf("unexpected authorization header: %q", got)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"auth":"signed-token"}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	client.httpClient = sharedClient

	for range 2 {
		auth, err := client.generateChannelAuth("socket-42", "private-events", "https://flowguard.test/auth", "host-key", "FlowGuard/99.0.0 server/synthetic-a")
		if err != nil {
			t.Fatalf("generate channel auth: %v", err)
		}
		if auth != "signed-token" {
			t.Fatalf("unexpected auth token: %q", auth)
		}
	}

	if client.httpClient != sharedClient {
		t.Fatal("expected the shared HTTP client to remain configured")
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("expected two requests through the shared client, got %d", got)
	}
}

func TestConnectDoesNotCreateSecondSocketBeforePusherEstablished(t *testing.T) {
	server := newRealtimeTestServer(t, false)
	client := NewClient(server.config(t, "private-test"), "flowguard-test", "host-key", false)
	t.Cleanup(client.Disconnect)

	if err := client.Connect(); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	waitForAccepts(t, server, 1)

	if client.IsConnected() {
		t.Fatalf("expected pusher connection to remain unestablished until server sends connection_established")
	}

	if err := client.Connect(); err != nil {
		t.Fatalf("second connect failed: %v", err)
	}

	time.Sleep(150 * time.Millisecond)
	if got := server.accepts.Load(); got != 1 {
		t.Fatalf("expected one websocket connection, got %d", got)
	}
}

func TestDisconnectSendsNormalCloseFrame(t *testing.T) {
	server := newRealtimeTestServer(t, true)
	client := NewClient(server.config(t, "public-test"), "flowguard-test", "host-key", false)
	t.Cleanup(client.Disconnect)

	if err := client.Connect(); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	waitForConnected(t, client)

	client.Disconnect()

	if code := waitForCloseCode(t, server); code != websocket.CloseNormalClosure {
		t.Fatalf("expected normal close code %d, got %d", websocket.CloseNormalClosure, code)
	}
}

func TestUpdateConfigReplacesConnectionWithNormalClose(t *testing.T) {
	firstServer := newRealtimeTestServer(t, true)
	secondServer := newRealtimeTestServer(t, true)
	client := NewClient(firstServer.config(t, "public-first"), "flowguard-test", "host-key", false)
	t.Cleanup(client.Disconnect)

	if err := client.Connect(); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	waitForConnected(t, client)

	if err := client.UpdateConfig(secondServer.config(t, "public-second"), "flowguard-test", "host-key"); err != nil {
		t.Fatalf("update config failed: %v", err)
	}

	if code := waitForCloseCode(t, firstServer); code != websocket.CloseNormalClosure {
		t.Fatalf("expected replaced connection to close normally with code %d, got %d", websocket.CloseNormalClosure, code)
	}

	waitForAccepts(t, secondServer, 1)
	waitForConnected(t, client)
}

func waitForAccepts(t *testing.T, server *realtimeTestServer, want int32) {
	t.Helper()

	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		if got := server.accepts.Load(); got >= want {
			return
		}

		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %d accepts, got %d", want, server.accepts.Load())
		case <-ticker.C:
		}
	}
}

func waitForConnected(t *testing.T, client *Client) {
	t.Helper()

	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		if client.IsConnected() {
			return
		}

		select {
		case <-deadline:
			t.Fatalf("timed out waiting for client to be connected")
		case <-ticker.C:
		}
	}
}

func waitForCloseCode(t *testing.T, server *realtimeTestServer) int {
	t.Helper()

	select {
	case code := <-server.closeCodes:
		return code
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for close code")
		return -1
	}
}

func TestUpdateConfigReconnectsWithChangedIdentity(t *testing.T) {
	server := newRealtimeTestServer(t, true)
	configuration := server.config(t, "public-test")
	client := NewClient(configuration, "FlowGuard/99.0.0 server/synthetic-a", "key-a", false)
	t.Cleanup(client.Disconnect)

	if err := client.Connect(); err != nil {
		t.Fatal(err)
	}
	waitForConnected(t, client)
	if got := <-server.userAgents; got != "FlowGuard/99.0.0 server/synthetic-a" {
		t.Fatalf("initial user agent: %q", got)
	}

	if err := client.UpdateConfig(configuration, "FlowGuard/99.0.0 server/synthetic-b", "key-b"); err != nil {
		t.Fatal(err)
	}
	waitForAccepts(t, server, 2)
	waitForConnected(t, client)
	if got := <-server.userAgents; got != "FlowGuard/99.0.0 server/synthetic-b" {
		t.Fatalf("reloaded user agent: %q", got)
	}
}
