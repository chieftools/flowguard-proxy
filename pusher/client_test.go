package pusher

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type realtimeTestServer struct {
	server          *httptest.Server
	sendEstablished bool
	accepts         atomic.Int32
	closeCodes      chan int
}

func newRealtimeTestServer(t *testing.T, sendEstablished bool) *realtimeTestServer {
	t.Helper()

	rts := &realtimeTestServer{
		sendEstablished: sendEstablished,
		closeCodes:      make(chan int, 10),
	}

	upgrader := websocket.Upgrader{}
	rts.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("failed to upgrade websocket: %v", err)
			return
		}
		defer conn.Close()

		acceptNumber := rts.accepts.Add(1)

		if rts.sendEstablished {
			if err := conn.WriteJSON(connectionEstablishedMessage(fmt.Sprintf("%d.1", acceptNumber))); err != nil {
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
	data, _ := json.Marshal(fmt.Sprintf(`{"socket_id":"%s","activity_timeout":60}`, socketID))
	return Message{
		Event: "pusher:connection_established",
		Data:  data,
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

	if err := client.UpdateConfig(secondServer.config(t, "public-second")); err != nil {
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
