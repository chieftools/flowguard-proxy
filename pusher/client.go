package pusher

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	websocketHandshakeTimeout = 10 * time.Second
	websocketWriteTimeout     = 10 * time.Second
	websocketCloseTimeout     = 2 * time.Second
)

// Config represents Realtime WebSocket configuration
type Config struct {
	Key       string `json:"key"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Channel   string `json:"channel"`
	AuthURL   string `json:"auth_url"`
	Encrypted bool   `json:"encrypted,omitempty"` // Use WSS instead of WS
}

// Message represents a Pusher protocol message
type Message struct {
	Event   string          `json:"event"`
	Data    json.RawMessage `json:"data"`
	Channel string          `json:"channel,omitempty"`
}

// UnmarshalData decodes the message data into the provided value.
// Pusher sends data as a JSON-encoded string, so this unmarshals twice:
// first to get the inner JSON string, then to parse the actual object.
func (m Message) UnmarshalData(v interface{}) error {
	var dataStr string
	if err := json.Unmarshal(m.Data, &dataStr); err != nil {
		return fmt.Errorf("failed to unmarshal data string: %w", err)
	}
	if err := json.Unmarshal([]byte(dataStr), v); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}
	return nil
}

// MessageHandler defines the callback function for handling Realtime events
type MessageHandler func(message Message)

// ConnectionEstablishedMessageData represents the connection established event data
type ConnectionEstablishedMessageData struct {
	SocketID        string `json:"socket_id"`
	ActivityTimeout int    `json:"activity_timeout"`
	SocketChiefColo string `json:"socketchief_colo,omitempty"`
}

// Client manages Realtime WebSocket connections
type Client struct {
	config         *Config
	hostKey        string
	userAgent      string
	verbose        bool
	conn           *websocket.Conn
	socketID       string
	isConnected    bool
	isConnecting   bool
	connectCancel  context.CancelFunc
	generation     uint64
	reconnectTimer *time.Timer
	stopChan       chan struct{}
	eventHandlers  map[string]MessageHandler
	mu             sync.RWMutex
	writeMu        sync.Mutex
	pingTicker     *time.Ticker
	pingStop       chan struct{}
}

// NewClient creates a new Realtime client
func NewClient(cfg *Config, userAgent, hostKey string, verbose bool) *Client {
	if cfg == nil || hostKey == "" {
		return nil
	}

	return &Client{
		config:        cfg,
		hostKey:       hostKey,
		userAgent:     userAgent,
		verbose:       verbose,
		stopChan:      make(chan struct{}),
		eventHandlers: make(map[string]MessageHandler),
	}
}

// Connect establishes a connection to Realtime
func (c *Client) Connect() error {
	c.mu.Lock()

	if c.isStoppedLocked() {
		c.mu.Unlock()
		return fmt.Errorf("realtime client is disconnected")
	}

	if c.config == nil {
		c.mu.Unlock()
		return fmt.Errorf("realtime configuration is missing")
	}

	if c.conn != nil || c.isConnecting {
		c.mu.Unlock()
		return nil
	}

	config := *c.config
	userAgent := c.userAgent
	generation := c.generation
	ctx, cancel := context.WithTimeout(context.Background(), websocketHandshakeTimeout)
	c.isConnecting = true
	c.connectCancel = cancel
	c.mu.Unlock()
	defer cancel()

	// Build WebSocket URL
	wsURL := buildWebSocketURLFromConfig(&config)

	// Set up WebSocket dialer
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = websocketHandshakeTimeout

	// Connect to WebSocket
	conn, _, err := dialer.DialContext(ctx, wsURL, map[string][]string{
		"User-Agent": {userAgent},
	})

	c.mu.Lock()
	activeAttempt := c.generation == generation
	if activeAttempt {
		c.isConnecting = false
		c.connectCancel = nil
	}
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	if !activeAttempt || c.isStoppedLocked() || c.config == nil || !sameConfig(c.config, &config) || c.conn != nil {
		c.mu.Unlock()
		c.closeWebSocket(conn, websocket.CloseNormalClosure, "connection superseded")
		return nil
	}

	c.conn = conn
	c.socketID = ""
	c.isConnected = false
	if c.reconnectTimer != nil {
		c.reconnectTimer.Stop()
		c.reconnectTimer = nil
	}
	c.mu.Unlock()

	log.Printf("[realtime] Connected to %s", config.Host)

	// Start message handling
	go c.handleMessages(conn)

	return nil
}

// IsConnected returns the current connection status
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isConnected
}

// UpdateConfig updates the Realtime configuration and reconnects if necessary
func (c *Client) UpdateConfig(newConfig *Config) error {
	c.mu.Lock()

	// If no config provided, disconnect
	if newConfig == nil {
		c.mu.Unlock()
		c.disconnect("configuration removed")
		return nil
	}

	if c.isStoppedLocked() {
		c.mu.Unlock()
		return fmt.Errorf("realtime client is disconnected")
	}

	// Check if config has changed
	configChanged := c.config == nil ||
		c.config.Key != newConfig.Key ||
		c.config.Host != newConfig.Host ||
		c.config.Port != newConfig.Port ||
		c.config.Channel != newConfig.Channel ||
		c.config.AuthURL != newConfig.AuthURL ||
		c.config.Encrypted != newConfig.Encrypted

	c.config = newConfig

	// If config changed, replace any current connection or in-flight connection attempt.
	var connToClose *websocket.Conn
	var cancelConnect context.CancelFunc
	shouldReconnect := false

	if configChanged {
		log.Printf("[realtime] Configuration changed, reconnecting...")

		c.generation++
		cancelConnect = c.connectCancel
		c.connectCancel = nil
		connToClose = c.conn
		c.conn = nil
		c.socketID = ""
		c.isConnected = false
		c.isConnecting = false
		c.stopPingTickerLocked()

		if c.reconnectTimer != nil {
			c.reconnectTimer.Stop()
			c.reconnectTimer = nil
		}

		shouldReconnect = true
	}

	c.mu.Unlock()

	if cancelConnect != nil {
		cancelConnect()
	}
	if connToClose != nil {
		c.closeWebSocket(connToClose, websocket.CloseNormalClosure, "configuration changed")
	}

	if shouldReconnect {
		go func() {
			if err := c.Connect(); err != nil {
				log.Printf("[realtime] Failed to reconnect with new config: %v", err)
				c.scheduleReconnect()
			}
		}()
	}

	return nil
}

// OnEvent registers an event handler for specific event types
func (c *Client) OnEvent(eventType string, handler MessageHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.eventHandlers[eventType] = handler
}

// Disconnect closes the Realtime connection
func (c *Client) Disconnect() {
	c.disconnect("client disconnecting")
}

func (c *Client) disconnect(reason string) {
	c.mu.Lock()

	// Signal stop to prevent reconnections
	select {
	case <-c.stopChan:
		// Already closed
	default:
		close(c.stopChan)
	}

	c.generation++
	cancelConnect := c.connectCancel
	c.connectCancel = nil
	connToClose := c.conn
	c.conn = nil
	c.socketID = ""

	// Stop ping ticker
	c.stopPingTickerLocked()

	// Stop reconnect timer
	if c.reconnectTimer != nil {
		c.reconnectTimer.Stop()
		c.reconnectTimer = nil
	}

	c.isConnected = false
	c.isConnecting = false
	c.config = nil
	c.mu.Unlock()

	if cancelConnect != nil {
		cancelConnect()
	}
	if connToClose != nil {
		c.closeWebSocket(connToClose, websocket.CloseNormalClosure, reason)
	}

	log.Printf("[realtime] Disconnected")
}

// buildWebSocketURL constructs the WebSocket URL based on configuration
func (c *Client) buildWebSocketURL() string {
	return buildWebSocketURLFromConfig(c.config)
}

func buildWebSocketURLFromConfig(config *Config) string {
	if config == nil {
		return ""
	}

	var host string
	var port int
	var scheme string

	// Use custom host and port
	host = config.Host
	port = config.Port

	if config.Encrypted {
		scheme = "wss"
	} else {
		scheme = "ws"
	}

	return fmt.Sprintf("%s://%s:%d/app/%s?protocol=7&client=flowguard&version=1.0.0", scheme, host, port, config.Key)
}

// handleMessages handles incoming WebSocket messages
func (c *Client) handleMessages(conn *websocket.Conn) {
	defer func() {
		shouldReconnect := false
		wasActive := false

		c.mu.Lock()
		if c.conn == conn {
			wasActive = true
			c.conn = nil
			c.socketID = ""
			c.isConnected = false
			c.stopPingTickerLocked()
			shouldReconnect = !c.isStoppedLocked() && c.config != nil
		}
		c.mu.Unlock()

		if wasActive {
			conn.Close()
		}

		// Schedule reconnect if not stopped
		if shouldReconnect {
			if c.verbose {
				log.Printf("[realtime] Connection lost, scheduling reconnect...")
			}

			c.scheduleReconnect()
		}
	}()

	for {
		select {
		case <-c.stopChan:
			return
		default:
		}

		var msg Message
		err := conn.ReadJSON(&msg)

		if err != nil {
			if c.isConnectionActive(conn) {
				log.Printf("[realtime] Failed to read message: %v", err)
			}
			return
		}

		c.handlePusherMessage(conn, msg)
	}
}

// handlePusherMessage processes individual Realtime protocol messages
func (c *Client) handlePusherMessage(conn *websocket.Conn, msg Message) {
	if !c.isConnectionActive(conn) {
		return
	}

	if c.verbose {
		log.Printf("[realtime] %s => %s", msg.Event, msg.Data)
	}

	switch msg.Event {
	case "pusher:connection_established":
		var data ConnectionEstablishedMessageData
		if err := msg.UnmarshalData(&data); err == nil {
			c.mu.Lock()
			if c.conn != conn || c.isStoppedLocked() {
				c.mu.Unlock()
				return
			}
			c.socketID = data.SocketID
			c.isConnected = true
			c.mu.Unlock()

			if c.verbose {
				log.Printf("[realtime] Connection established, socket ID: %s @ colo: %s", data.SocketID, data.SocketChiefColo)
			}

			// Start ping ticker for keepalive
			c.startPingTicker(conn, data.ActivityTimeout)

			// Subscribe to the configured channel
			go func() {
				if err := c.subscribeToChannel(conn, data.SocketID); err != nil {
					log.Printf("[realtime] Failed to subscribe to channel: %v", err)
				}
			}()
		} else {
			log.Printf("[realtime] Failed to parse connection established data: %v", err)
		}

	case "pusher:ping":
		// Respond to ping with pong
		if err := c.sendMessageOnConn(conn, Message{Event: "pusher:pong"}); err != nil {
			log.Printf("[realtime] Failed to send pong message: %v", err)
		}

	case "pusher:pong":
		// Received pong response, nothing to do

	case "pusher:error":
		log.Printf("[realtime] Received error: %s", string(msg.Data))

	case "pusher_internal:subscription_succeeded":
		if c.verbose {
			log.Printf("[realtime] Successfully subscribed to channel: %s", msg.Channel)
		}

	default:
		if !c.notifyEventListeners(msg) {
			log.Printf("[realtime] Received unhandled event: %s", msg.Event)
		}
	}
}

// startPingTicker starts the ping ticker for keepalive
func (c *Client) startPingTicker(conn *websocket.Conn, activityTimeout int) {
	if activityTimeout <= 0 {
		activityTimeout = 60 // Default 1 minute
	}

	ticker := time.NewTicker(time.Duration(activityTimeout) * time.Second)
	stop := make(chan struct{})

	c.mu.Lock()
	if c.conn != conn || c.isStoppedLocked() {
		c.mu.Unlock()
		ticker.Stop()
		return
	}
	c.stopPingTickerLocked()
	c.pingTicker = ticker
	c.pingStop = stop
	c.mu.Unlock()

	go func() {
		for {
			select {
			case <-ticker.C:
				if err := c.sendMessageOnConn(conn, Message{Event: "pusher:ping"}); err != nil && c.verbose {
					log.Printf("[realtime] Failed to send ping message: %v", err)
				}
			case <-stop:
				return
			case <-c.stopChan:
				return
			}
		}
	}()
}

func (c *Client) sendMessage(msg Message) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	return c.sendMessageOnConn(conn, msg)
}

func (c *Client) sendMessageOnConn(conn *websocket.Conn, msg Message) error {
	if conn == nil {
		return fmt.Errorf("not connected")
	}

	if msg.Data == nil {
		msg.Data = json.RawMessage(`{}`)
	}

	encoded, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	if !c.isConnectionActive(conn) {
		return fmt.Errorf("connection no longer active")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if !c.isConnectionActive(conn) {
		return fmt.Errorf("connection no longer active")
	}

	if err := conn.SetWriteDeadline(time.Now().Add(websocketWriteTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	if err := conn.WriteMessage(websocket.TextMessage, encoded); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

// subscribeToChannel subscribes to the configured channel
func (c *Client) subscribeToChannel(conn *websocket.Conn, socketID string) error {
	c.mu.RLock()
	if c.conn != conn || c.config == nil || c.isStoppedLocked() {
		c.mu.RUnlock()
		return fmt.Errorf("not connected")
	}
	config := *c.config
	hostKey := c.hostKey
	userAgent := c.userAgent
	verbose := c.verbose
	c.mu.RUnlock()

	if config.Channel == "" {
		return fmt.Errorf("no channel configured")
	}

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	var subscribeData map[string]interface{}

	// Check if it's a private channel
	if strings.HasPrefix(config.Channel, "private-") {
		// Generate auth signature for private channel
		auth, err := c.generateChannelAuth(socketID, config.Channel, config.AuthURL, hostKey, userAgent)
		if err != nil {
			return fmt.Errorf("failed to generate auth: %w", err)
		}

		subscribeData = map[string]interface{}{
			"channel": config.Channel,
			"auth":    auth,
		}
	} else {
		// Public channel
		subscribeData = map[string]interface{}{
			"channel": config.Channel,
		}
	}

	dataBytes, _ := json.Marshal(subscribeData)
	msg := Message{
		Event: "pusher:subscribe",
		Data:  dataBytes,
	}

	if err := c.sendMessageOnConn(conn, msg); err != nil {
		return fmt.Errorf("failed to send subscribe message: %w", err)
	}

	if verbose {
		log.Printf("[realtime] Subscribing to channel: %s", config.Channel)
	}

	return nil
}

// generateChannelAuth generates the auth signature for private channels
func (c *Client) generateChannelAuth(socketID, channel, authURL, hostKey, userAgent string) (string, error) {
	if authURL == "" {
		// If no auth URL, try to generate local auth (requires app secret)
		return "", fmt.Errorf("auth URL required for private channels")
	}

	// Make auth request to the auth URL
	authData := url.Values{}
	authData.Set("socket_id", socketID)
	authData.Set("channel_name", channel)

	// Create HTTP client and request
	client := &http.Client{Timeout: websocketWriteTimeout}
	req, err := http.NewRequest("POST", authURL, strings.NewReader(authData.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}

	// Set content type header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)

	// Add Bearer token if hostKey is provided
	if hostKey != "" {
		req.Header.Set("Authorization", "Bearer "+hostKey)
	}

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth request returned status %d", resp.StatusCode)
	}

	var authResp struct {
		Auth string `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", fmt.Errorf("failed to decode auth response: %w", err)
	}

	return authResp.Auth, nil
}

// notifyEventListeners processes config update events
func (c *Client) notifyEventListeners(msg Message) bool {
	var handled = false

	c.mu.RLock()
	for eventType, handler := range c.eventHandlers {
		if eventType == msg.Event {
			go handler(msg)

			handled = true
		}
	}
	c.mu.RUnlock()

	return handled
}

// scheduleReconnect schedules a reconnection attempt with exponential backoff
func (c *Client) scheduleReconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Don't schedule if we're already trying to reconnect or if stopped
	if c.isStoppedLocked() || c.config == nil || c.conn != nil || c.isConnecting {
		return
	}

	if c.reconnectTimer != nil {
		c.reconnectTimer.Stop()
	}

	// Use exponential backoff: start with 5 seconds
	delay := 5 * time.Second
	generation := c.generation

	c.reconnectTimer = time.AfterFunc(delay, func() {
		c.mu.RLock()
		stopped := c.isStoppedLocked() || c.generation != generation
		c.mu.RUnlock()
		if stopped {
			return
		}

		if c.verbose {
			log.Printf("[realtime] Attempting to reconnect...")
		}

		if err := c.Connect(); err != nil {
			log.Printf("[realtime] Reconnection failed: %v", err)
			c.scheduleReconnect()
		}
	})
}

func (c *Client) closeWebSocket(conn *websocket.Conn, code int, reason string) {
	if conn == nil {
		return
	}

	deadline := time.Now().Add(websocketCloseTimeout)
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), deadline)
	_ = conn.Close()
}

func (c *Client) stopPingTickerLocked() {
	if c.pingTicker != nil {
		c.pingTicker.Stop()
		c.pingTicker = nil
	}
	if c.pingStop != nil {
		close(c.pingStop)
		c.pingStop = nil
	}
}

func (c *Client) isStoppedLocked() bool {
	select {
	case <-c.stopChan:
		return true
	default:
		return false
	}
}

func (c *Client) isConnectionActive(conn *websocket.Conn) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn == conn && !c.isStoppedLocked()
}

func sameConfig(a, b *Config) bool {
	if a == nil || b == nil {
		return a == b
	}

	return a.Key == b.Key &&
		a.Host == b.Host &&
		a.Port == b.Port &&
		a.Channel == b.Channel &&
		a.AuthURL == b.AuthURL &&
		a.Encrypted == b.Encrypted
}
