package pusher

import (
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
	reconnectTimer *time.Timer
	stopChan       chan struct{}
	eventHandlers  map[string]MessageHandler
	mu             sync.RWMutex
	pingTicker     *time.Ticker
}

// NewClient creates a new Realtime client
func NewClient(cfg *Config, userAgent, hostKey string, verbose bool) *Client {
	if cfg == nil {
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
	defer c.mu.Unlock()

	if c.isConnected || c.isConnecting {
		return nil
	}

	c.isConnecting = true

	// Build WebSocket URL
	wsURL := c.buildWebSocketURL()

	// Set up WebSocket dialer
	dialer := websocket.DefaultDialer
	dialer.HandshakeTimeout = 10 * time.Second

	// Connect to WebSocket
	conn, _, err := dialer.Dial(wsURL, map[string][]string{
		"User-Agent": {c.userAgent},
	})
	if err != nil {
		c.isConnecting = false
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	c.conn = conn
	c.isConnecting = false

	log.Printf("[realtime] Connected to %s", c.config.Host)

	// Start message handling
	go c.handleMessages()

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
	defer c.mu.Unlock()

	// If no config provided, disconnect
	if newConfig == nil {
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
		c.config = nil
		c.isConnected = false
		c.isConnecting = false
		return nil
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

	// If config changed and we're connected, reconnect
	if configChanged && c.conn != nil {
		log.Printf("[realtime] Configuration changed, reconnecting...")

		c.conn.Close()
		c.conn = nil
		c.isConnected = false
		c.isConnecting = false

		// Reconnect with new config
		go func() {
			if err := c.Connect(); err != nil {
				log.Printf("[realtime] Failed to reconnect with new config: %v", err)
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
	c.mu.Lock()
	defer c.mu.Unlock()

	// Signal stop to prevent reconnections
	select {
	case <-c.stopChan:
		// Already closed
	default:
		close(c.stopChan)
	}

	// Stop ping ticker
	if c.pingTicker != nil {
		c.pingTicker.Stop()
		c.pingTicker = nil
	}

	// Stop reconnect timer
	if c.reconnectTimer != nil {
		c.reconnectTimer.Stop()
		c.reconnectTimer = nil
	}

	// Close connection
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	c.isConnected = false
	c.isConnecting = false

	log.Printf("[realtime] Disconnected")
}

// buildWebSocketURL constructs the WebSocket URL based on configuration
func (c *Client) buildWebSocketURL() string {
	var host string
	var port int
	var scheme string

	// Use custom host and port
	host = c.config.Host
	port = c.config.Port

	if c.config.Encrypted {
		scheme = "wss"
	} else {
		scheme = "ws"
	}

	return fmt.Sprintf("%s://%s:%d/app/%s?protocol=7&client=flowguard&version=1.0.0", scheme, host, port, c.config.Key)
}

// handleMessages handles incoming WebSocket messages
func (c *Client) handleMessages() {
	defer func() {
		c.mu.Lock()
		c.isConnected = false
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
		c.mu.Unlock()

		// Schedule reconnect if not stopped
		select {
		case <-c.stopChan:
			return
		default:
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
		err := c.conn.ReadJSON(&msg)

		if err != nil {
			log.Printf("[realtime] Failed to read message: %v", err)
			return
		}

		c.handlePusherMessage(msg)
	}
}

// handlePusherMessage processes individual Realtime protocol messages
func (c *Client) handlePusherMessage(msg Message) {
	if c.verbose {
		log.Printf("[realtime] %s => %s", msg.Event, msg.Data)
	}

	switch msg.Event {
	case "pusher:connection_established":
		var data ConnectionEstablishedMessageData
		if err := c.unmarshalMessageData(msg.Data, &data); err == nil {
			c.mu.Lock()
			c.socketID = data.SocketID
			c.isConnected = true
			c.mu.Unlock()

			if c.verbose {
				log.Printf("[realtime] Connection established, socket ID: %s @ colo: %s", data.SocketID, data.SocketChiefColo)
			}

			// Start ping ticker for keepalive
			c.startPingTicker(data.ActivityTimeout)

			// Subscribe to the configured channel
			go func() {
				if err := c.subscribeToChannel(); err != nil {
					log.Printf("[realtime] Failed to subscribe to channel: %v", err)
				}
			}()
		} else {
			log.Printf("[realtime] Failed to parse connection established data: %v", err)
		}

	case "pusher:ping":
		// Respond to ping with pong
		c.sendMessage(Message{Event: "pusher:pong"})

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

// unmarshalMessageData handles double-encoded JSON data from Pusher messages
func (c *Client) unmarshalMessageData(data json.RawMessage, v interface{}) error {
	var dataStr string

	if err := json.Unmarshal(data, &dataStr); err != nil {
		return fmt.Errorf("failed to unmarshal data string: %w", err)
	}

	if err := json.Unmarshal([]byte(dataStr), v); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return nil
}

// startPingTicker starts the ping ticker for keepalive
func (c *Client) startPingTicker(activityTimeout int) {
	if activityTimeout <= 0 {
		activityTimeout = 60 // Default 1 minute
	}

	c.mu.Lock()
	if c.pingTicker != nil {
		c.pingTicker.Stop()
	}
	c.pingTicker = time.NewTicker(time.Duration(activityTimeout) * time.Second)
	c.mu.Unlock()

	go func() {
		for {
			select {
			case <-c.pingTicker.C:
				c.sendMessage(Message{Event: "pusher:ping"})
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

	if conn != nil {
		if msg.Data == nil {
			msg.Data = json.RawMessage(`{}`)
		}
		encoded, err := json.Marshal(msg)
		if err != nil {
			log.Printf("[realtime] Failed to encode ping message: %v", err)
		}
		conn.WriteMessage(1, encoded)
	}

	return nil
}

// subscribeToChannel subscribes to the configured channel
func (c *Client) subscribeToChannel() error {
	if c.config.Channel == "" {
		return fmt.Errorf("no channel configured")
	}

	c.mu.RLock()
	conn := c.conn
	socketID := c.socketID
	c.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	var subscribeData map[string]interface{}

	// Check if it's a private channel
	if strings.HasPrefix(c.config.Channel, "private-") {
		// Generate auth signature for private channel
		auth, err := c.generateChannelAuth(socketID, c.config.Channel)
		if err != nil {
			return fmt.Errorf("failed to generate auth: %w", err)
		}

		subscribeData = map[string]interface{}{
			"channel": c.config.Channel,
			"auth":    auth,
		}
	} else {
		// Public channel
		subscribeData = map[string]interface{}{
			"channel": c.config.Channel,
		}
	}

	dataBytes, _ := json.Marshal(subscribeData)
	msg := Message{
		Event: "pusher:subscribe",
		Data:  dataBytes,
	}

	if err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("failed to send subscribe message: %w", err)
	}

	if c.verbose {
		log.Printf("[realtime] Subscribing to channel: %s", c.config.Channel)
	}

	return nil
}

// generateChannelAuth generates the auth signature for private channels
func (c *Client) generateChannelAuth(socketID, channel string) (string, error) {
	if c.config.AuthURL == "" {
		// If no auth URL, try to generate local auth (requires app secret)
		return "", fmt.Errorf("auth URL required for private channels")
	}

	// Make auth request to the auth URL
	authData := url.Values{}
	authData.Set("socket_id", socketID)
	authData.Set("channel_name", channel)

	// Create HTTP client and request
	client := &http.Client{}
	req, err := http.NewRequest("POST", c.config.AuthURL, strings.NewReader(authData.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}

	// Set content type header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.userAgent)

	// Add Bearer token if hostKey is provided
	if c.hostKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.hostKey)
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
	select {
	case <-c.stopChan:
		return
	default:
	}

	if c.reconnectTimer != nil {
		c.reconnectTimer.Stop()
	}

	// Use exponential backoff: start with 5 seconds
	delay := 5 * time.Second

	c.reconnectTimer = time.AfterFunc(delay, func() {
		select {
		case <-c.stopChan:
			return
		default:
			if c.verbose {
				log.Printf("[realtime] Attempting to reconnect...")
			}

			if err := c.Connect(); err != nil {
				log.Printf("[realtime] Reconnection failed: %v", err)
				c.scheduleReconnect()
			}
		}
	})
}
