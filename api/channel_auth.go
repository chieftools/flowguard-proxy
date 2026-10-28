package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"go.chief.tools/flowguard-proxy/instance"
)

// maximumChannelAuthBytes bounds the channel auth answer, which only holds a
// signature.
const maximumChannelAuthBytes = 64 << 10

// AuthorizeChannel asks the control panel to sign a subscription to a private
// realtime channel and returns the signature. The host key is only sent to
// the control panel: an authURL on another origin is replaced by the control
// panel's own endpoint.
func (c *Client) AuthorizeChannel(authURL, socketID, channel string) (string, error) {
	hostKey, userAgent := c.identity()
	if hostKey == "" {
		return "", fmt.Errorf("host key is required")
	}

	form := url.Values{"socket_id": {socketID}, "channel_name": {channel}}
	req, err := http.NewRequest(http.MethodPost, c.channelAuthURL(authURL), strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+hostKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set(instance.Header, instance.ID())

	resp, err := c.do(req)
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth request returned status %d", resp.StatusCode)
	}

	var answer struct {
		Auth string `json:"auth"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maximumChannelAuthBytes)).Decode(&answer); err != nil {
		return "", fmt.Errorf("failed to decode auth response: %w", err)
	}
	if answer.Auth == "" {
		return "", fmt.Errorf("auth response has no signature")
	}

	return answer.Auth, nil
}

// channelAuthURL returns candidate when it is on the control panel's origin,
// and the control panel's channel auth endpoint otherwise.
func (c *Client) channelAuthURL(candidate string) string {
	fallback := c.buildURL("broadcasting/auth")
	if candidate == "" {
		return fallback
	}

	base, err := url.Parse(c.baseURL)
	if err != nil {
		return fallback
	}
	target, err := url.Parse(candidate)
	if err != nil || target.Scheme != base.Scheme || target.Host != base.Host || target.User != nil {
		log.Printf("[api] Not sending the host key to realtime auth URL %q, which is not on the control panel; using %s", candidate, fallback)
		return fallback
	}

	return candidate
}
