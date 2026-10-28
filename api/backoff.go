package api

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maximumBackoff bounds how long the client stops contacting the control
// panel, for a Retry-After as well as for a rejected host key or version.
const maximumBackoff = time.Hour

// BackoffError is returned without contacting the control panel while it
// asked the client to wait, or rejected the host key or this version.
// Proxying is not affected; only requests to the control panel pause.
type BackoffError struct {
	Until  time.Time
	Reason string
}

func (e *BackoffError) Error() string {
	return fmt.Sprintf("not contacting the control panel until %s: %s", e.Until.Format(time.RFC3339), e.Reason)
}

// do sends the request unless the client is backing off, and starts backing
// off when the control panel answers 401, 426, or 429 or 503 with a
// Retry-After.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	if err := c.backoffError(); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	c.observe(resp)
	return resp, nil
}

func (c *Client) backoffError() error {
	c.backoffMu.Lock()
	defer c.backoffMu.Unlock()

	if c.backoffUntil.IsZero() || !c.now().Before(c.backoffUntil) {
		return nil
	}
	return &BackoffError{Until: c.backoffUntil, Reason: c.backoffReason}
}

func (c *Client) observe(resp *http.Response) {
	var wait time.Duration
	var reason string

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		wait = maximumBackoff
		reason = "the control panel rejected the host key; run `flowguard setup` with the key from the control panel"
	case resp.StatusCode == http.StatusUpgradeRequired:
		wait = maximumBackoff
		reason = "the control panel no longer supports this FlowGuard version; upgrade FlowGuard"
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable:
		retryAfter, ok := parseRetryAfter(resp.Header.Get("Retry-After"), c.now())
		if !ok || retryAfter <= 0 {
			// Without Retry-After the regular schedule is slow enough.
			return
		}
		wait = min(retryAfter, maximumBackoff)
		reason = fmt.Sprintf("the control panel answered %d and asked to retry later", resp.StatusCode)
	case resp.StatusCode < 400:
		c.clearBackoff()
		return
	default:
		return
	}

	c.backoffMu.Lock()
	defer c.backoffMu.Unlock()

	if reason != c.backoffReason || c.backoffUntil.IsZero() {
		log.Printf("[api] Pausing control panel requests for %s: %s", wait.Round(time.Second), reason)
	}
	c.backoffUntil = c.now().Add(wait)
	c.backoffReason = reason
}

func (c *Client) clearBackoff() {
	c.backoffMu.Lock()
	defer c.backoffMu.Unlock()

	c.backoffUntil = time.Time{}
	c.backoffReason = ""
}

// parseRetryAfter accepts the delay-seconds and HTTP-date forms.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	if at, err := http.ParseTime(value); err == nil {
		return max(at.Sub(now), 0), true
	}
	return 0, false
}
