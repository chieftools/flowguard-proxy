package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client represents a FlowGuard API client
type Client struct {
	baseURL    string
	hostKey    string
	userAgent  string
	httpClient *http.Client
}

// NewClient creates a new FlowGuard API client
func NewClient(hostKey, userAgent string) *Client {
	// Get base URL from environment variable, default to production
	baseURL := os.Getenv("API_BASE")
	if baseURL == "" {
		baseURL = "https://flowguard.network"
	}

	// Ensure base URL doesn't end with slash
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &Client{
		baseURL:   baseURL,
		hostKey:   hostKey,
		userAgent: userAgent,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// buildURL constructs the full API URL for a given path
func (c *Client) buildURL(path string) string {
	return fmt.Sprintf("%s/api/v1/%s", c.baseURL, strings.TrimPrefix(path, "/"))
}

// ErrNotModified is returned when the API returns 304 Not Modified
var ErrNotModified = fmt.Errorf("configuration not modified")

// GetConfig fetches the configuration from the API
// If etag is provided, it will be sent in the If-None-Match header
// Returns ErrNotModified if the server returns 304 Not Modified
func (c *Client) GetConfig(etag string) ([]byte, error) {
	if c.hostKey == "" {
		return nil, fmt.Errorf("host key is required")
	}

	req, err := http.NewRequest("GET", c.buildURL("config"), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.hostKey)
	req.Header.Set("User-Agent", c.userAgent)

	// Add If-None-Match header if etag is provided
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch configuration: %w", err)
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		return nil, ErrNotModified
	}

	if strings.SplitAfter(resp.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return nil, fmt.Errorf("unexpected content type: %s", resp.Header.Get("Content-Type"))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errorResponse struct {
			Message string `json:"message,omitempty"`
		}
		if err := json.Unmarshal(body, &errorResponse); err != nil {
			return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
		}

		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, errorResponse.Message)
	}

	return body, nil
}

// SetHostKey updates the host key for the client
func (c *Client) SetHostKey(hostKey string) {
	c.hostKey = hostKey
}

// GetBaseURL returns the configured base URL
func (c *Client) GetBaseURL() string {
	return c.baseURL
}
