package api

import (
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

// GetConfig fetches the configuration from the API
func (c *Client) GetConfig() ([]byte, error) {
	if c.hostKey == "" {
		return nil, fmt.Errorf("host key is required")
	}

	req, err := http.NewRequest("GET", c.buildURL("config"), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.hostKey)
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
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
