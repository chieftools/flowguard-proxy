package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Cache provides a generic file-based cache for external data
type Cache struct {
	identityMu   sync.RWMutex
	apiUserAgent string
	cacheDir     string
	userAgent    string
	apiBase      string
	apiKey       string
	verbose      bool
	httpClient   *http.Client
	apiGate      APIGate
}

// APIGate pauses requests to the control panel while it asked FlowGuard to
// wait or rejected its host key. api.Client implements it.
type APIGate interface {
	// Paused returns an error while requests to the control panel are paused.
	Paused() error
	// Observe starts or ends a pause based on a control panel response.
	Observe(*http.Response)
}

// CacheOption configures a Cache.
type CacheOption func(*Cache)

// WithHTTPClient configures the HTTP client used for cache fetches.
// A nil client leaves the default client unchanged.
func WithHTTPClient(httpClient *http.Client) CacheOption {
	return func(cache *Cache) {
		if httpClient != nil {
			cache.httpClient = httpClient
		}
	}
}

// Entry represents a cached item with metadata
type Entry struct {
	Data      []byte    `json:"data"`
	ETag      string    `json:"etag,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// NewCache creates a new cache instance
func NewCache(cacheDir string, userAgent string, verbose bool, options ...CacheOption) (*Cache, error) {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	cache := &Cache{
		cacheDir:  cacheDir,
		userAgent: userAgent,
		verbose:   verbose,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, option := range options {
		option(cache)
	}

	return cache, nil
}

// SetAPICredentials configures the API base URL and key for automatic authentication
func (c *Cache) SetAPICredentials(apiBase, apiKey string) {
	c.SetAPIIdentity(apiBase, apiKey, c.userAgent)
}

// SetAPIIdentity configures identification for managed API requests.
func (c *Cache) SetAPIIdentity(apiBase, apiKey, userAgent string) {
	c.identityMu.Lock()
	defer c.identityMu.Unlock()

	c.apiBase = apiBase
	c.apiKey = apiKey
	c.apiUserAgent = userAgent
}

// SetAPIGate makes downloads from the control panel pause together with the
// other requests to it.
func (c *Cache) SetAPIGate(gate APIGate) {
	c.identityMu.Lock()
	defer c.identityMu.Unlock()

	c.apiGate = gate
}

// do sends req, through the API gate when it goes to the control panel.
func (c *Cache) do(req *http.Request) (*http.Response, error) {
	c.identityMu.RLock()
	gate := c.apiGate
	if c.apiBase == "" || !strings.HasPrefix(req.URL.String(), strings.TrimRight(c.apiBase, "/")+"/") {
		gate = nil
	}
	c.identityMu.RUnlock()

	if gate == nil {
		return c.httpClient.Do(req)
	}
	if err := gate.Paused(); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	gate.Observe(resp)
	return resp, nil
}

// IsAPIURL reports whether rawURL is below the control panel's proxy
// endpoints, under /proxy/ or, from control panels before the move, /api/.
func (c *Cache) IsAPIURL(rawURL string) bool {
	if c == nil {
		return false
	}

	c.identityMu.RLock()
	defer c.identityMu.RUnlock()
	if c.apiBase == "" {
		return false
	}

	base := strings.TrimRight(c.apiBase, "/")
	return strings.HasPrefix(rawURL, base+"/proxy/") || strings.HasPrefix(rawURL, base+"/api/")
}

// FetchWithCache fetches data from a URL with caching support
// Returns (data, wasUpdated, error) where wasUpdated indicates if data changed
// Optional bearerToken parameter can be provided to add Authorization header
// If URL starts with configured API base, the API key is automatically applied
func (c *Cache) FetchWithCache(url string, maxAge time.Duration, bearerToken ...string) ([]byte, bool, error) {
	if c == nil {
		return nil, false, fmt.Errorf("cache not initialized")
	}
	cacheFile := c.getCacheFilePath(url)

	// For maxAge > 2 minutes, subtract 1 minute buffer to ensure cache is stale when periodic refreshes run
	// This prevents race conditions where a refresh ticker fires slightly before the cache expires
	effectiveMaxAge := maxAge
	if maxAge > 2*time.Minute {
		effectiveMaxAge = maxAge - time.Minute
	}

	// Try to load from cache first
	entry, _ := c.loadCacheEntry(cacheFile)
	if entry != nil && time.Since(entry.Timestamp) < effectiveMaxAge {
		if c.verbose {
			log.Printf("[cache] Using cached data for %s (age: %v)", url, time.Since(entry.Timestamp))
		}
		return entry.Data, false, nil
	}

	if c.verbose {
		log.Printf("[cache] Fetching fresh data from %s", url)
	}

	return c.fetchAndUpdate(url, cacheFile, entry, c.resolveToken(url, bearerToken...))
}

// FetchWithCacheForced fetches data from a URL, bypassing TTL but respecting etag
// Returns (data, wasUpdated, error) where wasUpdated indicates if data changed
// This is useful for forced refreshes triggered by external events
func (c *Cache) FetchWithCacheForced(url string, bearerToken ...string) ([]byte, bool, error) {
	if c == nil {
		return nil, false, fmt.Errorf("cache not initialized")
	}
	cacheFile := c.getCacheFilePath(url)

	// Load existing cache entry to get etag (if any)
	entry, _ := c.loadCacheEntry(cacheFile)

	if c.verbose {
		log.Printf("[cache] Force fetching data from %s (bypassing TTL)", url)
	}

	return c.fetchAndUpdate(url, cacheFile, entry, c.resolveToken(url, bearerToken...))
}

// resolveToken determines the bearer token to use for a request
func (c *Cache) resolveToken(url string, bearerToken ...string) string {
	if len(bearerToken) > 0 {
		return bearerToken[0]
	}
	c.identityMu.RLock()
	defer c.identityMu.RUnlock()
	if c.apiBase != "" && strings.HasPrefix(url, strings.TrimRight(c.apiBase, "/")+"/") {
		return c.apiKey
	}
	return ""
}

// fetchAndUpdate performs the actual HTTP fetch and updates the cache
// This is the shared implementation used by both FetchWithCache and FetchWithCacheForced
func (c *Cache) fetchAndUpdate(url string, cacheFile string, entry *Entry, token string) ([]byte, bool, error) {
	var existingETag string
	if entry != nil {
		existingETag = entry.ETag
	}

	data, etag, err := c.fetchFromURL(url, existingETag, token)
	if err != nil {
		// If fetch fails but we have stale cache, use it
		if entry != nil {
			log.Printf("[cache] Fetch failed, using stale cache for %s: %v", url, err)
			return entry.Data, false, nil
		}
		return nil, false, err
	}

	// If server returned 304 Not Modified, update timestamp and use cached data
	if data == nil && entry != nil {
		entry.Timestamp = time.Now()
		if err := c.saveCacheEntry(cacheFile, entry); err != nil {
			log.Printf("[cache] Failed to update cache timestamp for %s: %v", url, err)
		}

		if c.verbose {
			log.Printf("[cache] Not modified (304) for %s - using existing data", url)
		}

		return entry.Data, false, nil
	}

	// Save new data to cache
	newEntry := &Entry{
		Data:      data,
		Timestamp: time.Now(),
		ETag:      etag,
	}
	if err := c.saveCacheEntry(cacheFile, newEntry); err != nil {
		log.Printf("[cache] Failed to save to cache for %s: %v", url, err)
	}
	if c.verbose {
		log.Printf("[cache] Successfully fetched fresh data for %s", url)
	}
	return data, true, nil
}

// FetchFileWithCache fetches a binary file from a URL with efficient caching
// Returns (path, wasUpdated, error) where wasUpdated indicates if file changed
// This method stores the file directly on disk without JSON encoding
// Optional bearerToken parameter can be provided to add Authorization header
// If URL starts with configured API base, the API key is automatically applied
func (c *Cache) FetchFileWithCache(url string, maxAge time.Duration, bearerToken ...string) (string, bool, error) {
	if c == nil {
		return "", false, fmt.Errorf("cache not initialized")
	}

	// For maxAge > 2 minutes, subtract 1 minute buffer to ensure cache is stale when periodic refreshes run
	// This prevents race conditions where a refresh ticker fires slightly before the cache expires
	effectiveMaxAge := maxAge
	if maxAge > 2*time.Minute {
		effectiveMaxAge = maxAge - time.Minute
	}

	// Use a different naming scheme for binary files
	hash := sha256.Sum256([]byte(url))
	cacheFile := filepath.Join(c.cacheDir, hex.EncodeToString(hash[:])+"_file.bin")
	metaFile := filepath.Join(c.cacheDir, hex.EncodeToString(hash[:])+"_file.meta")

	// Check metadata first
	var meta struct {
		ETag      string    `json:"etag,omitempty"`
		Timestamp time.Time `json:"timestamp"`
	}

	if metaData, err := os.ReadFile(metaFile); err == nil {
		if err := json.Unmarshal(metaData, &meta); err == nil {
			// Check if cache is still fresh
			if time.Since(meta.Timestamp) < effectiveMaxAge {
				// Verify file exists
				if _, err := os.Stat(cacheFile); err == nil {
					if c.verbose {
						log.Printf("[cache] Using cached file for %s (age: %v)", url, time.Since(meta.Timestamp))
					}
					return cacheFile, false, nil
				}
			}
		}
	}

	// Fetch fresh file
	if c.verbose {
		log.Printf("[cache] Fetching fresh file from %s", url)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", false, err
	}

	if userAgent := c.userAgentForURL(url); userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	if meta.ETag != "" {
		req.Header.Set("If-None-Match", meta.ETag)
	}

	// Apply bearer token: explicit parameter or automatic API key
	token := c.resolveToken(url, bearerToken...)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.do(req)
	if err != nil {
		// If fetch fails but we have stale cache, use it
		if _, err := os.Stat(cacheFile); err == nil {
			log.Printf("[cache] Fetch failed, using stale cache for %s", url)
			return cacheFile, false, nil
		}
		return "", false, err
	}
	defer resp.Body.Close()

	if c.verbose {
		log.Printf("[cache] HTTP %d for %s (ETag sent: %v, ETag received: %s)",
			resp.StatusCode, url, meta.ETag != "", resp.Header.Get("ETag"))
	}

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		// Update timestamp
		meta.Timestamp = time.Now()
		if metaData, err := json.Marshal(meta); err == nil {
			os.WriteFile(metaFile, metaData, 0644)
		}
		log.Printf("[cache] File not modified (304) for %s - using existing file", url)
		return cacheFile, false, nil
	}

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Create temporary file first
	tempFile := cacheFile + ".tmp"
	out, err := os.Create(tempFile)
	if err != nil {
		return "", false, err
	}

	// Copy data
	size, err := io.Copy(out, resp.Body)
	out.Close()
	if err != nil {
		os.Remove(tempFile)
		return "", false, err
	}

	// Move temp file to final location
	if err := os.Rename(tempFile, cacheFile); err != nil {
		os.Remove(tempFile)
		return "", false, err
	}

	// Save metadata
	meta.ETag = resp.Header.Get("ETag")
	meta.Timestamp = time.Now()
	if metaData, err := json.Marshal(meta); err == nil {
		os.WriteFile(metaFile, metaData, 0644)
	}

	log.Printf("[cache] Successfully downloaded fresh file from %s (size: %.2f MB)", url, float64(size)/1024/1024)
	return cacheFile, true, nil
}

// LoadFromCache loads data from cache without fetching
func (c *Cache) LoadFromCache(url string) ([]byte, time.Time, error) {
	cacheFile := c.getCacheFilePath(url)
	entry, err := c.loadCacheEntry(cacheFile)
	if err != nil {
		return nil, time.Time{}, err
	}
	return entry.Data, entry.Timestamp, nil
}

// SaveToCache saves data directly to cache
func (c *Cache) SaveToCache(url string, data []byte) error {
	cacheFile := c.getCacheFilePath(url)
	entry := &Entry{
		Data:      data,
		Timestamp: time.Now(),
	}
	return c.saveCacheEntry(cacheFile, entry)
}

// ClearCache removes all cached entries
func (c *Cache) ClearCache() (int, error) {
	entries, err := os.ReadDir(c.cacheDir)
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := filepath.Ext(entry.Name())
		// Remove JSON cache files, binary cache files, and metadata files
		if ext == ".json" || ext == ".bin" || ext == ".meta" {
			if err := os.Remove(filepath.Join(c.cacheDir, entry.Name())); err != nil {
				log.Printf("[cache] Failed to remove cache file %s: %v", entry.Name(), err)
			} else {
				removed++
			}
		}
	}
	return removed, nil
}

// ClearCacheEntry removes a specific cached entry
func (c *Cache) ClearCacheEntry(url string) error {
	cacheFile := c.getCacheFilePath(url)
	return os.Remove(cacheFile)
}

// Dir returns the cache directory path
func (c *Cache) Dir() string {
	return c.cacheDir
}

func (c *Cache) getCacheFilePath(url string) string {
	hash := sha256.Sum256([]byte(url))
	filename := hex.EncodeToString(hash[:]) + ".json"
	return filepath.Join(c.cacheDir, filename)
}

func (c *Cache) loadCacheEntry(path string) (*Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

func (c *Cache) saveCacheEntry(path string, entry *Entry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func (c *Cache) fetchFromURL(url string, etag string, bearerToken string) ([]byte, string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", err
	}

	if userAgent := c.userAgentForURL(url); userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if c.verbose {
		log.Printf("[cache] HTTP %d for %s (ETag sent: %v, ETag received: %s)",
			resp.StatusCode, url, etag != "", resp.Header.Get("ETag"))
	}

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	newETag := resp.Header.Get("ETag")
	return body, newETag, nil
}

func (c *Cache) userAgentForURL(url string) string {
	c.identityMu.RLock()
	defer c.identityMu.RUnlock()

	if c.apiKey != "" && c.apiBase != "" && strings.HasPrefix(url, strings.TrimRight(c.apiBase, "/")+"/") {
		return c.apiUserAgent
	}

	return c.userAgent
}
