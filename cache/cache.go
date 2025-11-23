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
	"time"
)

// Cache provides a generic file-based cache for external data
type Cache struct {
	cacheDir   string
	userAgent  string
	apiBase    string
	apiKey     string
	verbose    bool
	httpClient *http.Client
}

// Entry represents a cached item with metadata
type Entry struct {
	Data      []byte    `json:"data"`
	ETag      string    `json:"etag,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// NewCache creates a new cache instance
func NewCache(cacheDir string, userAgent string, verbose bool) (*Cache, error) {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &Cache{
		cacheDir:  cacheDir,
		userAgent: userAgent,
		verbose:   verbose,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// SetAPICredentials configures the API base URL and key for automatic authentication
func (c *Cache) SetAPICredentials(apiBase, apiKey string) {
	c.apiBase = apiBase
	c.apiKey = apiKey
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

	// Try to load from cache first
	entry, err := c.loadCacheEntry(cacheFile)
	if err == nil && time.Since(entry.Timestamp) < maxAge {
		if c.verbose {
			log.Printf("[cache] Using cached data for %s (age: %v)", url, time.Since(entry.Timestamp))
		}
		return entry.Data, false, nil
	}

	if c.verbose {
		log.Printf("[cache] Fetching fresh data from %s", url)
	}

	var existingETag string
	if entry != nil {
		existingETag = entry.ETag
	}
	var token string
	if len(bearerToken) > 0 {
		token = bearerToken[0]
	} else if c.shouldUseAPIKey(url) {
		token = c.apiKey
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
			if time.Since(meta.Timestamp) < maxAge {
				// Verify file exists
				if _, err := os.Stat(cacheFile); err == nil {
					log.Printf("[cache] Using cached file for %s (age: %v)", url, time.Since(meta.Timestamp))
					return cacheFile, false, nil
				}
			}
		}
	}

	// Fetch fresh file
	log.Printf("[cache] Fetching fresh file from %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", false, err
	}

	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	if meta.ETag != "" {
		req.Header.Set("If-None-Match", meta.ETag)
	}

	// Apply bearer token: explicit parameter or automatic API key
	var token string
	if len(bearerToken) > 0 {
		token = bearerToken[0]
	} else if c.shouldUseAPIKey(url) {
		token = c.apiKey
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
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
func (c *Cache) ClearCache() error {
	entries, err := os.ReadDir(c.cacheDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			if err := os.Remove(filepath.Join(c.cacheDir, entry.Name())); err != nil {
				log.Printf("[cache] Failed to remove cache file %s: %v", entry.Name(), err)
			}
		}
	}
	return nil
}

// ClearCacheEntry removes a specific cached entry
func (c *Cache) ClearCacheEntry(url string) error {
	cacheFile := c.getCacheFilePath(url)
	return os.Remove(cacheFile)
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

	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := c.httpClient.Do(req)
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

// shouldUseAPIKey checks if a URL starts with the configured API base
func (c *Cache) shouldUseAPIKey(url string) bool {
	if c.apiBase == "" || c.apiKey == "" {
		return false
	}
	return strings.HasPrefix(url, c.apiBase)
}
