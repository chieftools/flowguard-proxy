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
	"time"
)

// Cache provides a generic file-based cache for external data
type Cache struct {
	cacheDir   string
	userAgent  string
	httpClient *http.Client
}

// Entry represents a cached item with metadata
type Entry struct {
	Data      []byte    `json:"data"`
	ETag      string    `json:"etag,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// NewCache creates a new cache instance
func NewCache(cacheDir string, userAgent string) (*Cache, error) {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &Cache{
		cacheDir:  cacheDir,
		userAgent: userAgent,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// FetchWithCache fetches data from a URL with caching support
func (c *Cache) FetchWithCache(url string, maxAge time.Duration) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("cache not initialized")
	}
	cacheFile := c.getCacheFilePath(url)

	// Try to load from cache first
	entry, err := c.loadCacheEntry(cacheFile)
	if err == nil && time.Since(entry.Timestamp) < maxAge {
		log.Printf("[cache] Using cached data for %s (age: %v)", url, time.Since(entry.Timestamp))
		return entry.Data, nil
	}

	// Fetch fresh data
	log.Printf("[cache] Fetching fresh data from %s", url)
	var existingETag string
	if entry != nil {
		existingETag = entry.ETag
	}
	data, etag, err := c.fetchFromURL(url, existingETag)
	if err != nil {
		// If fetch fails but we have stale cache, use it
		if entry != nil {
			log.Printf("[cache] Fetch failed, using stale cache for %s: %v", url, err)
			return entry.Data, nil
		}
		return nil, err
	}

	// If server returned 304 Not Modified, update timestamp and use cached data
	if data == nil && entry != nil {
		entry.Timestamp = time.Now()
		if err := c.saveCacheEntry(cacheFile, entry); err != nil {
			log.Printf("[cache] Failed to update cache timestamp for %s: %v", url, err)
		}
		return entry.Data, nil
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

	return data, nil
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

func (c *Cache) fetchFromURL(url string, etag string) ([]byte, string, error) {
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

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

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
