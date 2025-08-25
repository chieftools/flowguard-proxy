package cache

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCacheBasics(t *testing.T) {
	// Create temp directory for cache
	tempDir := t.TempDir()

	// Create test server that counts requests
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("ETag", fmt.Sprintf("etag-%d", requestCount))
		fmt.Fprintf(w, "Response #%d", requestCount)
	}))
	defer ts.Close()

	// Create cache
	cache, err := NewCache(tempDir, "test-agent")
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// First fetch should hit the server
	data1, err := cache.FetchWithCache(ts.URL, 1*time.Hour)
	if err != nil {
		t.Fatalf("First fetch failed: %v", err)
	}
	if string(data1) != "Response #1" {
		t.Errorf("Expected 'Response #1', got '%s'", string(data1))
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request, got %d", requestCount)
	}

	// Second fetch should use cache
	data2, err := cache.FetchWithCache(ts.URL, 1*time.Hour)
	if err != nil {
		t.Fatalf("Second fetch failed: %v", err)
	}
	if string(data2) != "Response #1" {
		t.Errorf("Expected cached 'Response #1', got '%s'", string(data2))
	}
	if requestCount != 1 {
		t.Errorf("Expected still 1 request (cached), got %d", requestCount)
	}

	// Third fetch with expired cache should hit server again
	time.Sleep(2 * time.Millisecond) // Ensure cache is expired
	data3, err := cache.FetchWithCache(ts.URL, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Third fetch failed: %v", err)
	}
	if string(data3) != "Response #2" {
		t.Errorf("Expected 'Response #2', got '%s'", string(data3))
	}
	if requestCount != 2 {
		t.Errorf("Expected 2 requests (cache expired), got %d", requestCount)
	}

	// Verify cache file exists
	cacheFiles, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read cache dir: %v", err)
	}
	if len(cacheFiles) != 1 {
		t.Errorf("Expected 1 cache file, got %d", len(cacheFiles))
	}
}

func TestCacheETag(t *testing.T) {
	tempDir := t.TempDir()

	// Create test server that supports ETag
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// Check for If-None-Match header
		if r.Header.Get("If-None-Match") == "stable-etag" {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("ETag", "stable-etag")
		fmt.Fprint(w, "Stable content")
	}))
	defer ts.Close()

	cache, err := NewCache(tempDir, "test-agent")
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// First fetch
	data1, err := cache.FetchWithCache(ts.URL, 1*time.Hour)
	if err != nil {
		t.Fatalf("First fetch failed: %v", err)
	}
	if string(data1) != "Stable content" {
		t.Errorf("Expected 'Stable content', got '%s'", string(data1))
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request, got %d", requestCount)
	}

	// Force re-fetch (with very short max age)
	// Server should return 304 Not Modified
	time.Sleep(2 * time.Millisecond) // Ensure cache is expired
	data2, err := cache.FetchWithCache(ts.URL, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Second fetch failed: %v", err)
	}
	if string(data2) != "Stable content" {
		t.Errorf("Expected cached 'Stable content', got '%s'", string(data2))
	}
	if requestCount != 2 {
		t.Errorf("Expected 2 requests (but 304 response), got %d", requestCount)
	}
}

func TestCacheClearOperations(t *testing.T) {
	tempDir := t.TempDir()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Test content")
	}))
	defer ts.Close()

	cache, err := NewCache(tempDir, "test-agent")
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// Fetch and cache data
	_, err = cache.FetchWithCache(ts.URL, 1*time.Hour)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	// Verify cache file exists
	files, _ := os.ReadDir(tempDir)
	if len(files) != 1 {
		t.Errorf("Expected 1 cache file, got %d", len(files))
	}

	// Clear specific entry
	err = cache.ClearCacheEntry(ts.URL)
	if err != nil {
		t.Errorf("Failed to clear cache entry: %v", err)
	}

	// Verify cache file is gone
	files, _ = os.ReadDir(tempDir)
	if len(files) != 0 {
		t.Errorf("Expected 0 cache files after clear, got %d", len(files))
	}

	// Cache multiple entries
	for i := 0; i < 3; i++ {
		url := fmt.Sprintf("%s?id=%d", ts.URL, i)
		_, err = cache.FetchWithCache(url, 1*time.Hour)
		if err != nil {
			t.Fatalf("Fetch %d failed: %v", i, err)
		}
	}

	// Verify 3 cache files exist
	files, _ = os.ReadDir(tempDir)
	if len(files) != 3 {
		t.Errorf("Expected 3 cache files, got %d", len(files))
	}

	// Clear all cache
	err = cache.ClearCache()
	if err != nil {
		t.Errorf("Failed to clear all cache: %v", err)
	}

	// Verify all cache files are gone
	files, _ = os.ReadDir(tempDir)
	jsonCount := 0
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".json" {
			jsonCount++
		}
	}
	if jsonCount != 0 {
		t.Errorf("Expected 0 cache files after clear all, got %d", jsonCount)
	}
}

func TestCacheFailover(t *testing.T) {
	tempDir := t.TempDir()

	// Create test server that fails after first request
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			fmt.Fprint(w, "First response")
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	cache, err := NewCache(tempDir, "test-agent")
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// First fetch should succeed
	data1, err := cache.FetchWithCache(ts.URL, 1*time.Hour)
	if err != nil {
		t.Fatalf("First fetch failed: %v", err)
	}
	if string(data1) != "First response" {
		t.Errorf("Expected 'First response', got '%s'", string(data1))
	}

	// Second fetch with expired cache should try server, fail, but return stale cache
	time.Sleep(2 * time.Millisecond) // Ensure cache is expired
	data2, err := cache.FetchWithCache(ts.URL, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Second fetch failed: %v", err)
	}
	if string(data2) != "First response" {
		t.Errorf("Expected stale cached 'First response', got '%s'", string(data2))
	}
	if requestCount != 2 {
		t.Errorf("Expected 2 requests, got %d", requestCount)
	}
}
