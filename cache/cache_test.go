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
	cache, err := NewCache(tempDir, "test-agent", false)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// First fetch should hit the server
	data1, updated1, err := cache.FetchWithCache(ts.URL, 1*time.Hour)
	if err != nil {
		t.Fatalf("First fetch failed: %v", err)
	}
	if string(data1) != "Response #1" {
		t.Errorf("Expected 'Response #1', got '%s'", string(data1))
	}
	if !updated1 {
		t.Errorf("Expected updated=true for first fetch")
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request, got %d", requestCount)
	}

	// Second fetch should use cache
	data2, updated2, err := cache.FetchWithCache(ts.URL, 1*time.Hour)
	if err != nil {
		t.Fatalf("Second fetch failed: %v", err)
	}
	if string(data2) != "Response #1" {
		t.Errorf("Expected cached 'Response #1', got '%s'", string(data2))
	}
	if updated2 {
		t.Errorf("Expected updated=false for cached data")
	}
	if requestCount != 1 {
		t.Errorf("Expected still 1 request (cached), got %d", requestCount)
	}

	// Third fetch with expired cache should hit server again
	time.Sleep(2 * time.Millisecond) // Ensure cache is expired
	data3, updated3, err := cache.FetchWithCache(ts.URL, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Third fetch failed: %v", err)
	}
	if string(data3) != "Response #2" {
		t.Errorf("Expected 'Response #2', got '%s'", string(data3))
	}
	if !updated3 {
		t.Errorf("Expected updated=true for fresh fetch")
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

	cache, err := NewCache(tempDir, "test-agent", false)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// First fetch
	data1, updated1, err := cache.FetchWithCache(ts.URL, 1*time.Hour)
	if err != nil {
		t.Fatalf("First fetch failed: %v", err)
	}
	if string(data1) != "Stable content" {
		t.Errorf("Expected 'Stable content', got '%s'", string(data1))
	}
	if !updated1 {
		t.Errorf("Expected updated=true for first fetch")
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request, got %d", requestCount)
	}

	// Force re-fetch (with very short max age)
	// Server should return 304 Not Modified
	time.Sleep(2 * time.Millisecond) // Ensure cache is expired
	data2, updated2, err := cache.FetchWithCache(ts.URL, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Second fetch failed: %v", err)
	}
	if string(data2) != "Stable content" {
		t.Errorf("Expected cached 'Stable content', got '%s'", string(data2))
	}
	if updated2 {
		t.Errorf("Expected updated=false for 304 Not Modified response")
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

	cache, err := NewCache(tempDir, "test-agent", false)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// Fetch and cache data
	_, _, err = cache.FetchWithCache(ts.URL, 1*time.Hour)
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
		_, _, err = cache.FetchWithCache(url, 1*time.Hour)
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
	_, err = cache.ClearCache()
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

	cache, err := NewCache(tempDir, "test-agent", false)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// First fetch should succeed
	data1, updated1, err := cache.FetchWithCache(ts.URL, 1*time.Hour)
	if err != nil {
		t.Fatalf("First fetch failed: %v", err)
	}
	if string(data1) != "First response" {
		t.Errorf("Expected 'First response', got '%s'", string(data1))
	}
	if !updated1 {
		t.Errorf("Expected updated=true for first fetch")
	}

	// Second fetch with expired cache should try server, fail, but return stale cache
	time.Sleep(2 * time.Millisecond) // Ensure cache is expired
	data2, updated2, err := cache.FetchWithCache(ts.URL, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Second fetch failed: %v", err)
	}
	if string(data2) != "First response" {
		t.Errorf("Expected stale cached 'First response', got '%s'", string(data2))
	}
	if updated2 {
		t.Errorf("Expected updated=false for stale cache fallback")
	}
	if requestCount != 2 {
		t.Errorf("Expected 2 requests, got %d", requestCount)
	}
}

func TestAPIKeyAutomatic(t *testing.T) {
	tempDir := t.TempDir()

	// Create test API server that checks for auth header
	apiRequestCount := 0
	var receivedAuthHeader string
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiRequestCount++
		receivedAuthHeader = r.Header.Get("Authorization")
		fmt.Fprint(w, "API response")
	}))
	defer apiServer.Close()

	// Create test public server that should NOT receive auth
	publicRequestCount := 0
	var publicAuthHeader string
	publicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicRequestCount++
		publicAuthHeader = r.Header.Get("Authorization")
		fmt.Fprint(w, "Public response")
	}))
	defer publicServer.Close()

	cache, err := NewCache(tempDir, "test-agent", false)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// Configure API credentials
	cache.SetAPICredentials(apiServer.URL, "test-api-key-12345")

	// Test 1: URL starting with API base should get automatic auth
	receivedAuthHeader = ""
	_, _, err = cache.FetchWithCache(apiServer.URL+"/database.mmdb", 1*time.Hour)
	if err != nil {
		t.Fatalf("API fetch failed: %v", err)
	}
	if receivedAuthHeader != "Bearer test-api-key-12345" {
		t.Errorf("Expected 'Bearer test-api-key-12345', got '%s'", receivedAuthHeader)
	}
	if apiRequestCount != 1 {
		t.Errorf("Expected 1 API request, got %d", apiRequestCount)
	}

	// Test 2: Public URL should NOT get auth header
	publicAuthHeader = ""
	_, _, err = cache.FetchWithCache(publicServer.URL+"/public.txt", 1*time.Hour)
	if err != nil {
		t.Fatalf("Public fetch failed: %v", err)
	}
	if publicAuthHeader != "" {
		t.Errorf("Expected no auth header for public URL, got '%s'", publicAuthHeader)
	}
	if publicRequestCount != 1 {
		t.Errorf("Expected 1 public request, got %d", publicRequestCount)
	}

	// Test 3: Explicit bearer token should override automatic
	receivedAuthHeader = ""
	apiRequestCount = 0
	_, _, err = cache.FetchWithCache(apiServer.URL+"/override", 1*time.Hour, "explicit-token")
	if err != nil {
		t.Fatalf("API fetch with explicit token failed: %v", err)
	}
	if receivedAuthHeader != "Bearer explicit-token" {
		t.Errorf("Expected 'Bearer explicit-token', got '%s'", receivedAuthHeader)
	}
}

func TestAPIKeyAutomaticFileCache(t *testing.T) {
	tempDir := t.TempDir()

	// Create test API server
	var receivedAuthHeader string
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		fmt.Fprint(w, "Binary file content")
	}))
	defer apiServer.Close()

	cache, err := NewCache(tempDir, "test-agent", false)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// Configure API credentials
	cache.SetAPICredentials(apiServer.URL, "file-api-key-67890")

	// Test: URL starting with API base should get automatic auth
	receivedAuthHeader = ""
	_, _, err = cache.FetchFileWithCache(apiServer.URL+"/database.bin", 1*time.Hour)
	if err != nil {
		t.Fatalf("API file fetch failed: %v", err)
	}
	if receivedAuthHeader != "Bearer file-api-key-67890" {
		t.Errorf("Expected 'Bearer file-api-key-67890', got '%s'", receivedAuthHeader)
	}
}
