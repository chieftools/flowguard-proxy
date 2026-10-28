package cache

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestWithHTTPClient(t *testing.T) {
	sharedClient := &http.Client{}
	cache, err := NewCache(t.TempDir(), "test-agent", false, WithHTTPClient(sharedClient))
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	if cache.httpClient != sharedClient {
		t.Fatal("expected configured HTTP client")
	}

	defaultCache, err := NewCache(t.TempDir(), "test-agent", false, WithHTTPClient(nil))
	if err != nil {
		t.Fatalf("NewCache with nil client: %v", err)
	}
	if defaultCache.httpClient == nil {
		t.Fatal("expected nil option to retain the default HTTP client")
	}
}

func TestCacheBasics(t *testing.T) {
	synctest.Test(t, testCacheBasics)
}

func testCacheBasics(t *testing.T) {
	// Create temp directory for cache
	tempDir := t.TempDir()

	// Create test server that counts requests
	requestCount := 0
	ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("ETag", fmt.Sprintf("etag-%d", requestCount))
		fmt.Fprintf(w, "Response #%d", requestCount)
	}))

	// Create cache
	cache, err := NewCache(tempDir, "test-agent", false, WithHTTPClient(ts.Client()))
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
	synctest.Sleep(2 * time.Millisecond) // Ensure cache is expired
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
	synctest.Test(t, testCacheETag)
}

func testCacheETag(t *testing.T) {
	tempDir := t.TempDir()

	// Create test server that supports ETag
	requestCount := 0
	ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// Check for If-None-Match header
		if r.Header.Get("If-None-Match") == "stable-etag" {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("ETag", "stable-etag")
		fmt.Fprint(w, "Stable content")
	}))

	cache, err := NewCache(tempDir, "test-agent", false, WithHTTPClient(ts.Client()))
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
	synctest.Sleep(2 * time.Millisecond) // Ensure cache is expired
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

	ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Test content")
	}))

	cache, err := NewCache(tempDir, "test-agent", false, WithHTTPClient(ts.Client()))
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
	synctest.Test(t, testCacheFailover)
}

func testCacheFailover(t *testing.T) {
	tempDir := t.TempDir()

	// Create test server that fails after first request
	requestCount := 0
	ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			fmt.Fprint(w, "First response")
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))

	cache, err := NewCache(tempDir, "test-agent", false, WithHTTPClient(ts.Client()))
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
	synctest.Sleep(2 * time.Millisecond) // Ensure cache is expired
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

	apiRequestCount := 0
	var receivedAuthHeader string
	publicRequestCount := 0
	var publicAuthHeader string
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			apiRequestCount++
			receivedAuthHeader = r.Header.Get("Authorization")
			fmt.Fprint(w, "API response")
			return
		}

		publicRequestCount++
		publicAuthHeader = r.Header.Get("Authorization")
		fmt.Fprint(w, "Public response")
	}))

	cache, err := NewCache(tempDir, "test-agent", false, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	// Configure API credentials
	cache.SetAPICredentials(server.URL+"/api", "test-api-key-12345")

	// Test 1: URL starting with API base should get automatic auth
	receivedAuthHeader = ""
	_, _, err = cache.FetchWithCache(server.URL+"/api/database.mmdb", 1*time.Hour)
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
	_, _, err = cache.FetchWithCache(server.URL+"/public.txt", 1*time.Hour)
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
	_, _, err = cache.FetchWithCache(server.URL+"/api/override", 1*time.Hour, "explicit-token")
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
	apiServer := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		fmt.Fprint(w, "Binary file content")
	}))

	cache, err := NewCache(tempDir, "test-agent", false, WithHTTPClient(apiServer.Client()))
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

func TestIsAPIURL(t *testing.T) {
	cache, err := NewCache(t.TempDir(), "test-agent", false)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	cache.SetAPICredentials("https://flowguard.network", "test-key")

	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "API resource", url: "https://flowguard.network/api/v1/ip_list/example/download", want: true},
		{name: "API resource with query", url: "https://flowguard.network/api/v1/ip_list/example/download?confidence=80", want: true},
		{name: "same origin outside API", url: "https://flowguard.network/public/list.txt", want: false},
		{name: "lookalike origin", url: "https://flowguard.network.example/api/v1/ip_list/example/download", want: false},
		{name: "external resource", url: "https://example.com/list.txt", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cache.IsAPIURL(tt.url); got != tt.want {
				t.Fatalf("IsAPIURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestManagedCacheIdentityOnlyReachesPanel(t *testing.T) {
	for _, fileMode := range []bool{false, true} {
		t.Run(fmt.Sprintf("file=%t", fileMode), func(t *testing.T) {
			requests := 0
			client := &http.Client{Transport: cacheIdentityTransport(func(request *http.Request) (*http.Response, error) {
				requests++
				wantAgent, wantAuth := "FlowGuard/99.0.0", ""
				if request.URL.Host == "panel.example.test" {
					wantAgent = "FlowGuard/99.0.0 server/synthetic-a"
					wantAuth = "Bearer synthetic-key"
				}
				if request.UserAgent() != wantAgent || request.Header.Get("Authorization") != wantAuth {
					t.Errorf("unexpected identity for %s: %v", request.URL, request.Header)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("synthetic-data"))}, nil
			})}
			cache, err := NewCache(t.TempDir(), "FlowGuard/99.0.0", false, WithHTTPClient(client))
			if err != nil {
				t.Fatal(err)
			}
			cache.SetAPIIdentity("https://panel.example.test", "synthetic-key", "FlowGuard/99.0.0 server/synthetic-a")

			for _, endpoint := range []string{
				"https://panel.example.test/api/v1/list",
				"https://lists.example.test/list",
				"https://panel.example.test.external.invalid/list",
			} {
				if fileMode {
					_, _, err = cache.FetchFileWithCache(endpoint, 0)
				} else {
					_, _, err = cache.FetchWithCacheForced(endpoint)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if requests != 3 {
				t.Fatalf("requests = %d, want 3", requests)
			}
		})
	}
}

type cacheIdentityTransport func(*http.Request) (*http.Response, error)

func (transport cacheIdentityTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

type testAPIGate struct {
	paused   error
	observed []int
}

func (gate *testAPIGate) Paused() error {
	return gate.paused
}

func (gate *testAPIGate) Observe(response *http.Response) {
	gate.observed = append(gate.observed, response.StatusCode)
}

func TestAPIGateOnlyAppliesToPanel(t *testing.T) {
	for _, fileMode := range []bool{false, true} {
		t.Run(fmt.Sprintf("file=%t", fileMode), func(t *testing.T) {
			var requested []string
			client := &http.Client{Transport: cacheIdentityTransport(func(request *http.Request) (*http.Response, error) {
				requested = append(requested, request.URL.Host)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("synthetic-data"))}, nil
			})}
			cache, err := NewCache(t.TempDir(), "FlowGuard/99.0.0", false, WithHTTPClient(client))
			if err != nil {
				t.Fatal(err)
			}
			cache.SetAPIIdentity("https://panel.example.test", "synthetic-key", "FlowGuard/99.0.0 server/synthetic-a")
			gate := &testAPIGate{}
			cache.SetAPIGate(gate)

			fetch := func(endpoint string) error {
				if fileMode {
					_, _, err := cache.FetchFileWithCache(endpoint, 0)
					return err
				}
				_, _, err := cache.FetchWithCacheForced(endpoint)
				return err
			}

			if err := fetch("https://panel.example.test/api/v1/list"); err != nil {
				t.Fatal(err)
			}
			if err := fetch("https://lists.example.test/list"); err != nil {
				t.Fatal(err)
			}
			if len(gate.observed) != 1 || gate.observed[0] != 200 {
				t.Fatalf("observed = %v, want only the panel response", gate.observed)
			}

			gate.paused = errors.New("paused")
			if err := fetch("https://panel.example.test/api/v1/other"); err == nil || !strings.Contains(err.Error(), "paused") {
				t.Fatalf("expected the paused gate to stop the panel download, got %v", err)
			}
			if err := fetch("https://lists.example.test/other"); err != nil {
				t.Fatalf("expected other downloads to continue while paused, got %v", err)
			}
			if want := []string{"panel.example.test", "lists.example.test", "lists.example.test"}; strings.Join(requested, ",") != strings.Join(want, ",") {
				t.Fatalf("requested = %v, want %v", requested, want)
			}
		})
	}
}

func TestAPIGateKeepsStaleDataWhilePaused(t *testing.T) {
	client := &http.Client{Transport: cacheIdentityTransport(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("synthetic-data"))}, nil
	})}
	cache, err := NewCache(t.TempDir(), "FlowGuard/99.0.0", false, WithHTTPClient(client))
	if err != nil {
		t.Fatal(err)
	}
	cache.SetAPIIdentity("https://panel.example.test", "synthetic-key", "FlowGuard/99.0.0 server/synthetic-a")
	gate := &testAPIGate{}
	cache.SetAPIGate(gate)

	endpoint := "https://panel.example.test/api/v1/list"
	if _, _, err := cache.FetchWithCacheForced(endpoint); err != nil {
		t.Fatal(err)
	}

	gate.paused = errors.New("paused")
	data, updated, err := cache.FetchWithCacheForced(endpoint)
	if err != nil || updated || string(data) != "synthetic-data" {
		t.Fatalf("got (%q, %t, %v), want the cached data", data, updated, err)
	}
}
