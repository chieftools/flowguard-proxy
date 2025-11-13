package iplist

import (
	"net/netip"
	"os"
	"testing"

	"flowguard/cache"

	"github.com/phemmer/go-iptrie"
)

func TestParseIPsToTrie(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		expectCount int
		expectError bool
		testIPs     map[string]bool // IP -> should be in trie
	}{
		{
			name: "IPv4 addresses",
			data: `192.168.1.1
10.0.0.1
172.16.0.1`,
			expectCount: 3,
			expectError: false,
			testIPs: map[string]bool{
				"192.168.1.1": true,
				"10.0.0.1":    true,
				"172.16.0.1":  true,
				"1.2.3.4":     false,
			},
		},
		{
			name: "IPv6 addresses",
			data: `2001:db8::1
2001:db8::2
fe80::1`,
			expectCount: 3,
			expectError: false,
			testIPs: map[string]bool{
				"2001:db8::1":  true,
				"2001:db8::2":  true,
				"fe80::1":      true,
				"2001:db8::10": false,
			},
		},
		{
			name: "Mixed IPv4 and IPv6",
			data: `192.168.1.1
2001:db8::1
10.0.0.1
fe80::1`,
			expectCount: 4,
			expectError: false,
			testIPs: map[string]bool{
				"192.168.1.1":  true,
				"2001:db8::1":  true,
				"10.0.0.1":     true,
				"fe80::1":      true,
				"172.16.0.1":   false,
				"2001:db8::10": false,
			},
		},
		{
			name: "CIDR ranges",
			data: `192.168.0.0/24
10.0.0.0/8
2001:db8::/32`,
			expectCount: 3,
			expectError: false,
			testIPs: map[string]bool{
				"192.168.0.1":     true,
				"192.168.0.254":   true,
				"192.168.1.1":     false,
				"10.0.0.1":        true,
				"10.255.255.255":  true,
				"11.0.0.1":        false,
				"2001:db8::1":     true,
				"2001:db8:ffff::": true,
				"2001:db9::1":     false,
			},
		},
		{
			name: "Comments and empty lines",
			data: `# This is a comment
192.168.1.1

# Another comment
10.0.0.1

# Empty line above`,
			expectCount: 2,
			expectError: false,
			testIPs: map[string]bool{
				"192.168.1.1": true,
				"10.0.0.1":    true,
			},
		},
		{
			name: "Invalid entries",
			data: `192.168.1.1
invalid-ip
10.0.0.1`,
			expectCount: 2,
			expectError: false,
			testIPs: map[string]bool{
				"192.168.1.1": true,
				"10.0.0.1":    true,
			},
		},
		{
			name:        "Empty data",
			data:        "",
			expectCount: 0,
			expectError: true,
		},
		{
			name:        "Only comments",
			data:        "# Comment 1\n# Comment 2\n",
			expectCount: 0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trie, count, err := parseIPsToTrie([]byte(tt.data), "test")

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if count != tt.expectCount {
				t.Errorf("Expected count %d but got %d", tt.expectCount, count)
			}

			// Test IP containment
			for ip, shouldContain := range tt.testIPs {
				contains := containsIP(trie, ip)
				if contains != shouldContain {
					t.Errorf("IP %s: expected contains=%v but got %v", ip, shouldContain, contains)
				}
			}
		})
	}
}

func TestIPListLoad(t *testing.T) {
	// Create temporary file with test IPs
	tmpFile, err := os.CreateTemp("", "iplist-test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	testData := `192.168.1.1
10.0.0.0/24
2001:db8::1`

	if _, err := tmpFile.Write([]byte(testData)); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	// Create a cache instance
	cacheInstance, err := cache.NewCache("/tmp/flowguard-test-cache", "test-agent")
	if err != nil {
		t.Fatal(err)
	}

	list := &IPList{
		name: "test",
		config: ListConfig{
			Path: tmpFile.Name(),
		},
	}

	err = list.load(cacheInstance)
	if err != nil {
		t.Fatalf("Failed to load list: %v", err)
	}

	// Test that IPs are in the trie
	if !containsIP(list.trie, "192.168.1.1") {
		t.Error("Expected 192.168.1.1 to be in list")
	}
	if !containsIP(list.trie, "10.0.0.1") {
		t.Error("Expected 10.0.0.1 to be in list (part of 10.0.0.0/24)")
	}
	if !containsIP(list.trie, "2001:db8::1") {
		t.Error("Expected 2001:db8::1 to be in list")
	}
	if containsIP(list.trie, "172.16.0.1") {
		t.Error("Did not expect 172.16.0.1 to be in list")
	}
}

func TestManagerContains(t *testing.T) {
	// Create temporary file with test IPs
	tmpFile, err := os.CreateTemp("", "iplist-test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	testData := `192.168.1.1
10.0.0.0/24
2001:db8::1/32`

	if _, err := tmpFile.Write([]byte(testData)); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	// Create a cache instance
	cacheInstance, err := cache.NewCache("/tmp/flowguard-test-cache", "test-agent")
	if err != nil {
		t.Fatal(err)
	}

	// Create manager with a test list
	listsConfig := map[string]ListConfig{
		"test_list": {
			Path: tmpFile.Name(),
		},
	}

	manager, err := New(listsConfig, cacheInstance)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer manager.Stop()

	tests := []struct {
		name     string
		listName string
		ip       string
		expected bool
	}{
		{"IPv4 exact match", "test_list", "192.168.1.1", true},
		{"IPv4 CIDR match", "test_list", "10.0.0.50", true},
		{"IPv4 no match", "test_list", "172.16.0.1", false},
		{"IPv6 CIDR match", "test_list", "2001:db8::100", true},
		{"IPv6 no match", "test_list", "2001:db9::1", false},
		{"Non-existent list", "non_existent", "192.168.1.1", false},
		{"Invalid IP", "test_list", "not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.Contains(tt.listName, tt.ip)
			if result != tt.expected {
				t.Errorf("Contains(%s, %s) = %v; want %v", tt.listName, tt.ip, result, tt.expected)
			}
		})
	}
}

func TestManagerMultipleLists(t *testing.T) {
	// Create two temporary files
	tmpFile1, err := os.CreateTemp("", "iplist-test1-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile1.Name())

	tmpFile2, err := os.CreateTemp("", "iplist-test2-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile2.Name())

	// Write different IPs to each file
	testData1 := "192.168.1.0/24"
	testData2 := "10.0.0.0/24"

	tmpFile1.Write([]byte(testData1))
	tmpFile1.Close()

	tmpFile2.Write([]byte(testData2))
	tmpFile2.Close()

	// Create a cache instance
	cacheInstance, err := cache.NewCache("/tmp/flowguard-test-cache", "test-agent")
	if err != nil {
		t.Fatal(err)
	}

	// Create manager with two lists
	listsConfig := map[string]ListConfig{
		"list1": {Path: tmpFile1.Name()},
		"list2": {Path: tmpFile2.Name()},
	}

	manager, err := New(listsConfig, cacheInstance)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer manager.Stop()

	// Verify list separation
	if !manager.Contains("list1", "192.168.1.1") {
		t.Error("Expected 192.168.1.1 in list1")
	}
	if manager.Contains("list1", "10.0.0.1") {
		t.Error("Did not expect 10.0.0.1 in list1")
	}
	if !manager.Contains("list2", "10.0.0.1") {
		t.Error("Expected 10.0.0.1 in list2")
	}
	if manager.Contains("list2", "192.168.1.1") {
		t.Error("Did not expect 192.168.1.1 in list2")
	}

	// Verify list names
	names := manager.GetListNames()
	if len(names) != 2 {
		t.Errorf("Expected 2 lists, got %d", len(names))
	}
}

// Helper function to check if an IP is in a trie
func containsIP(trie *iptrie.Trie, ip string) bool {
	if trie == nil {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return trie.Contains(addr)
}
