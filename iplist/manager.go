package iplist

import (
	"bufio"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"flowguard/cache"

	"github.com/phemmer/go-iptrie"
)

// ListConfig represents configuration for a single IP list
type ListConfig struct {
	URL                    string `json:"url,omitempty"`                      // URL to fetch IPs from
	Path                   string `json:"path,omitempty"`                     // Local file path
	RefreshIntervalSeconds int    `json:"refresh_interval_seconds,omitempty"` // Refresh interval in seconds
}

// IPList represents a single named IP list with its trie
type IPList struct {
	name   string
	config ListConfig
	trie   *iptrie.Trie
	loaded bool // tracks if list has been loaded at least once
	mu     sync.RWMutex
}

// Manager manages multiple named IP lists
type Manager struct {
	lists    map[string]*IPList
	cache    *cache.Cache
	mu       sync.RWMutex
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// New creates a new IP list manager
func New(listsConfig map[string]ListConfig, cacheInstance *cache.Cache) (*Manager, error) {
	m := &Manager{
		lists:    make(map[string]*IPList),
		cache:    cacheInstance,
		stopChan: make(chan struct{}),
	}

	// Initialize each list
	for name, config := range listsConfig {
		if err := m.addList(name, config); err != nil {
			log.Printf("[ip_list] Failed to initialize list %s: %v", name, err)
			continue
		}
	}

	// Start refresh goroutines for lists with URL sources
	for name, list := range m.lists {
		if list.config.URL != "" && list.config.RefreshIntervalSeconds > 0 {
			m.wg.Add(1)
			go m.refreshLoop(name, list)
		}
	}

	return m, nil
}

// addList creates and loads a new IP list
func (m *Manager) addList(name string, config ListConfig) error {
	list := &IPList{
		name:   name,
		config: config,
	}

	// Load initial data
	if err := list.load(m.cache); err != nil {
		return fmt.Errorf("failed to load initial data: %w", err)
	}

	m.mu.Lock()
	m.lists[name] = list
	m.mu.Unlock()

	return nil
}

// load loads IP data into the list's trie
func (l *IPList) load(cacheInstance *cache.Cache) error {
	var data []byte
	var err error
	var source string
	var wasUpdated bool

	// Fetch data from URL or file
	if l.config.URL != "" {
		source = l.config.URL
		cacheTTL := 24 * time.Hour
		if l.config.RefreshIntervalSeconds > 0 {
			cacheTTL = time.Duration(l.config.RefreshIntervalSeconds) * time.Second
		}
		data, wasUpdated, err = cacheInstance.FetchWithCache(l.config.URL, cacheTTL)
		if err != nil {
			// Try local path as fallback
			if l.config.Path != "" {
				log.Printf("[ip_list] Failed to fetch %s from URL, trying local path: %v", l.name, err)
				source = l.config.Path
				data, err = os.ReadFile(l.config.Path)
				wasUpdated = true // File read is always treated as updated
			}
			if err != nil {
				return fmt.Errorf("failed to load from URL or path: %w", err)
			}
		}
	} else if l.config.Path != "" {
		source = l.config.Path
		data, err = os.ReadFile(l.config.Path)
		wasUpdated = true // File read is always treated as updated
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
	} else {
		return fmt.Errorf("no URL or path configured")
	}

	// Skip rebuilding if data hasn't changed AND list is already loaded
	if !wasUpdated && l.loaded {
		log.Printf("[ip_list] List '%s' not modified, skipping rebuild", l.name)
		return nil
	}

	// Parse IPs and build new trie
	newTrie, count, err := parseIPsToTrie(data, source)
	if err != nil {
		return fmt.Errorf("failed to parse IPs: %w", err)
	}

	// Atomically swap the trie
	l.mu.Lock()
	l.trie = newTrie
	l.loaded = true
	l.mu.Unlock()

	log.Printf("[ip_list] Loaded list '%s' from %s: %d entries", l.name, source, count)
	return nil
}

// parseIPsToTrie parses IP data and builds a new trie
func parseIPsToTrie(data []byte, source string) (*iptrie.Trie, int, error) {
	newTrie := iptrie.NewTrie()
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	count := 0
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Try to parse as CIDR first
		if strings.Contains(line, "/") {
			prefix, err := netip.ParsePrefix(line)
			if err != nil {
				log.Printf("[ip_list] Invalid CIDR at line %d in %s: %s", lineNum, source, line)
				continue
			}
			newTrie.Insert(prefix, true)
			count++
		} else {
			// Parse as individual IP
			addr, err := netip.ParseAddr(line)
			if err != nil {
				log.Printf("[ip_list] Invalid IP at line %d in %s: %s", lineNum, source, line)
				continue
			}
			// Convert to /32 or /128 prefix
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			prefix := netip.PrefixFrom(addr, bits)
			newTrie.Insert(prefix, true)
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("scanner error: %w", err)
	}

	if count == 0 {
		return nil, 0, fmt.Errorf("no valid IPs found in %s", source)
	}

	return newTrie, count, nil
}

// Contains checks if an IP address is in the named list
func (m *Manager) Contains(listName string, ip string) bool {
	m.mu.RLock()
	list, exists := m.lists[listName]
	m.mu.RUnlock()

	if !exists {
		return false
	}

	// Parse the IP address
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

	// Check containment in the trie
	list.mu.RLock()
	defer list.mu.RUnlock()

	if list.trie == nil {
		return false
	}

	return list.trie.Contains(addr)
}

// refreshLoop periodically refreshes a list from its URL
func (m *Manager) refreshLoop(name string, list *IPList) {
	defer m.wg.Done()

	interval := time.Duration(list.config.RefreshIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := list.load(m.cache); err != nil {
				log.Printf("[ip_list] Failed to refresh list %s: %v", name, err)
			}
		case <-m.stopChan:
			return
		}
	}
}

// Stop gracefully shuts down the manager
func (m *Manager) Stop() {
	close(m.stopChan)
	m.wg.Wait()
}

// GetListNames returns the names of all loaded lists
func (m *Manager) GetListNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.lists))
	for name := range m.lists {
		names = append(names, name)
	}
	return names
}
