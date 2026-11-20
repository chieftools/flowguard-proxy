package fingerprint

import (
	"sync"
	"time"
)

const (
	// storeTTL is how long a fingerprint waits for its connection to finish
	// the handshake and take it. It is well above the QUIC handshake timeout.
	storeTTL = 30 * time.Second

	// storeMaxEntries caps the fingerprints of handshakes in progress, so a
	// flood of handshakes that never finish cannot grow the store unbounded.
	storeMaxEntries = 100_000
)

// Store holds the fingerprints of QUIC handshakes until their connection
// takes them.
type Store struct {
	mu          sync.Mutex
	entries     map[string]storeEntry
	lastCleanup time.Time
}

type storeEntry struct {
	value     string
	expiresAt time.Time
}

func NewStore() *Store {
	return &Store{
		entries: make(map[string]storeEntry),
	}
}

// Set stores a fingerprint. When the store is full of unexpired entries, the
// fingerprint is dropped.
func (s *Store) Set(localAddr, remoteAddr, value string) {
	if s == nil || localAddr == "" || remoteAddr == "" || value == "" {
		return
	}

	now := time.Now()
	k := key(localAddr, remoteAddr)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Clean up once a minute, or once a second while the store is full.
	full := len(s.entries) >= storeMaxEntries
	if since := now.Sub(s.lastCleanup); since > time.Minute || (full && since > time.Second) {
		s.cleanupLocked(now)
		full = len(s.entries) >= storeMaxEntries
	}
	if _, exists := s.entries[k]; full && !exists {
		return
	}

	s.entries[k] = storeEntry{
		value:     value,
		expiresAt: now.Add(storeTTL),
	}
}

// Take returns a stored fingerprint and removes it from the store.
func (s *Store) Take(localAddr, remoteAddr string) string {
	if s == nil || localAddr == "" || remoteAddr == "" {
		return ""
	}

	now := time.Now()
	k := key(localAddr, remoteAddr)

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[k]
	if !ok {
		return ""
	}
	delete(s.entries, k)
	if now.After(entry.expiresAt) {
		return ""
	}
	return entry.value
}

func (s *Store) cleanupLocked(now time.Time) {
	for key, entry := range s.entries {
		if now.After(entry.expiresAt) {
			delete(s.entries, key)
		}
	}
	s.lastCleanup = now
}

func key(localAddr, remoteAddr string) string {
	return localAddr + "|" + remoteAddr
}
