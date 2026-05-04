package fingerprint

import (
	"sync"
	"time"
)

const storeTTL = 10 * time.Minute

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

func (s *Store) Set(localAddr, remoteAddr, value string) {
	if s == nil || localAddr == "" || remoteAddr == "" || value == "" {
		return
	}

	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[key(localAddr, remoteAddr)] = storeEntry{
		value:     value,
		expiresAt: now.Add(storeTTL),
	}

	if now.Sub(s.lastCleanup) > time.Minute {
		s.cleanupLocked(now)
	}
}

func (s *Store) Get(localAddr, remoteAddr string) string {
	if s == nil || localAddr == "" || remoteAddr == "" {
		return ""
	}

	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key(localAddr, remoteAddr)]
	if !ok || now.After(entry.expiresAt) {
		delete(s.entries, key(localAddr, remoteAddr))
		return ""
	}

	entry.expiresAt = now.Add(storeTTL)
	s.entries[key(localAddr, remoteAddr)] = entry
	return entry.value
}

func (s *Store) Delete(localAddr, remoteAddr string) {
	if s == nil || localAddr == "" || remoteAddr == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, key(localAddr, remoteAddr))
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
