package api

import (
	"sync"
	"time"
)

// nonceStore provides a thread-safe in-memory store for short-lived nonces
// with automatic TTL expiry. Used for CLI session nonce validation.
type nonceStore struct {
	mu      sync.Mutex
	entries map[string]nonceEntry
	ttl     time.Duration
}

type nonceEntry struct {
	value     string
	expiresAt time.Time
}

func newNonceStore(ttl time.Duration) *nonceStore {
	return &nonceStore{
		entries: make(map[string]nonceEntry),
		ttl:     ttl,
	}
}

// Set stores a nonce value keyed by the given key. Overwrites any existing entry.
func (s *nonceStore) Set(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked()
	s.entries[key] = nonceEntry{
		value:     value,
		expiresAt: time.Now().Add(s.ttl),
	}
}

// Validate checks that the given key exists and its stored value matches.
// On success, the entry is consumed (deleted) to prevent replay.
func (s *nonceStore) Validate(key, value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked()
	entry, ok := s.entries[key]
	if !ok {
		return false
	}
	delete(s.entries, key) // consume on any lookup attempt
	return entry.value == value
}

// evictExpiredLocked removes expired entries. Caller must hold mu.
func (s *nonceStore) evictExpiredLocked() {
	now := time.Now()
	for k, e := range s.entries {
		if now.After(e.expiresAt) {
			delete(s.entries, k)
		}
	}
}
