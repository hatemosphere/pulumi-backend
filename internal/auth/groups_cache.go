package auth

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// GroupsResolverIface defines the contract for resolving group memberships.
// The concrete GroupsResolver (Google Admin SDK) implements this interface.
type GroupsResolverIface interface {
	ResolveGroups(ctx context.Context, email string) ([]string, error)
}

type cachedGroups struct {
	groups    []string
	fetchedAt time.Time
}

// GroupsCache wraps a GroupsResolverIface with an in-memory TTL cache.
// Concurrent requests for the same email are deduplicated via singleflight.
type GroupsCache struct {
	resolver GroupsResolverIface
	ttl      time.Duration

	mu    sync.RWMutex
	cache map[string]*cachedGroups
	sf    singleflight.Group
}

// NewGroupsCache creates a cache that delegates to the given resolver on miss.
func NewGroupsCache(resolver GroupsResolverIface, ttl time.Duration) *GroupsCache {
	return &GroupsCache{
		resolver: resolver,
		ttl:      ttl,
		cache:    make(map[string]*cachedGroups),
	}
}

// ResolveGroups returns cached group memberships for the email, or fetches fresh
// from the resolver if the cache entry is missing or expired. Concurrent requests
// for the same email are coalesced into a single resolver call.
func (c *GroupsCache) ResolveGroups(ctx context.Context, email string) ([]string, error) {
	c.mu.RLock()
	entry, ok := c.cache[email]
	c.mu.RUnlock()

	if ok && time.Since(entry.fetchedAt) < c.ttl {
		return entry.groups, nil
	}

	// Deduplicate concurrent fetches for the same email.
	result, err, _ := c.sf.Do(email, func() (any, error) {
		// Double-check cache inside singleflight (another goroutine may have populated it).
		c.mu.RLock()
		entry, ok := c.cache[email]
		c.mu.RUnlock()
		if ok && time.Since(entry.fetchedAt) < c.ttl {
			return entry.groups, nil
		}

		groups, err := c.resolver.ResolveGroups(ctx, email)
		if err != nil {
			return nil, err
		}

		c.mu.Lock()
		c.cache[email] = &cachedGroups{
			groups:    groups,
			fetchedAt: time.Now(),
		}
		c.mu.Unlock()

		return groups, nil
	})
	if err != nil {
		return nil, err
	}

	return result.([]string), nil
}
