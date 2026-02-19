package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mockResolver implements GroupsResolverIface for testing.
type mockResolver struct {
	mu     sync.Mutex
	calls  int
	groups map[string][]string
	err    error
}

func (m *mockResolver) ResolveGroups(_ context.Context, email string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.groups[email], nil
}

func (m *mockResolver) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func TestGroupsCache_Miss(t *testing.T) {
	resolver := &mockResolver{
		groups: map[string][]string{
			"alice@example.com": {"devs", "admins"},
		},
	}
	cache := NewGroupsCache(resolver, time.Minute)

	groups, err := cache.ResolveGroups(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != 2 || groups[0] != "devs" || groups[1] != "admins" {
		t.Errorf("unexpected groups: %v", groups)
	}
	if resolver.callCount() != 1 {
		t.Errorf("expected 1 resolver call, got %d", resolver.callCount())
	}
}

func TestGroupsCache_Hit(t *testing.T) {
	resolver := &mockResolver{
		groups: map[string][]string{
			"alice@example.com": {"devs"},
		},
	}
	cache := NewGroupsCache(resolver, time.Minute)

	// First call: cache miss.
	_, _ = cache.ResolveGroups(context.Background(), "alice@example.com")
	// Second call: cache hit.
	groups, err := cache.ResolveGroups(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != 1 || groups[0] != "devs" {
		t.Errorf("unexpected groups: %v", groups)
	}
	if resolver.callCount() != 1 {
		t.Errorf("expected 1 resolver call (cached), got %d", resolver.callCount())
	}
}

func TestGroupsCache_Expiry(t *testing.T) {
	resolver := &mockResolver{
		groups: map[string][]string{
			"alice@example.com": {"devs"},
		},
	}
	cache := NewGroupsCache(resolver, 10*time.Millisecond)

	// First call: cache miss.
	_, _ = cache.ResolveGroups(context.Background(), "alice@example.com")
	if resolver.callCount() != 1 {
		t.Fatalf("expected 1 call, got %d", resolver.callCount())
	}

	// Wait for expiry.
	time.Sleep(20 * time.Millisecond)

	// Second call: cache expired, re-fetches.
	_, err := cache.ResolveGroups(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolver.callCount() != 2 {
		t.Errorf("expected 2 resolver calls after expiry, got %d", resolver.callCount())
	}
}

func TestGroupsCache_DifferentUsers(t *testing.T) {
	resolver := &mockResolver{
		groups: map[string][]string{
			"alice@example.com": {"devs"},
			"bob@example.com":   {"ops"},
		},
	}
	cache := NewGroupsCache(resolver, time.Minute)

	g1, _ := cache.ResolveGroups(context.Background(), "alice@example.com")
	g2, _ := cache.ResolveGroups(context.Background(), "bob@example.com")

	if len(g1) != 1 || g1[0] != "devs" {
		t.Errorf("alice: unexpected groups: %v", g1)
	}
	if len(g2) != 1 || g2[0] != "ops" {
		t.Errorf("bob: unexpected groups: %v", g2)
	}
	if resolver.callCount() != 2 {
		t.Errorf("expected 2 resolver calls for different users, got %d", resolver.callCount())
	}
}

func TestGroupsCache_ResolverError(t *testing.T) {
	resolver := &mockResolver{err: errors.New("network error")}
	cache := NewGroupsCache(resolver, time.Minute)

	_, err := cache.ResolveGroups(context.Background(), "alice@example.com")
	if err == nil {
		t.Fatal("expected error from resolver")
	}

	// Errors should not be cached — next call should try again.
	resolver.mu.Lock()
	resolver.err = nil
	resolver.groups = map[string][]string{"alice@example.com": {"devs"}}
	resolver.mu.Unlock()

	groups, err := cache.ResolveGroups(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error on retry: %v", err)
	}
	if len(groups) != 1 || groups[0] != "devs" {
		t.Errorf("unexpected groups after retry: %v", groups)
	}
}

func TestGroupsCache_ConcurrentAccess(t *testing.T) {
	resolver := &mockResolver{
		groups: map[string][]string{
			"alice@example.com": {"devs"},
		},
	}
	cache := NewGroupsCache(resolver, time.Minute)

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			groups, err := cache.ResolveGroups(context.Background(), "alice@example.com")
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if len(groups) != 1 || groups[0] != "devs" {
				t.Errorf("unexpected groups: %v", groups)
			}
		}()
	}
	wg.Wait()

	// Due to caching, the resolver should be called far fewer times than 100.
	if resolver.callCount() > 10 {
		t.Errorf("expected few resolver calls due to caching, got %d", resolver.callCount())
	}
}
