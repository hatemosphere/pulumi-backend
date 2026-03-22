package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme/autocert"
)

func TestACMECache_PutGetDelete(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	defer store.Close()

	cache := NewACMECache(store)
	ctx := t.Context()

	// Get missing key returns ErrCacheMiss.
	_, err = cache.Get(ctx, "missing")
	assert.ErrorIs(t, err, autocert.ErrCacheMiss)

	// Put and Get round-trip.
	data := []byte("-----BEGIN CERTIFICATE-----\ntest cert data\n-----END CERTIFICATE-----")
	require.NoError(t, cache.Put(ctx, "example.com", data))

	got, err := cache.Get(ctx, "example.com")
	require.NoError(t, err)
	assert.Equal(t, data, got)

	// Delete removes the entry.
	require.NoError(t, cache.Delete(ctx, "example.com"))
	_, err = cache.Get(ctx, "example.com")
	assert.ErrorIs(t, err, autocert.ErrCacheMiss)

	// Delete on missing key is a no-op.
	require.NoError(t, cache.Delete(ctx, "nonexistent"))
}

func TestACMECache_KeysArePrefixed(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	defer store.Close()

	cache := NewACMECache(store)
	ctx := t.Context()

	require.NoError(t, cache.Put(ctx, "mykey", []byte("data")))

	// The raw server_config key should be prefixed with "acme:".
	val, err := store.GetConfig(ctx, "acme:mykey")
	require.NoError(t, err)
	assert.NotEmpty(t, val)

	// Without prefix, nothing.
	val, err = store.GetConfig(ctx, "mykey")
	require.NoError(t, err)
	assert.Empty(t, val)
}
