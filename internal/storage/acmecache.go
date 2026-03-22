package storage

import (
	"context"
	"encoding/hex"

	"golang.org/x/crypto/acme/autocert"
)

// ACMECache implements autocert.Cache using the server_config table.
// Keys are prefixed with "acme:" to avoid collisions.
// Data is stored as hex-encoded strings (cert/key bytes are binary).
type ACMECache struct {
	store *SQLiteStore
}

// NewACMECache creates an autocert.Cache backed by SQLite.
func NewACMECache(store *SQLiteStore) *ACMECache {
	return &ACMECache{store: store}
}

func (c *ACMECache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := c.store.GetConfig(ctx, "acme:"+key)
	if err != nil {
		return nil, err
	}
	if val == "" {
		return nil, autocert.ErrCacheMiss
	}
	return hex.DecodeString(val)
}

func (c *ACMECache) Put(ctx context.Context, key string, data []byte) error {
	return c.store.SetConfig(ctx, "acme:"+key, hex.EncodeToString(data))
}

func (c *ACMECache) Delete(ctx context.Context, key string) error {
	return c.store.DeleteConfig(ctx, "acme:"+key)
}
