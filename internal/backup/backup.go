package backup

import (
	"context"
	"fmt"
	"time"
)

// BackupInfo describes a single backup stored by a Provider.
type BackupInfo struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// Provider is the interface for backup storage destinations.
type Provider interface {
	// Upload sends a local file to the backup destination.
	// Returns the remote key/identifier for the uploaded backup.
	Upload(ctx context.Context, localPath string) (remoteKey string, err error)

	// List returns all backups at the destination, ordered newest-first.
	List(ctx context.Context) ([]BackupInfo, error)

	// Delete removes a specific backup by key.
	Delete(ctx context.Context, key string) error

	// Name returns a human-readable name for this provider (e.g., "s3").
	Name() string
}

// Prune deletes backups beyond the retention count from the given provider.
// Expects List to return results sorted newest-first.
// Returns the number of backups deleted.
func Prune(ctx context.Context, p Provider, keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}

	backups, err := p.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("list backups for pruning: %w", err)
	}

	if len(backups) <= keep {
		return 0, nil
	}

	deleted := 0
	for _, b := range backups[keep:] {
		if err := p.Delete(ctx, b.Key); err != nil {
			return deleted, fmt.Errorf("delete backup %s: %w", b.Key, err)
		}
		deleted++
	}
	return deleted, nil
}
