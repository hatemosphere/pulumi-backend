package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/hatemosphere/pulumi-backend/internal/backup"
)

// Backup creates a consistent database backup and uploads to configured remote providers.
func (m *Manager) Backup(ctx context.Context) (*BackupResult, error) {
	ctx, span := tracer.Start(ctx, "engine.Backup")
	defer span.End()
	if m.backupDir == "" && len(m.backupProviders) == 0 {
		return nil, errors.New("no backup destination configured (use -backup-dir and/or -backup-s3-bucket)")
	}

	dir := m.backupDir
	if dir == "" {
		dir = os.TempDir()
	}
	filename := fmt.Sprintf("backup-%s.db", m.clock.Now().Format("20060102-150405"))
	localPath := filepath.Join(dir, filename)

	if err := m.store.Backup(ctx, localPath); err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}

	result := &BackupResult{
		RemoteKeys: make(map[string]string),
	}

	if m.backupDir != "" {
		result.LocalPath = localPath
	}

	for _, p := range m.backupProviders {
		key, err := p.Upload(ctx, localPath)
		if err != nil {
			slog.Error("backup upload failed", "provider", p.Name(), "error", err)
			continue
		}
		result.RemoteKeys[p.Name()] = key

		if m.backupRetention > 0 {
			pruned, prunErr := backup.Prune(ctx, p, m.backupRetention)
			if prunErr != nil {
				slog.Error("backup pruning failed", "provider", p.Name(), "error", prunErr)
			} else if pruned > 0 {
				slog.Info("old backups pruned", "provider", p.Name(), "pruned", pruned)
			}
		}
	}

	if m.backupDir == "" {
		os.Remove(localPath) //nolint:errcheck
	}

	return result, nil
}
