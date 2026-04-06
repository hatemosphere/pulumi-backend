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
		return nil, errors.New("no backup destination configured (use -backup-dir and/or -backup-destination)")
	}

	dir := m.backupDir
	if dir == "" {
		dir = os.TempDir()
	}
	filename := fmt.Sprintf("backup-%s.db", m.clock.Now().Format("20060102-150405"))
	localPath := filepath.Join(dir, filename)
	if m.backupDir == "" {
		defer func() {
			if err := os.Remove(localPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				slog.Warn("failed to remove temporary backup", "path", localPath, "error", err)
			}
		}()
	}

	if err := m.store.Backup(ctx, localPath); err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}

	result := &BackupResult{
		RemoteKeys: make(map[string]string),
	}

	if m.backupDir != "" {
		result.LocalPath = localPath
	}

	var uploadErrs []error
	for _, p := range m.backupProviders {
		key, err := p.Upload(ctx, localPath)
		if err != nil {
			slog.Error("backup upload failed", "provider", p.Name(), "error", err)
			uploadErrs = append(uploadErrs, fmt.Errorf("%s: %w", p.Name(), err))
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

	if m.backupDir == "" && len(m.backupProviders) > 0 && len(result.RemoteKeys) == 0 {
		return nil, fmt.Errorf("backup: no remote uploads succeeded: %w", errors.Join(uploadErrs...))
	}

	return result, nil
}
