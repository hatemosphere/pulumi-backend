package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hatemosphere/pulumi-backend/internal/backup"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

type failingBackupProvider struct {
	name string
}

func (p failingBackupProvider) Name() string { return p.name }

func (p failingBackupProvider) Upload(context.Context, string) (string, error) {
	return "", errors.New("upload failed")
}

func (p failingBackupProvider) List(context.Context) ([]backup.Info, error) {
	return nil, nil
}

func (p failingBackupProvider) Delete(context.Context, string) error {
	return nil
}

func newTestManagerStore(t *testing.T) *storage.SQLiteStore {
	t.Helper()

	store, err := storage.NewSQLiteStore(filepath.Join(t.TempDir(), "test.db"), storage.SQLiteStoreConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestManagerActiveUpdateCountInitializedFromStore(t *testing.T) {
	store := newTestManagerStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreateStack(ctx, &storage.Stack{
		OrgName:     "org",
		ProjectName: "proj",
		StackName:   "stack",
	}))
	require.NoError(t, store.CreateUpdate(ctx, &storage.Update{
		ID:          "upd-1",
		OrgName:     "org",
		ProjectName: "proj",
		StackName:   "stack",
		Kind:        "update",
	}))
	require.NoError(t, store.StartUpdate(ctx, "upd-1", 1, "token", time.Now().Add(time.Hour), 0))

	mgr, err := NewManager(store, nil)
	require.NoError(t, err)
	t.Cleanup(mgr.Shutdown)

	assert.Equal(t, int64(1), mgr.ActiveUpdateCount())

	require.NoError(t, mgr.CancelUpdate(ctx, "org", "proj", "stack"))
	assert.Equal(t, int64(0), mgr.ActiveUpdateCount())
}

func TestManagerBackupFailsWhenRemoteOnlyUploadsAllFail(t *testing.T) {
	store := newTestManagerStore(t)
	backupTempDir := t.TempDir()
	t.Setenv("TMPDIR", backupTempDir)

	mgr, err := NewManager(store, nil, ManagerConfig{
		BackupProviders:   []backup.Provider{failingBackupProvider{name: "remote"}},
		Clock:             fixedClock{now: time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)},
		BackgroundContext: context.Background(),
	})
	require.NoError(t, err)
	t.Cleanup(mgr.Shutdown)

	result, err := mgr.Backup(context.Background())
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no remote uploads succeeded")

	entries, readErr := os.ReadDir(backupTempDir)
	require.NoError(t, readErr)
	assert.Empty(t, entries)
}

func TestManagerBackupKeepsLocalBackupWhenRemoteUploadFails(t *testing.T) {
	store := newTestManagerStore(t)
	backupDir := t.TempDir()

	mgr, err := NewManager(store, nil, ManagerConfig{
		BackupDir:         backupDir,
		BackupProviders:   []backup.Provider{failingBackupProvider{name: "remote"}},
		Clock:             fixedClock{now: time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)},
		BackgroundContext: context.Background(),
	})
	require.NoError(t, err)
	t.Cleanup(mgr.Shutdown)

	result, err := mgr.Backup(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.LocalPath)
	assert.Empty(t, result.RemoteKeys)
	assert.FileExists(t, result.LocalPath)
}
