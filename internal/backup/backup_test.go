package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3mock "github.com/grafana/s3-mock"
)

func TestS3Provider_UploadAndList(t *testing.T) {
	client, closeFn, err := s3mock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn(context.Background()) //nolint:errcheck

	ctx := context.Background()
	bucket := "test-backups"

	// Create bucket.
	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket})
	if err != nil {
		t.Fatal(err)
	}

	p := newS3Provider(client, bucket, "backups/")

	// Write a temp file to upload.
	tmpFile := filepath.Join(t.TempDir(), "backup-20260101-120000.db")
	if err := os.WriteFile(tmpFile, []byte("fake-db-content"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Upload.
	key, err := p.Upload(ctx, tmpFile)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if key != "backups/backup-20260101-120000.db" {
		t.Fatalf("unexpected key: %s", key)
	}

	// List.
	backups, err := p.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(backups) != 1 {
		t.Fatalf("expected 1 backup, got %d", len(backups))
	}
	if backups[0].Key != key {
		t.Fatalf("expected key %s, got %s", key, backups[0].Key)
	}
	if backups[0].Size != int64(len("fake-db-content")) {
		t.Fatalf("expected size %d, got %d", len("fake-db-content"), backups[0].Size)
	}
}

func TestS3Provider_Delete(t *testing.T) {
	client, closeFn, err := s3mock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn(context.Background()) //nolint:errcheck

	ctx := context.Background()
	bucket := "test-backups"

	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket})
	if err != nil {
		t.Fatal(err)
	}

	p := newS3Provider(client, bucket, "backups/")

	// Upload a file.
	tmpFile := filepath.Join(t.TempDir(), "backup-to-delete.db")
	if err := os.WriteFile(tmpFile, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	key, err := p.Upload(ctx, tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	// Delete.
	if err := p.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Verify deleted.
	backups, err := p.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Fatalf("expected 0 backups after delete, got %d", len(backups))
	}
}

func TestS3Provider_ListSortedNewestFirst(t *testing.T) {
	client, closeFn, err := s3mock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn(context.Background()) //nolint:errcheck

	ctx := context.Background()
	bucket := "test-backups"

	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket})
	if err != nil {
		t.Fatal(err)
	}

	p := newS3Provider(client, bucket, "pfx/")

	// Upload files with 1s+ delays so s3-mock (second-precision timestamps) records different times.
	dir := t.TempDir()
	for _, name := range []string{"backup-1.db", "backup-2.db", "backup-3.db"} {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, []byte("data-"+name), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Upload(ctx, f); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1100 * time.Millisecond) // s3-mock truncates to seconds
	}

	backups, err := p.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 3 {
		t.Fatalf("expected 3 backups, got %d", len(backups))
	}

	// Newest first.
	if backups[0].Key != "pfx/backup-3.db" {
		t.Fatalf("expected newest first, got %s", backups[0].Key)
	}
	if backups[2].Key != "pfx/backup-1.db" {
		t.Fatalf("expected oldest last, got %s", backups[2].Key)
	}
}

// --- Prune tests (using mock provider) ---

type mockProvider struct {
	backups []BackupInfo
	deleted []string
}

func (m *mockProvider) Name() string { return "mock" }

func (m *mockProvider) Upload(_ context.Context, _ string) (string, error) {
	return "mock-key", nil
}

func (m *mockProvider) List(_ context.Context) ([]BackupInfo, error) {
	return m.backups, nil
}

func (m *mockProvider) Delete(_ context.Context, key string) error {
	m.deleted = append(m.deleted, key)
	return nil
}

func TestPrune_KeepsCorrectCount(t *testing.T) {
	mock := &mockProvider{
		backups: []BackupInfo{
			{Key: "backup-5.db", LastModified: time.Now()},
			{Key: "backup-4.db", LastModified: time.Now().Add(-1 * time.Hour)},
			{Key: "backup-3.db", LastModified: time.Now().Add(-2 * time.Hour)},
			{Key: "backup-2.db", LastModified: time.Now().Add(-3 * time.Hour)},
			{Key: "backup-1.db", LastModified: time.Now().Add(-4 * time.Hour)},
		},
	}

	deleted, err := Prune(context.Background(), mock, 3)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("expected 2 deleted, got %d", deleted)
	}
	if mock.deleted[0] != "backup-2.db" || mock.deleted[1] != "backup-1.db" {
		t.Fatalf("wrong backups deleted: %v", mock.deleted)
	}
}

func TestPrune_UnlimitedRetention(t *testing.T) {
	mock := &mockProvider{
		backups: []BackupInfo{{Key: "b1"}, {Key: "b2"}},
	}
	deleted, err := Prune(context.Background(), mock, 0)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Fatalf("expected 0 deleted with unlimited retention, got %d", deleted)
	}
}

func TestPrune_FewerThanRetention(t *testing.T) {
	mock := &mockProvider{
		backups: []BackupInfo{{Key: "b1"}},
	}
	deleted, err := Prune(context.Background(), mock, 5)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Fatalf("expected 0 deleted, got %d", deleted)
	}
}

func TestPrune_S3Integration(t *testing.T) {
	client, closeFn, err := s3mock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn(context.Background()) //nolint:errcheck

	ctx := context.Background()
	bucket := "prune-test"

	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket})
	if err != nil {
		t.Fatal(err)
	}

	p := newS3Provider(client, bucket, "backups/")

	// Upload 5 backups with unique names and 1s+ delays for distinct timestamps.
	dir := t.TempDir()
	for i := 1; i <= 5; i++ {
		name := filepath.Join(dir, fmt.Sprintf("backup-%d.db", i))
		if err := os.WriteFile(name, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Upload(ctx, name); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1100 * time.Millisecond) // s3-mock truncates to seconds
	}

	// Keep 3, should delete 2.
	deleted, err := Prune(ctx, p, 3)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("expected 2 deleted, got %d", deleted)
	}

	// Verify 3 remain.
	remaining, err := p.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 3 {
		t.Fatalf("expected 3 remaining, got %d", len(remaining))
	}
}
