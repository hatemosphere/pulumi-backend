package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

// GCSProvider implements Provider for Google Cloud Storage.
// Uses Application Default Credentials (workload identity, SA keys, gcloud auth, metadata server).
type GCSProvider struct {
	client *storage.Client
	bucket string
	prefix string
}

func newGCSProvider(ctx context.Context, bucket, prefix string) (*GCSProvider, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create GCS client: %w", err)
	}
	return &GCSProvider{client: client, bucket: bucket, prefix: prefix}, nil
}

func (p *GCSProvider) Name() string { return "gcs" }

func (p *GCSProvider) Upload(ctx context.Context, localPath string) (string, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return "", fmt.Errorf("open backup file: %w", err)
	}
	defer f.Close()

	key := p.prefix + filepath.Base(localPath)
	w := p.client.Bucket(p.bucket).Object(key).NewWriter(ctx)
	if _, err := io.Copy(w, f); err != nil {
		w.Close()
		return "", fmt.Errorf("upload to gs://%s/%s: %w", p.bucket, key, err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("finalize upload to gs://%s/%s: %w", p.bucket, key, err)
	}

	slog.Info("backup uploaded to GCS", "bucket", p.bucket, "key", key)
	return key, nil
}

func (p *GCSProvider) List(ctx context.Context) ([]BackupInfo, error) {
	var backups []BackupInfo

	it := p.client.Bucket(p.bucket).Objects(ctx, &storage.Query{Prefix: p.prefix})
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list GCS objects: %w", err)
		}
		backups = append(backups, BackupInfo{
			Key:          attrs.Name,
			Size:         attrs.Size,
			LastModified: attrs.Updated,
		})
	}

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].LastModified.After(backups[j].LastModified)
	})

	return backups, nil
}

func (p *GCSProvider) Delete(ctx context.Context, key string) error {
	if err := p.client.Bucket(p.bucket).Object(key).Delete(ctx); err != nil {
		return fmt.Errorf("delete gs://%s/%s: %w", p.bucket, key, err)
	}
	slog.Info("backup deleted from GCS", "bucket", p.bucket, "key", key)
	return nil
}

// Close releases resources held by the GCS client.
func (p *GCSProvider) Close() error {
	return p.client.Close()
}
