package backup

import (
	"context"
	"fmt"
	"strings"
)

// S3Options holds S3-specific configuration not expressible in the URI.
type S3Options struct {
	Region         string
	Endpoint       string
	ForcePathStyle bool
}

// ResolveDestination parses a backup destination URI and returns the appropriate Provider.
//
// Supported URI schemes:
//
//	s3://bucket/prefix   — S3-compatible storage (AWS, MinIO, R2, B2)
//	gs://bucket/prefix   — Google Cloud Storage (uses Application Default Credentials)
//
// The prefix defaults to "backups/" if only a bucket is specified.
func ResolveDestination(ctx context.Context, uri string, s3opts S3Options) (Provider, error) {
	scheme, rest, ok := strings.Cut(uri, "://")
	if !ok || rest == "" {
		return nil, fmt.Errorf("invalid backup destination %q: expected scheme://bucket[/prefix]", uri)
	}

	bucket, prefix, _ := strings.Cut(rest, "/")
	if bucket == "" {
		return nil, fmt.Errorf("invalid backup destination %q: empty bucket name", uri)
	}
	if prefix == "" {
		prefix = "backups/"
	} else if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	switch scheme {
	case "s3":
		return newS3Provider(ctx, bucket, prefix, s3opts)
	case "gs":
		return newGCSProvider(ctx, bucket, prefix)
	default:
		return nil, fmt.Errorf("unsupported backup destination scheme %q in %q (supported: s3, gs)", scheme, uri)
	}
}
