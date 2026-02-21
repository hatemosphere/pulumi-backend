package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Config holds configuration for the S3 backup provider.
type S3Config struct {
	Bucket         string
	Region         string // default: "us-east-1"
	Endpoint       string // custom endpoint for MinIO, R2, B2, etc.
	Prefix         string // key prefix (default: "backups/")
	ForcePathStyle bool   // force path-style addressing (for MinIO)
}

// S3Provider implements Provider for S3-compatible storage.
type S3Provider struct {
	client *s3.Client
	bucket string
	prefix string
}

// NewS3Provider creates a new S3-compatible backup provider.
func NewS3Provider(ctx context.Context, cfg S3Config) (*S3Provider, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("S3 bucket name is required")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "backups/"
	}

	optFns := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
	}
	if cfg.Endpoint != "" {
		optFns = append(optFns, awsconfig.WithBaseEndpoint(cfg.Endpoint))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	clientOpts := []func(*s3.Options){}
	if cfg.ForcePathStyle {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, clientOpts...)
	return newS3Provider(client, cfg.Bucket, cfg.Prefix), nil
}

// newS3Provider creates an S3Provider with the given client (used in tests with s3-mock).
func newS3Provider(client *s3.Client, bucket, prefix string) *S3Provider {
	return &S3Provider{client: client, bucket: bucket, prefix: prefix}
}

func (p *S3Provider) Name() string { return "s3" }

// Upload opens the local file and uploads it to S3.
func (p *S3Provider) Upload(ctx context.Context, localPath string) (string, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return "", fmt.Errorf("open backup file: %w", err)
	}
	defer f.Close()

	key := p.prefix + filepath.Base(localPath)

	_, err = p.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
		Body:   f,
	})
	if err != nil {
		return "", fmt.Errorf("upload to s3://%s/%s: %w", p.bucket, key, err)
	}

	slog.Info("backup uploaded to S3", "bucket", p.bucket, "key", key)
	return key, nil
}

// List returns all backups under the configured prefix, sorted newest-first.
func (p *S3Provider) List(ctx context.Context) ([]BackupInfo, error) {
	var backups []BackupInfo

	paginator := s3.NewListObjectsV2Paginator(p.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(p.bucket),
		Prefix: aws.String(p.prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list S3 objects: %w", err)
		}
		for _, obj := range page.Contents {
			backups = append(backups, BackupInfo{
				Key:          aws.ToString(obj.Key),
				Size:         aws.ToInt64(obj.Size),
				LastModified: aws.ToTime(obj.LastModified),
			})
		}
	}

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].LastModified.After(backups[j].LastModified)
	})

	return backups, nil
}

// Delete removes a single object from S3.
func (p *S3Provider) Delete(ctx context.Context, key string) error {
	_, err := p.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("delete s3://%s/%s: %w", p.bucket, key, err)
	}
	slog.Info("backup deleted from S3", "bucket", p.bucket, "key", key)
	return nil
}
