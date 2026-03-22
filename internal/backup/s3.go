package backup

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Provider implements Provider for S3-compatible storage.
type S3Provider struct {
	client *s3.Client
	bucket string
	prefix string
}

func newS3Provider(ctx context.Context, bucket, prefix string, opts S3Options) (*S3Provider, error) {
	region := opts.Region
	if region == "" {
		region = "us-east-1"
	}

	optFns := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
	}
	if opts.Endpoint != "" {
		optFns = append(optFns, awsconfig.WithBaseEndpoint(opts.Endpoint))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	clientOpts := []func(*s3.Options){}
	if opts.ForcePathStyle {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, clientOpts...)
	return newS3ProviderFromClient(client, bucket, prefix), nil
}

// newS3ProviderFromClient creates an S3Provider with the given client (used in tests with s3-mock).
func newS3ProviderFromClient(client *s3.Client, bucket, prefix string) *S3Provider {
	return &S3Provider{client: client, bucket: bucket, prefix: prefix}
}

// Name implements Provider.
func (p *S3Provider) Name() string { return "s3" }

// Upload implements Provider.
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

// List implements Provider.
func (p *S3Provider) List(ctx context.Context) ([]Info, error) {
	var backups []Info

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
			backups = append(backups, Info{
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

// Delete implements Provider.
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
