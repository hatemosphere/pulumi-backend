package backup

import (
	"strings"
	"testing"
)

func TestResolveDestination_URIParsing(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr string
	}{
		{name: "empty", uri: "", wantErr: "invalid backup destination"},
		{name: "no scheme", uri: "bucket/prefix", wantErr: "invalid backup destination"},
		{name: "empty bucket", uri: "s3:///prefix", wantErr: "empty bucket name"},
		{name: "unsupported scheme", uri: "azure://container/prefix", wantErr: "unsupported backup destination scheme"},
		{name: "scheme only", uri: "s3://", wantErr: "invalid backup destination"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveDestination(t.Context(), tt.uri, S3Options{})
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.wantErr != "" {
				if got := err.Error(); !strings.Contains(got, tt.wantErr) {
					t.Fatalf("error %q should contain %q", got, tt.wantErr)
				}
			}
		})
	}
}

func TestResolveDestination_S3(t *testing.T) {
	// S3 resolution requires AWS credentials — we verify it returns an S3Provider
	// by checking the name. This will fail in environments without AWS config,
	// but the s3-mock tests cover actual operations.
	p, err := ResolveDestination(t.Context(), "s3://my-bucket/my-prefix", S3Options{
		Region: "us-west-2",
	})
	if err != nil {
		t.Fatalf("ResolveDestination: %v", err)
	}
	if p.Name() != "s3" {
		t.Fatalf("expected s3 provider, got %s", p.Name())
	}
}

func TestResolveDestination_DefaultPrefix(t *testing.T) {
	p, err := ResolveDestination(t.Context(), "s3://my-bucket", S3Options{})
	if err != nil {
		t.Fatalf("ResolveDestination: %v", err)
	}
	s3p := p.(*S3Provider)
	if s3p.prefix != "backups/" {
		t.Fatalf("expected default prefix 'backups/', got %q", s3p.prefix)
	}
}

func TestResolveDestination_TrailingSlash(t *testing.T) {
	p, err := ResolveDestination(t.Context(), "s3://my-bucket/custom-prefix", S3Options{})
	if err != nil {
		t.Fatalf("ResolveDestination: %v", err)
	}
	s3p := p.(*S3Provider)
	if s3p.prefix != "custom-prefix/" {
		t.Fatalf("expected 'custom-prefix/', got %q", s3p.prefix)
	}
}
