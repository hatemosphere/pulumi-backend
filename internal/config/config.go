package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	ff "github.com/peterbourgon/ff/v3"
)

// Config holds all server configuration.
type Config struct {
	Addr      string // listen address, e.g. ":8080"
	DBPath    string // path to SQLite database file
	MasterKey string // hex-encoded 32-byte master key for secrets encryption
	TLS       bool
	CertFile  string
	KeyFile   string
	// Default user/org when running in single-tenant mode.
	DefaultOrg  string
	DefaultUser string

	// Tuning.
	LeaseDuration     time.Duration // update lease TTL
	CacheSize         int           // LRU cache entries for deployment snapshots
	DeltaCutoffBytes  int           // checkpoint size threshold for delta mode
	HistoryPageSize   int           // default page size for update history
	MaxStateVersions  int           // max state versions kept per stack (0 = unlimited)
	StackListPageSize int           // page size for stack listings

	// Async event buffering.
	EventBufferSize    int           // max buffered events before forced flush
	EventFlushInterval time.Duration // periodic flush interval

	// Backup.
	BackupDir              string        // directory for VACUUM INTO backups (empty = disabled)
	BackupS3Bucket         string        // S3 bucket for remote backups (empty = disabled)
	BackupS3Region         string        // AWS region (default: us-east-1)
	BackupS3Endpoint       string        // custom S3 endpoint URL (MinIO, R2, B2)
	BackupS3Prefix         string        // key prefix in S3 bucket (default: "backups/")
	BackupS3ForcePathStyle bool          // force path-style S3 addressing (for MinIO)
	BackupSchedule         time.Duration // periodic backup interval (0 = disabled)
	BackupRetention        int           // number of backups to keep per destination (0 = unlimited)

	// Secrets provider: "local" (default) or "gcpkms".
	SecretsProvider string
	// GCP KMS key resource name (required when SecretsProvider == "gcpkms").
	KMSKeyResourceName string

	// Auth mode: "single-tenant" (default), "google", "oidc", or "jwt".
	AuthMode string
	// Google auth settings (required when AuthMode == "google").
	GoogleClientID         string        // OAuth2 client ID for JWT audience verification
	GoogleSAKeyFile        string        // Optional path to SA JSON key for Admin SDK
	GoogleSAEmail          string        // SA email for keyless DWD via IAM impersonation
	GoogleAdminEmail       string        // Workspace super-admin email for DWD subject
	GoogleClientSecret     string        // OAuth2 client secret (for browser login flow)
	GoogleAllowedDomains   string        // Comma-separated allowed hosted domains
	GoogleTransitiveGroups bool          // Resolve nested group memberships
	TokenTTL               time.Duration // Backend-issued token lifetime
	GroupsCacheTTL         time.Duration // Group membership cache TTL
	// Generic OIDC settings (required when AuthMode == "oidc").
	OIDCIssuer         string // OIDC provider discovery URL
	OIDCClientID       string // OAuth2 client ID
	OIDCClientSecret   string // OAuth2 client secret
	OIDCAllowedDomains string // Comma-separated allowed email domains
	OIDCScopes         string // Additional scopes (default: "profile,email")
	OIDCGroupsClaim    string // Claim key for groups (default: "groups")
	OIDCUsernameClaim  string // Claim key for username (default: "email")
	OIDCProviderName   string // Display name for login page (default: "SSO")
	// JWT auth settings (required when AuthMode == "jwt").
	JWTSigningKey    string // HMAC secret string or path to PEM public key file
	JWTIssuer        string // Expected JWT issuer (optional)
	JWTAudience      string // Expected JWT audience (optional)
	JWTGroupsClaim   string // JWT claim name for groups (default: "groups")
	JWTUsernameClaim string // JWT claim for username (default: "sub")

	// RBAC config file path (empty = no RBAC enforcement, all users are admin).
	RBACConfigPath string

	// Logging.
	LogFormat string // "json" (default) or "text"
	AuditLogs bool   // enable audit logging (default true)

	// Security.
	TrustedProxies string // comma-separated CIDRs for trusted proxy validation

	// Public URL for redirect URI construction (mitigates Host header poisoning).
	PublicURL string

	// Profiling.
	PprofEnabled bool // enable pprof endpoints at /debug/pprof/

	// Secrets key migration (re-wrap DEKs from old to new provider, then exit).
	MigrateSecretsKey  bool   // --migrate-secrets-key
	OldSecretsProvider string // --old-secrets-provider (local or gcpkms)
	OldMasterKey       string // --old-master-key (hex key for old local provider)
	OldKMSKey          string // --old-kms-key (KMS resource name for old provider)
}

func Parse() *Config {
	c := &Config{}
	fs := flag.NewFlagSet("pulumi-backend", flag.ExitOnError)

	// Core flags.
	fs.StringVar(&c.Addr, "addr", ":8080", "listen address")
	fs.StringVar(&c.DBPath, "db", "pulumi-backend.db", "SQLite database path")
	fs.StringVar(&c.MasterKey, "master-key", "", "hex-encoded 32-byte master key for secrets (auto-generated if empty)")
	fs.BoolVar(&c.TLS, "tls", false, "enable TLS")
	fs.StringVar(&c.CertFile, "cert", "", "TLS certificate file")
	fs.StringVar(&c.KeyFile, "key", "", "TLS key file")
	fs.StringVar(&c.DefaultOrg, "org", "organization", "default organization name")
	fs.StringVar(&c.DefaultUser, "user", "admin", "default user name")

	// Tuning flags.
	fs.DurationVar(&c.LeaseDuration, "lease-duration", 5*time.Minute, "update lease TTL")
	fs.IntVar(&c.CacheSize, "cache-size", 256, "LRU cache size for deployment snapshots")
	fs.IntVar(&c.DeltaCutoffBytes, "delta-cutoff", 1024*1024, "checkpoint size threshold for delta mode (bytes)")
	fs.IntVar(&c.HistoryPageSize, "history-page-size", 10, "default page size for update history")
	fs.IntVar(&c.MaxStateVersions, "max-state-versions", 50, "max state versions kept per stack (0 = unlimited)")
	fs.IntVar(&c.StackListPageSize, "stack-list-page-size", 100, "page size for stack listings")

	// Async event flags.
	fs.IntVar(&c.EventBufferSize, "event-buffer-size", 1000, "max buffered events before forced flush")
	fs.DurationVar(&c.EventFlushInterval, "event-flush-interval", time.Second, "periodic event flush interval")

	// Backup flags.
	fs.StringVar(&c.BackupDir, "backup-dir", "", "directory for database backups (empty = disabled)")
	fs.StringVar(&c.BackupS3Bucket, "backup-s3-bucket", "", "S3 bucket for remote backups (empty = disabled)")
	fs.StringVar(&c.BackupS3Region, "backup-s3-region", "us-east-1", "AWS region for S3 backups")
	fs.StringVar(&c.BackupS3Endpoint, "backup-s3-endpoint", "", "custom S3 endpoint URL (for MinIO, R2, etc.)")
	fs.StringVar(&c.BackupS3Prefix, "backup-s3-prefix", "backups/", "key prefix in S3 bucket")
	fs.BoolVar(&c.BackupS3ForcePathStyle, "backup-s3-force-path-style", false, "force path-style S3 addressing (for MinIO)")
	fs.DurationVar(&c.BackupSchedule, "backup-schedule", 0, "periodic backup interval (e.g., 6h, 24h; 0 = disabled)")
	fs.IntVar(&c.BackupRetention, "backup-retention", 0, "number of backups to keep per destination (0 = unlimited)")

	// Secrets provider flags.
	fs.StringVar(&c.SecretsProvider, "secrets-provider", "local", "secrets provider: local or gcpkms")
	fs.StringVar(&c.KMSKeyResourceName, "kms-key", "", "GCP KMS key resource name (required for gcpkms provider)")

	// Auth flags.
	fs.StringVar(&c.AuthMode, "auth-mode", "single-tenant", "authentication mode: single-tenant, google, oidc, or jwt")
	fs.StringVar(&c.GoogleClientID, "google-client-id", "", "Google OAuth2 client ID for JWT verification")
	fs.StringVar(&c.GoogleSAKeyFile, "google-sa-key", "", "optional path to SA JSON key for Admin SDK")
	fs.StringVar(&c.GoogleSAEmail, "google-sa-email", "", "SA email for keyless DWD via IAM impersonation")
	fs.StringVar(&c.GoogleAdminEmail, "google-admin-email", "", "Workspace super-admin email for DWD subject")
	fs.StringVar(&c.GoogleClientSecret, "google-client-secret", "", "Google OAuth2 client secret (required for browser login)")
	fs.StringVar(&c.GoogleAllowedDomains, "google-allowed-domains", "", "comma-separated allowed hosted domains")
	fs.BoolVar(&c.GoogleTransitiveGroups, "google-transitive-groups", false, "resolve nested group memberships")
	fs.DurationVar(&c.TokenTTL, "token-ttl", 24*time.Hour, "backend-issued token lifetime")
	fs.DurationVar(&c.GroupsCacheTTL, "groups-cache-ttl", 5*time.Minute, "group membership cache TTL")
	// Generic OIDC flags.
	fs.StringVar(&c.OIDCIssuer, "oidc-issuer", "", "OIDC provider discovery URL (required for oidc mode)")
	fs.StringVar(&c.OIDCClientID, "oidc-client-id", "", "OIDC OAuth2 client ID")
	fs.StringVar(&c.OIDCClientSecret, "oidc-client-secret", "", "OIDC OAuth2 client secret")
	fs.StringVar(&c.OIDCAllowedDomains, "oidc-allowed-domains", "", "comma-separated allowed email domains")
	fs.StringVar(&c.OIDCScopes, "oidc-scopes", "profile,email", "additional OIDC scopes beyond openid")
	fs.StringVar(&c.OIDCGroupsClaim, "oidc-groups-claim", "groups", "OIDC claim key for group memberships")
	fs.StringVar(&c.OIDCUsernameClaim, "oidc-username-claim", "email", "OIDC claim key for username")
	fs.StringVar(&c.OIDCProviderName, "oidc-provider-name", "SSO", "display name for login page")
	// JWT auth flags.
	fs.StringVar(&c.JWTSigningKey, "jwt-signing-key", "", "HMAC secret or path to PEM public key for JWT verification")
	fs.StringVar(&c.JWTIssuer, "jwt-issuer", "", "expected JWT issuer claim (optional)")
	fs.StringVar(&c.JWTAudience, "jwt-audience", "", "expected JWT audience claim (optional)")
	fs.StringVar(&c.JWTGroupsClaim, "jwt-groups-claim", "groups", "JWT claim name for group memberships")
	fs.StringVar(&c.JWTUsernameClaim, "jwt-username-claim", "sub", "JWT claim for username (sub or email)")
	fs.StringVar(&c.RBACConfigPath, "rbac-config", "", "path to rbac.yaml (empty = all users are admin)")

	// Logging flags.
	fs.StringVar(&c.LogFormat, "log-format", "json", "log format: json or text")
	fs.BoolVar(&c.AuditLogs, "audit-logs", true, "enable structured audit logging")

	// Security flags.
	fs.StringVar(&c.TrustedProxies, "trusted-proxies", "", "comma-separated CIDRs for trusted proxy validation (empty = trust all)")

	// Public URL flag.
	fs.StringVar(&c.PublicURL, "public-url", "", "public base URL for redirect URIs (e.g. https://pulumi.example.com)")

	// Profiling flags.
	fs.BoolVar(&c.PprofEnabled, "pprof", false, "enable pprof profiling endpoints at /debug/pprof/")

	// Secrets key migration flags.
	fs.BoolVar(&c.MigrateSecretsKey, "migrate-secrets-key", false, "re-wrap all DEKs from old to new provider, then exit")
	fs.StringVar(&c.OldSecretsProvider, "old-secrets-provider", "", "previous secrets provider: local or gcpkms (for --migrate-secrets-key)")
	fs.StringVar(&c.OldMasterKey, "old-master-key", "", "previous hex-encoded master key (for --migrate-secrets-key with local)")
	fs.StringVar(&c.OldKMSKey, "old-kms-key", "", "previous GCP KMS key resource name (for --migrate-secrets-key with gcpkms)")

	// Parse flags and env vars (flag > env > default).
	if err := ff.Parse(fs, os.Args[1:], ff.WithEnvVarPrefix("PULUMI_BACKEND")); err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(1)
	}

	// Auto-generate master key if not provided (local secrets provider only, non-migration mode).
	if c.MasterKey == "" && c.SecretsProvider == "local" && !c.MigrateSecretsKey {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate master key: %v\n", err)
			os.Exit(1)
		}
		c.MasterKey = hex.EncodeToString(key)
		h := sha256.Sum256([]byte(c.MasterKey))
		fmt.Fprintf(os.Stderr, "WARNING: auto-generated master key (fingerprint: %s). Will not survive restart.\n", hex.EncodeToString(h[:8]))
		fmt.Fprintf(os.Stderr, "  Set PULUMI_BACKEND_MASTER_KEY to persist it.\n\n")
	}

	return c
}

func (c *Config) MasterKeyBytes() ([]byte, error) {
	return hex.DecodeString(c.MasterKey)
}
