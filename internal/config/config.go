package config

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"
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
	BackupDir string // directory for VACUUM INTO backups (empty = disabled)

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
}

func Parse() *Config {
	c := &Config{}
	flag.StringVar(&c.Addr, "addr", ":8080", "listen address")
	flag.StringVar(&c.DBPath, "db", "pulumi-backend.db", "SQLite database path")
	flag.StringVar(&c.MasterKey, "master-key", "", "hex-encoded 32-byte master key for secrets (auto-generated if empty)")
	flag.BoolVar(&c.TLS, "tls", false, "enable TLS")
	flag.StringVar(&c.CertFile, "cert", "", "TLS certificate file")
	flag.StringVar(&c.KeyFile, "key", "", "TLS key file")
	flag.StringVar(&c.DefaultOrg, "org", "organization", "default organization name")
	flag.StringVar(&c.DefaultUser, "user", "admin", "default user name")

	// Tuning flags.
	flag.DurationVar(&c.LeaseDuration, "lease-duration", 5*time.Minute, "update lease TTL")
	flag.IntVar(&c.CacheSize, "cache-size", 256, "LRU cache size for deployment snapshots")
	flag.IntVar(&c.DeltaCutoffBytes, "delta-cutoff", 1024*1024, "checkpoint size threshold for delta mode (bytes)")
	flag.IntVar(&c.HistoryPageSize, "history-page-size", 10, "default page size for update history")
	flag.IntVar(&c.MaxStateVersions, "max-state-versions", 50, "max state versions kept per stack (0 = unlimited)")
	flag.IntVar(&c.StackListPageSize, "stack-list-page-size", 100, "page size for stack listings")

	// Async event flags.
	flag.IntVar(&c.EventBufferSize, "event-buffer-size", 1000, "max buffered events before forced flush")
	flag.DurationVar(&c.EventFlushInterval, "event-flush-interval", time.Second, "periodic event flush interval")

	// Backup flags.
	flag.StringVar(&c.BackupDir, "backup-dir", "", "directory for database backups (empty = disabled)")

	// Secrets provider flags.
	flag.StringVar(&c.SecretsProvider, "secrets-provider", "local", "secrets provider: local or gcpkms")
	flag.StringVar(&c.KMSKeyResourceName, "kms-key", "", "GCP KMS key resource name (required for gcpkms provider)")

	// Auth flags.
	flag.StringVar(&c.AuthMode, "auth-mode", "single-tenant", "authentication mode: single-tenant, google, oidc, or jwt")
	flag.StringVar(&c.GoogleClientID, "google-client-id", "", "Google OAuth2 client ID for JWT verification")
	flag.StringVar(&c.GoogleSAKeyFile, "google-sa-key", "", "optional path to SA JSON key for Admin SDK")
	flag.StringVar(&c.GoogleSAEmail, "google-sa-email", "", "SA email for keyless DWD via IAM impersonation")
	flag.StringVar(&c.GoogleAdminEmail, "google-admin-email", "", "Workspace super-admin email for DWD subject")
	flag.StringVar(&c.GoogleClientSecret, "google-client-secret", "", "Google OAuth2 client secret (required for browser login)")
	flag.StringVar(&c.GoogleAllowedDomains, "google-allowed-domains", "", "comma-separated allowed hosted domains")
	flag.BoolVar(&c.GoogleTransitiveGroups, "google-transitive-groups", false, "resolve nested group memberships")
	flag.DurationVar(&c.TokenTTL, "token-ttl", 24*time.Hour, "backend-issued token lifetime")
	flag.DurationVar(&c.GroupsCacheTTL, "groups-cache-ttl", 5*time.Minute, "group membership cache TTL")
	// Generic OIDC flags.
	flag.StringVar(&c.OIDCIssuer, "oidc-issuer", "", "OIDC provider discovery URL (required for oidc mode)")
	flag.StringVar(&c.OIDCClientID, "oidc-client-id", "", "OIDC OAuth2 client ID")
	flag.StringVar(&c.OIDCClientSecret, "oidc-client-secret", "", "OIDC OAuth2 client secret")
	flag.StringVar(&c.OIDCAllowedDomains, "oidc-allowed-domains", "", "comma-separated allowed email domains")
	flag.StringVar(&c.OIDCScopes, "oidc-scopes", "profile,email", "additional OIDC scopes beyond openid")
	flag.StringVar(&c.OIDCGroupsClaim, "oidc-groups-claim", "groups", "OIDC claim key for group memberships")
	flag.StringVar(&c.OIDCUsernameClaim, "oidc-username-claim", "email", "OIDC claim key for username")
	flag.StringVar(&c.OIDCProviderName, "oidc-provider-name", "SSO", "display name for login page")
	// JWT auth flags.
	flag.StringVar(&c.JWTSigningKey, "jwt-signing-key", "", "HMAC secret or path to PEM public key for JWT verification")
	flag.StringVar(&c.JWTIssuer, "jwt-issuer", "", "expected JWT issuer claim (optional)")
	flag.StringVar(&c.JWTAudience, "jwt-audience", "", "expected JWT audience claim (optional)")
	flag.StringVar(&c.JWTGroupsClaim, "jwt-groups-claim", "groups", "JWT claim name for group memberships")
	flag.StringVar(&c.JWTUsernameClaim, "jwt-username-claim", "sub", "JWT claim for username (sub or email)")
	flag.StringVar(&c.RBACConfigPath, "rbac-config", "", "path to rbac.yaml (empty = all users are admin)")

	// Logging flags.
	flag.StringVar(&c.LogFormat, "log-format", "json", "log format: json or text")
	flag.BoolVar(&c.AuditLogs, "audit-logs", true, "enable structured audit logging")

	flag.Parse()

	// Allow env overrides.
	if v := os.Getenv("PULUMI_BACKEND_ADDR"); v != "" {
		c.Addr = v
	}
	if v := os.Getenv("PULUMI_BACKEND_DB"); v != "" {
		c.DBPath = v
	}
	if v := os.Getenv("PULUMI_BACKEND_MASTER_KEY"); v != "" {
		c.MasterKey = v
	}
	if v := os.Getenv("PULUMI_BACKEND_ORG"); v != "" {
		c.DefaultOrg = v
	}
	if v := os.Getenv("PULUMI_BACKEND_USER"); v != "" {
		c.DefaultUser = v
	}
	if v := os.Getenv("PULUMI_BACKEND_LEASE_DURATION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.LeaseDuration = d
		}
	}
	if v := os.Getenv("PULUMI_BACKEND_CACHE_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.CacheSize = n
		}
	}
	if v := os.Getenv("PULUMI_BACKEND_DELTA_CUTOFF"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.DeltaCutoffBytes = n
		}
	}
	if v := os.Getenv("PULUMI_BACKEND_HISTORY_PAGE_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.HistoryPageSize = n
		}
	}
	if v := os.Getenv("PULUMI_BACKEND_MAX_STATE_VERSIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.MaxStateVersions = n
		}
	}
	if v := os.Getenv("PULUMI_BACKEND_STACK_LIST_PAGE_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.StackListPageSize = n
		}
	}
	if v := os.Getenv("PULUMI_BACKEND_EVENT_BUFFER_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.EventBufferSize = n
		}
	}
	if v := os.Getenv("PULUMI_BACKEND_EVENT_FLUSH_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.EventFlushInterval = d
		}
	}
	if v := os.Getenv("PULUMI_BACKEND_BACKUP_DIR"); v != "" {
		c.BackupDir = v
	}
	if v := os.Getenv("PULUMI_BACKEND_SECRETS_PROVIDER"); v != "" {
		c.SecretsProvider = v
	}
	if v := os.Getenv("PULUMI_BACKEND_KMS_KEY"); v != "" {
		c.KMSKeyResourceName = v
	}
	if v := os.Getenv("PULUMI_BACKEND_AUTH_MODE"); v != "" {
		c.AuthMode = v
	}
	if v := os.Getenv("PULUMI_BACKEND_GOOGLE_CLIENT_ID"); v != "" {
		c.GoogleClientID = v
	}
	if v := os.Getenv("PULUMI_BACKEND_GOOGLE_SA_KEY"); v != "" {
		c.GoogleSAKeyFile = v
	}
	if v := os.Getenv("PULUMI_BACKEND_GOOGLE_SA_EMAIL"); v != "" {
		c.GoogleSAEmail = v
	}
	if v := os.Getenv("PULUMI_BACKEND_GOOGLE_ADMIN_EMAIL"); v != "" {
		c.GoogleAdminEmail = v
	}
	if v := os.Getenv("PULUMI_BACKEND_GOOGLE_CLIENT_SECRET"); v != "" {
		c.GoogleClientSecret = v
	}
	if v := os.Getenv("PULUMI_BACKEND_GOOGLE_ALLOWED_DOMAINS"); v != "" {
		c.GoogleAllowedDomains = v
	}
	if v := os.Getenv("PULUMI_BACKEND_GOOGLE_TRANSITIVE_GROUPS"); v == "true" {
		c.GoogleTransitiveGroups = true
	}
	if v := os.Getenv("PULUMI_BACKEND_TOKEN_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.TokenTTL = d
		}
	}
	if v := os.Getenv("PULUMI_BACKEND_GROUPS_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.GroupsCacheTTL = d
		}
	}
	if v := os.Getenv("PULUMI_BACKEND_OIDC_ISSUER"); v != "" {
		c.OIDCIssuer = v
	}
	if v := os.Getenv("PULUMI_BACKEND_OIDC_CLIENT_ID"); v != "" {
		c.OIDCClientID = v
	}
	if v := os.Getenv("PULUMI_BACKEND_OIDC_CLIENT_SECRET"); v != "" {
		c.OIDCClientSecret = v
	}
	if v := os.Getenv("PULUMI_BACKEND_OIDC_ALLOWED_DOMAINS"); v != "" {
		c.OIDCAllowedDomains = v
	}
	if v := os.Getenv("PULUMI_BACKEND_OIDC_SCOPES"); v != "" {
		c.OIDCScopes = v
	}
	if v := os.Getenv("PULUMI_BACKEND_OIDC_GROUPS_CLAIM"); v != "" {
		c.OIDCGroupsClaim = v
	}
	if v := os.Getenv("PULUMI_BACKEND_OIDC_USERNAME_CLAIM"); v != "" {
		c.OIDCUsernameClaim = v
	}
	if v := os.Getenv("PULUMI_BACKEND_OIDC_PROVIDER_NAME"); v != "" {
		c.OIDCProviderName = v
	}
	if v := os.Getenv("PULUMI_BACKEND_JWT_SIGNING_KEY"); v != "" {
		c.JWTSigningKey = v
	}
	if v := os.Getenv("PULUMI_BACKEND_JWT_ISSUER"); v != "" {
		c.JWTIssuer = v
	}
	if v := os.Getenv("PULUMI_BACKEND_JWT_AUDIENCE"); v != "" {
		c.JWTAudience = v
	}
	if v := os.Getenv("PULUMI_BACKEND_JWT_GROUPS_CLAIM"); v != "" {
		c.JWTGroupsClaim = v
	}
	if v := os.Getenv("PULUMI_BACKEND_JWT_USERNAME_CLAIM"); v != "" {
		c.JWTUsernameClaim = v
	}
	if v := os.Getenv("PULUMI_BACKEND_RBAC_CONFIG"); v != "" {
		c.RBACConfigPath = v
	}
	if v := os.Getenv("PULUMI_BACKEND_LOG_FORMAT"); v != "" {
		c.LogFormat = v
	}
	if v := os.Getenv("PULUMI_BACKEND_AUDIT_LOGS"); v == "false" {
		c.AuditLogs = false
	}

	if c.MasterKey == "" && c.SecretsProvider == "local" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate master key: %v\n", err)
			os.Exit(1)
		}
		c.MasterKey = hex.EncodeToString(key)
		fmt.Fprintf(os.Stderr, "WARNING: auto-generated master key (will not survive restart unless you persist it):\n")
		fmt.Fprintf(os.Stderr, "  export PULUMI_BACKEND_MASTER_KEY=%s\n\n", c.MasterKey)
	}

	return c
}

func (c *Config) MasterKeyBytes() ([]byte, error) {
	return hex.DecodeString(c.MasterKey)
}
