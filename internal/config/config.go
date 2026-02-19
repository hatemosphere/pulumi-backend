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

	if c.MasterKey == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate master key: %v\n", err)
			os.Exit(1)
		}
		c.MasterKey = hex.EncodeToString(key)
		fmt.Fprintf(os.Stderr, "WARNING: auto-generated master key (secrets will be lost on restart unless you persist this):\n")
		fmt.Fprintf(os.Stderr, "  export PULUMI_BACKEND_MASTER_KEY=%s\n\n", c.MasterKey)
	}
	return c
}

func (c *Config) MasterKeyBytes() ([]byte, error) {
	return hex.DecodeString(c.MasterKey)
}
