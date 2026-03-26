package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/segmentio/encoding/json"

	"github.com/XSAM/otelsql"
	sqlitedriver "github.com/ncruces/go-sqlite3/driver"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/hatemosphere/pulumi-backend/internal/gziputil"
)

// EmptyDeployment is the canonical JSON for a stack with no state.
var EmptyDeployment = []byte(`{"version":3,"deployment":{"manifest":{"time":"0001-01-01T00:00:00Z","magic":"","version":""},"resources":null}}`)

// Ping checks database connectivity.
func (s *SQLiteStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func unixToTimePtr(v *int64) *time.Time {
	if v == nil {
		return nil
	}
	t := time.Unix(*v, 0)
	return &t
}

func nullUnixToTimePtr(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(v.Int64, 0)
	return &t
}

const defaultMaxStateVersions = 50

// SQLiteStoreConfig holds tuning parameters for SQLiteStore.
type SQLiteStoreConfig struct {
	MaxStateVersions  int // 0 = default (50), -1 = unlimited
	StackListPageSize int // 0 = default (100)
}

// TokenEncryptor encrypts and decrypts refresh tokens at rest.
// Encryption uses AES-256-GCM; the ciphertext is stored as hex in the TEXT column.
type TokenEncryptor struct {
	seal func(plaintext []byte) ([]byte, error)
	open func(ciphertext []byte) ([]byte, error)
}

// NewTokenEncryptor creates an encryptor from seal/open functions (typically aesGCMSeal/aesGCMOpen).
func NewTokenEncryptor(seal func([]byte) ([]byte, error), open func([]byte) ([]byte, error)) *TokenEncryptor {
	return &TokenEncryptor{seal: seal, open: open}
}

// SQLiteStore implements Store using SQLite.
type SQLiteStore struct {
	db                *sql.DB
	dsn               string
	maxStateVersions  int
	stackListPageSize int
	tokenEncryptor    *TokenEncryptor
}

// NewSQLiteStore opens or creates a SQLite database at the given path.
func NewSQLiteStore(path string, cfgs ...SQLiteStoreConfig) (*SQLiteStore, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=synchronous(normal)&_pragma=foreign_keys(on)"
	db, err := otelsql.Open("sqlite3", dsn,
		otelsql.WithAttributes(semconv.DBSystemSqlite),
		otelsql.WithSpanOptions(otelsql.SpanOptions{DisableErrSkip: true}),
	)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	maxVer := defaultMaxStateVersions
	pageSize := 100
	if len(cfgs) > 0 {
		cfg := cfgs[0]
		if cfg.MaxStateVersions > 0 {
			maxVer = cfg.MaxStateVersions
		} else if cfg.MaxStateVersions < 0 {
			maxVer = 0 // unlimited
		}
		if cfg.StackListPageSize > 0 {
			pageSize = cfg.StackListPageSize
		}
	}

	s := &SQLiteStore{db: db, dsn: dsn, maxStateVersions: maxVer, stackListPageSize: pageSize}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := s.enableChecksums(); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable checksums: %w", err)
	}
	return s, nil
}

// rawConn opens a direct (non-otelsql) connection for operations that need
// the ncruces driver.Conn interface (backup API, checksums).
func (s *SQLiteStore) rawConn(ctx context.Context, fn func(sqlitedriver.Conn) error) error {
	db, err := sql.Open("sqlite3", s.dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	return conn.Raw(func(driverConn any) error {
		return fn(driverConn.(sqlitedriver.Conn))
	})
}

// enableChecksums enables per-page checksums for corruption detection.
// This is a one-time operation that VACUUMs the database on first enablement.
func (s *SQLiteStore) enableChecksums() error {
	return s.rawConn(context.Background(), func(c sqlitedriver.Conn) error {
		return c.Raw().EnableChecksums("main")
	})
}

// SetTokenEncryptor enables at-rest encryption for refresh tokens.
// Must be called before any token operations. Not safe for concurrent use during setup.
func (s *SQLiteStore) SetTokenEncryptor(enc *TokenEncryptor) {
	s.tokenEncryptor = enc
}

// encryptRefreshToken encrypts a refresh token for storage. Returns empty string if input is empty.
func (s *SQLiteStore) encryptRefreshToken(plaintext string) (string, error) {
	if plaintext == "" || s.tokenEncryptor == nil {
		return plaintext, nil
	}
	ct, err := s.tokenEncryptor.seal([]byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("encrypt refresh token: %w", err)
	}
	return hex.EncodeToString(ct), nil
}

// decryptRefreshToken decrypts a stored refresh token. Returns empty string if input is empty.
func (s *SQLiteStore) decryptRefreshToken(stored string) (string, error) {
	if stored == "" || s.tokenEncryptor == nil {
		return stored, nil
	}
	ct, err := hex.DecodeString(stored)
	if err != nil {
		return "", fmt.Errorf("decode refresh token: %w", err)
	}
	pt, err := s.tokenEncryptor.open(ct)
	if err != nil {
		return "", fmt.Errorf("decrypt refresh token: %w", err)
	}
	return string(pt), nil
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// DB returns the underlying *sql.DB for test access. Do not use in production code.
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

// Backup creates a consistent database backup at destPath.
func (s *SQLiteStore) Backup(ctx context.Context, destPath string) error {
	return s.rawConn(ctx, func(c sqlitedriver.Conn) error {
		return c.Raw().Backup("main", "file:"+destPath)
	})
}

// --- Server config ---

// GetConfig returns a server config value by key.
func (s *SQLiteStore) GetConfig(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM server_config WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

// SetConfig stores a server config key-value pair.
func (s *SQLiteStore) SetConfig(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO server_config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	return err
}

// DeleteConfig removes a server config entry.
func (s *SQLiteStore) DeleteConfig(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM server_config WHERE key = ?`, key)
	return err
}

func (s *SQLiteStore) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Additive migrations for existing databases.
	for _, m := range []string{
		`ALTER TABLE stacks ADD COLUMN resource_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE tokens ADD COLUMN refresh_token TEXT DEFAULT ''`,
		`ALTER TABLE tokens ADD COLUMN groups TEXT DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_name)`,
	} {
		_, _ = s.db.Exec(m) // Ignore "duplicate column" errors.
	}
	return nil
}

const schema = `
CREATE TABLE IF NOT EXISTS organizations (
    name TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    org_name TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (org_name, name)
);

CREATE TABLE IF NOT EXISTS stacks (
    org_name TEXT NOT NULL,
    project_name TEXT NOT NULL,
    name TEXT NOT NULL,
    tags TEXT DEFAULT '{}',
    current_version INTEGER NOT NULL DEFAULT 0,
    resource_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (org_name, project_name, name)
);

CREATE TABLE IF NOT EXISTS stack_state (
    org_name TEXT NOT NULL,
    project_name TEXT NOT NULL,
    stack_name TEXT NOT NULL,
    version INTEGER NOT NULL,
    deployment BLOB NOT NULL,
    deployment_hash TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    PRIMARY KEY (org_name, project_name, stack_name, version)
);

CREATE TABLE IF NOT EXISTS updates (
    id TEXT PRIMARY KEY,
    org_name TEXT NOT NULL,
    project_name TEXT NOT NULL,
    stack_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'not-started',
    version INTEGER NOT NULL DEFAULT 0,
    config TEXT DEFAULT '{}',
    metadata TEXT DEFAULT '{}',
    token TEXT NOT NULL DEFAULT '',
    token_expires_at INTEGER NOT NULL DEFAULT 0,
    journal_version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    result TEXT
);

CREATE TABLE IF NOT EXISTS journal_entries (
    update_id TEXT NOT NULL,
    sequence_id INTEGER NOT NULL,
    entry BLOB NOT NULL,
    PRIMARY KEY (update_id, sequence_id)
);

CREATE TABLE IF NOT EXISTS engine_events (
    update_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    event BLOB NOT NULL,
    PRIMARY KEY (update_id, sequence)
);

CREATE TABLE IF NOT EXISTS update_history (
    org_name TEXT NOT NULL,
    project_name TEXT NOT NULL,
    stack_name TEXT NOT NULL,
    version INTEGER NOT NULL,
    update_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT DEFAULT '',
    environment TEXT DEFAULT '{}',
    config TEXT DEFAULT '{}',
    start_time INTEGER NOT NULL,
    end_time INTEGER,
    resource_changes TEXT DEFAULT '{}',
    PRIMARY KEY (org_name, project_name, stack_name, version)
);

CREATE TABLE IF NOT EXISTS secrets_keys (
    org_name TEXT NOT NULL,
    project_name TEXT NOT NULL,
    stack_name TEXT NOT NULL,
    encryption_key BLOB NOT NULL,
    PRIMARY KEY (org_name, project_name, stack_name)
);

CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    user_name TEXT NOT NULL,
    description TEXT DEFAULT '',
    refresh_token TEXT DEFAULT '',
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS server_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_updates_stack ON updates(org_name, project_name, stack_name);
CREATE INDEX IF NOT EXISTS idx_updates_active ON updates(org_name, project_name, stack_name, status) WHERE status IN ('not-started', 'in-progress');
CREATE INDEX IF NOT EXISTS idx_history_stack ON update_history(org_name, project_name, stack_name, version DESC);
`

// --- Stacks ---

// CreateStack creates a new stack record.
func (s *SQLiteStore) CreateStack(ctx context.Context, st *Stack) error {
	now := time.Now().Unix()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	// Ensure org exists.
	_, err = tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO organizations (name, created_at) VALUES (?, ?)`,
		st.OrgName, now)
	if err != nil {
		return err
	}

	// Ensure project exists.
	_, err = tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO projects (org_name, name, created_at) VALUES (?, ?, ?)`,
		st.OrgName, st.ProjectName, now)
	if err != nil {
		return err
	}

	tagsJSON, err := json.Marshal(st.Tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO stacks (org_name, project_name, name, tags, current_version, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 0, ?, ?)`,
		st.OrgName, st.ProjectName, st.StackName, string(tagsJSON), now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("%w: %s/%s/%s", ErrStackAlreadyExists, st.OrgName, st.ProjectName, st.StackName)
		}
		return fmt.Errorf("create stack: %w", err)
	}

	return tx.Commit()
}

// GetStack returns a stack by org, project, and name.
func (s *SQLiteStore) GetStack(ctx context.Context, org, project, stack string) (*Stack, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT org_name, project_name, name, tags, current_version, resource_count, created_at, updated_at
		 FROM stacks WHERE org_name=? AND project_name=? AND name=?`,
		org, project, stack)

	st := &Stack{}
	var tagsJSON string
	var createdAt, updatedAt int64
	err := row.Scan(&st.OrgName, &st.ProjectName, &st.StackName, &tagsJSON, &st.Version, &st.ResourceCount, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	st.CreatedAt = time.Unix(createdAt, 0)
	st.UpdatedAt = time.Unix(updatedAt, 0)
	if err := json.Unmarshal([]byte(tagsJSON), &st.Tags); err != nil {
		slog.Warn("failed to unmarshal stack tags", "org", st.OrgName, "project", st.ProjectName, "stack", st.StackName, "error", err)
	}
	if st.Tags == nil {
		st.Tags = map[string]string{}
	}
	return st, nil
}

// execAllTx executes each query in order within the given transaction, passing the same args to each.
func execAllTx(ctx context.Context, tx *sql.Tx, queries []string, args ...any) error {
	for _, q := range queries {
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return err
		}
	}
	return nil
}

// DeleteStack removes a stack and all its associated data.
func (s *SQLiteStore) DeleteStack(ctx context.Context, org, project, stack string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	// Delete in dependency order.
	for _, table := range []string{"journal_entries", "engine_events"} {
		_, err = tx.ExecContext(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE update_id IN (SELECT id FROM updates WHERE org_name=? AND project_name=? AND stack_name=?)`, table),
			org, project, stack)
		if err != nil {
			return err
		}
	}
	if err = execAllTx(ctx, tx, []string{
		`DELETE FROM updates WHERE org_name=? AND project_name=? AND stack_name=?`,
		`DELETE FROM update_history WHERE org_name=? AND project_name=? AND stack_name=?`,
		`DELETE FROM stack_state WHERE org_name=? AND project_name=? AND stack_name=?`,
		`DELETE FROM secrets_keys WHERE org_name=? AND project_name=? AND stack_name=?`,
		`DELETE FROM stacks WHERE org_name=? AND project_name=? AND name=?`,
	}, org, project, stack); err != nil {
		return err
	}
	return tx.Commit()
}

// buildListStacksQuery constructs the SQL query and arguments for ListStacks
// based on the provided filters and continuation token.
func buildListStacksQuery(org, project, continuationToken string, pageSize int) (string, []any) {
	var filters []string
	var args []any

	if org != "" {
		filters = append(filters, "org_name=?")
		args = append(args, org)
	}
	if project != "" {
		filters = append(filters, "project_name=?")
		args = append(args, project)
	}
	if continuationToken != "" {
		filters = append(filters, "(org_name, project_name, name) > (?, ?, ?)")
		parts := splitToken(continuationToken)
		args = append(args, parts[0], parts[1], parts[2])
	}

	query := `SELECT org_name, project_name, name, tags, current_version, resource_count, created_at, updated_at FROM stacks`
	if len(filters) > 0 {
		query += " WHERE " + strings.Join(filters, " AND ")
	}
	query += ` ORDER BY org_name, project_name, name LIMIT ?`
	args = append(args, pageSize)
	return query, args
}

// ListStacks returns a paginated list of stacks with optional org/project filters.
func (s *SQLiteStore) ListStacks(ctx context.Context, org, project string, continuationToken string) ([]Stack, string, error) {
	query, args := buildListStacksQuery(org, project, continuationToken, s.stackListPageSize+1)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var stacks []Stack
	for rows.Next() {
		var st Stack
		var tagsJSON string
		var createdAt, updatedAt int64
		if err := rows.Scan(&st.OrgName, &st.ProjectName, &st.StackName, &tagsJSON, &st.Version, &st.ResourceCount, &createdAt, &updatedAt); err != nil {
			return nil, "", err
		}
		st.CreatedAt = time.Unix(createdAt, 0)
		st.UpdatedAt = time.Unix(updatedAt, 0)
		if err := json.Unmarshal([]byte(tagsJSON), &st.Tags); err != nil {
			slog.Warn("failed to unmarshal stack tags", "org", st.OrgName, "project", st.ProjectName, "stack", st.StackName, "error", err)
		}
		if st.Tags == nil {
			st.Tags = map[string]string{}
		}
		stacks = append(stacks, st)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}

	var nextToken string
	if len(stacks) > s.stackListPageSize {
		last := stacks[s.stackListPageSize-1]
		nextToken = last.OrgName + "/" + last.ProjectName + "/" + last.StackName
		stacks = stacks[:s.stackListPageSize]
	}
	return stacks, nextToken, nil
}

func splitToken(token string) []string {
	parts := strings.SplitN(token, "/", 3)
	// Pad if necessary
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	return parts
}

// UpdateStackTags replaces the tags for a stack.
func (s *SQLiteStore) UpdateStackTags(ctx context.Context, org, project, stack string, tags map[string]string) error {
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE stacks SET tags=?, updated_at=? WHERE org_name=? AND project_name=? AND name=?`,
		string(tagsJSON), time.Now().Unix(), org, project, stack)
	return err
}

// RenameStack renames a stack and cascades the change to related tables.
func (s *SQLiteStore) RenameStack(ctx context.Context, org, oldProject, oldName, newProject, newName string) error {
	now := time.Now().Unix()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	// Update stack name and project.
	_, err = tx.ExecContext(ctx,
		`UPDATE stacks SET project_name=?, name=?, updated_at=? WHERE org_name=? AND project_name=? AND name=?`,
		newProject, newName, now, org, oldProject, oldName)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("%w: %s/%s/%s", ErrStackAlreadyExists, org, newProject, newName)
		}
		return fmt.Errorf("rename stack: %w", err)
	}

	// Cascade to related tables.
	if err = execAllTx(ctx, tx, []string{
		`UPDATE stack_state SET project_name=?, stack_name=? WHERE org_name=? AND project_name=? AND stack_name=?`,
		`UPDATE updates SET project_name=?, stack_name=? WHERE org_name=? AND project_name=? AND stack_name=?`,
		`UPDATE update_history SET project_name=?, stack_name=? WHERE org_name=? AND project_name=? AND stack_name=?`,
		`UPDATE secrets_keys SET project_name=?, stack_name=? WHERE org_name=? AND project_name=? AND stack_name=?`,
	}, newProject, newName, org, oldProject, oldName); err != nil {
		return err
	}

	return tx.Commit()
}

// ProjectExists reports whether any stacks exist under the given org/project.
func (s *SQLiteStore) ProjectExists(ctx context.Context, org, project string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM stacks WHERE org_name=? AND project_name=?`,
		org, project).Scan(&count)
	return count > 0, err
}

// --- Stack State ---

// GetCurrentState returns the latest deployment state for a stack.
func (s *SQLiteStore) GetCurrentState(ctx context.Context, org, project, stack string) (*StackState, error) {
	var version int
	err := s.db.QueryRowContext(ctx,
		`SELECT current_version FROM stacks WHERE org_name=? AND project_name=? AND name=?`,
		org, project, stack).Scan(&version)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if version == 0 {
		return &StackState{
			OrgName: org, ProjectName: project, StackName: stack,
			Version: 0, Deployment: EmptyDeployment,
		}, nil
	}
	return s.GetStateVersion(ctx, org, project, stack, version)
}

// GetStateVersion returns a specific version of a stack's deployment state.
func (s *SQLiteStore) GetStateVersion(ctx context.Context, org, project, stack string, version int) (*StackState, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT org_name, project_name, stack_name, version, deployment, deployment_hash, created_at
		 FROM stack_state WHERE org_name=? AND project_name=? AND stack_name=? AND version=?`,
		org, project, stack, version)

	st := &StackState{}
	var createdAt int64
	err := row.Scan(&st.OrgName, &st.ProjectName, &st.StackName, &st.Version, &st.Deployment, &st.Hash, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Transparently decompress if needed.
	st.Deployment, err = gziputil.MaybeDecompress(st.Deployment)
	if err != nil {
		return nil, fmt.Errorf("decompress deployment: %w", err)
	}

	st.CreatedAt = time.Unix(createdAt, 0)
	return st, nil
}

// GetStateVersionRaw returns the raw deployment bytes from SQLite without decompression.
func (s *SQLiteStore) GetStateVersionRaw(ctx context.Context, org, project, stack string, version int) ([]byte, bool, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT deployment FROM stack_state WHERE org_name=? AND project_name=? AND stack_name=? AND version=?`,
		org, project, stack, version).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	isCompressed := gziputil.IsGzipped(data)
	return data, isCompressed, nil
}

// GetCurrentStateRaw returns the current state's raw deployment bytes without decompression.
func (s *SQLiteStore) GetCurrentStateRaw(ctx context.Context, org, project, stack string) ([]byte, int, bool, error) {
	var version int
	err := s.db.QueryRowContext(ctx,
		`SELECT current_version FROM stacks WHERE org_name=? AND project_name=? AND name=?`,
		org, project, stack).Scan(&version)
	if err == sql.ErrNoRows {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	if version == 0 {
		return EmptyDeployment, 0, false, nil
	}
	data, isCompressed, err := s.GetStateVersionRaw(ctx, org, project, stack, version)
	return data, version, isCompressed, err
}

// SaveState persists a deployment state version and updates the stack's current version.
func (s *SQLiteStore) SaveState(ctx context.Context, state *StackState) error {
	now := time.Now().Unix()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	// Check if already compressed.
	var compressedDeployment []byte
	if gziputil.IsGzipped(state.Deployment) {
		compressedDeployment = state.Deployment
	} else {
		var compErr error
		compressedDeployment, compErr = gziputil.Compress(state.Deployment)
		if compErr != nil {
			return fmt.Errorf("compress deployment: %w", compErr)
		}
	}

	_, err = tx.ExecContext(ctx,
		`INSERT OR REPLACE INTO stack_state (org_name, project_name, stack_name, version, deployment, deployment_hash, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		state.OrgName, state.ProjectName, state.StackName, state.Version, compressedDeployment, state.Hash, now)
	if err != nil {
		return err
	}

	// Use pre-computed resource count from engine layer (avoids decompressing).
	resourceCount := state.ResourceCount

	_, err = tx.ExecContext(ctx,
		`UPDATE stacks SET current_version=?, resource_count=?, updated_at=? WHERE org_name=? AND project_name=? AND name=? AND current_version<?`,
		state.Version, resourceCount, now, state.OrgName, state.ProjectName, state.StackName, state.Version)
	if err != nil {
		return err
	}

	// Prune old state versions, keeping only the most recent N.
	if s.maxStateVersions > 0 {
		_, err = tx.ExecContext(ctx,
			`DELETE FROM stack_state WHERE org_name=? AND project_name=? AND stack_name=? AND version NOT IN (
				SELECT version FROM stack_state WHERE org_name=? AND project_name=? AND stack_name=?
				ORDER BY version DESC LIMIT ?
			)`,
			state.OrgName, state.ProjectName, state.StackName,
			state.OrgName, state.ProjectName, state.StackName,
			s.maxStateVersions)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// CountResources extracts the resource count from uncompressed deployment JSON.
// CountResources counts resources in a deployment JSON without unmarshaling.
// Scans for "resources":[ and counts top-level objects by tracking brace depth.
func CountResources(deployment []byte) int {
	// Find "resources":[
	key := []byte(`"resources":[`)
	idx := bytes.Index(deployment, key)
	if idx < 0 {
		return 0
	}
	pos := idx + len(key)

	count := 0
	depth := 0
	inString := false
	escaped := false

	for pos < len(deployment) {
		b := deployment[pos]
		pos++

		if escaped {
			escaped = false
			continue
		}
		if b == '\\' && inString {
			escaped = true
			continue
		}
		if b == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}

		switch b {
		case '{':
			if depth == 0 {
				count++
			}
			depth++
		case '}':
			depth--
		case ']':
			if depth == 0 {
				return count
			}
		}
	}
	return count
}

// --- Updates ---

// CreateUpdate inserts a new update record.
func (s *SQLiteStore) CreateUpdate(ctx context.Context, u *Update) error {
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO updates (id, org_name, project_name, stack_name, kind, status, config, metadata, created_at)
		 VALUES (?, ?, ?, ?, ?, 'not-started', ?, ?, ?)`,
		u.ID, u.OrgName, u.ProjectName, u.StackName, u.Kind, u.Config, u.Metadata, now)
	return err
}

// StartUpdate transitions an update to in-progress with a lease token.
func (s *SQLiteStore) StartUpdate(ctx context.Context, id string, version int, token string, expires time.Time, journalVer int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE updates SET status='in-progress', version=?, token=?, token_expires_at=?, journal_version=?, started_at=?
		 WHERE id=?`,
		version, token, expires.Unix(), journalVer, time.Now().Unix(), id)
	return err
}

// GetUpdate returns an update by ID.
func (s *SQLiteStore) GetUpdate(ctx context.Context, id string) (*Update, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, org_name, project_name, stack_name, kind, status, version, config, metadata, token, token_expires_at, journal_version, created_at, started_at, completed_at, result
		 FROM updates WHERE id=?`, id)

	u := &Update{}
	var configJSON, metadataJSON, resultJSON sql.NullString
	var start, end sql.NullInt64
	var expires int64
	var createdAt int64

	// Scan based on schema
	if err := row.Scan(&u.ID, &u.OrgName, &u.ProjectName, &u.StackName, &u.Kind, &u.Status, &u.Version, &configJSON, &metadataJSON, &u.Token, &expires, &u.JournalVersion, &createdAt, &start, &end, &resultJSON); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	u.CreatedAt = time.Unix(createdAt, 0)
	u.StartedAt = nullUnixToTimePtr(start)
	u.CompletedAt = nullUnixToTimePtr(end)
	if expires > 0 {
		u.TokenExpiresAt = time.Unix(expires, 0)
	}

	if configJSON.Valid {
		u.Config = []byte(configJSON.String)
	}
	if metadataJSON.Valid {
		u.Metadata = []byte(metadataJSON.String)
	}
	if resultJSON.Valid {
		u.Result = []byte(resultJSON.String)
	}

	return u, nil
}

// GetActiveUpdate returns the in-progress update for a stack, if any.
func (s *SQLiteStore) GetActiveUpdate(ctx context.Context, org, proj, stack string) (*Update, error) {
	// Find in-progress update
	row := s.db.QueryRowContext(ctx,
		`SELECT id FROM updates 
		 WHERE org_name=? AND project_name=? AND stack_name=? AND status='in-progress'`,
		org, proj, stack)

	var id string
	if err := row.Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return s.GetUpdate(ctx, id)
}

// CompleteUpdate marks an update as finished with the given status and result.
func (s *SQLiteStore) CompleteUpdate(ctx context.Context, id string, status string, result []byte) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE updates SET status=?, result=?, completed_at=?, token='' WHERE id=?`,
		status, string(result), time.Now().Unix(), id)
	return err
}

// RenewLease extends an update's lease with a new token and expiry.
func (s *SQLiteStore) RenewLease(ctx context.Context, id string, newToken string, newExpiry time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE updates SET token=?, token_expires_at=? WHERE id=?`,
		newToken, newExpiry.Unix(), id)
	return err
}

// CancelUpdate marks an update as cancelled.
func (s *SQLiteStore) CancelUpdate(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE updates SET status='cancelled', completed_at=? WHERE id=?`, time.Now().Unix(), id)
	return err
}

// --- Journal ---

// SaveJournalEntries persists a batch of journal entries in a transaction.
func (s *SQLiteStore) SaveJournalEntries(ctx context.Context, entries []JournalEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	for _, e := range entries {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO journal_entries (update_id, sequence_id, entry) VALUES (?, ?, ?)`,
			e.UpdateID, e.SequenceID, e.Entry)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetJournalEntries returns all journal entries for an update, ordered by sequence.
func (s *SQLiteStore) GetJournalEntries(ctx context.Context, id string) ([]JournalEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sequence_id, entry FROM journal_entries WHERE update_id=? ORDER BY sequence_id ASC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []JournalEntry
	for rows.Next() {
		var e JournalEntry
		e.UpdateID = id
		if err := rows.Scan(&e.SequenceID, &e.Entry); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// GetMaxJournalSequence returns the highest journal sequence ID for an update.
func (s *SQLiteStore) GetMaxJournalSequence(ctx context.Context, id string) (int64, error) {
	var maxSeq sql.NullInt64
	err := s.db.QueryRowContext(ctx, "SELECT MAX(sequence_id) FROM journal_entries WHERE update_id=?", id).Scan(&maxSeq)
	if err != nil {
		return 0, err
	}
	if maxSeq.Valid {
		return maxSeq.Int64, nil
	}
	return 0, nil
}

// --- Engine Events ---

// SaveEngineEvents persists a batch of engine events in a transaction.
func (s *SQLiteStore) SaveEngineEvents(ctx context.Context, events []EngineEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR REPLACE INTO engine_events (update_id, sequence, event) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range events {
		if _, err := stmt.ExecContext(ctx, e.UpdateID, e.Sequence, e.Event); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetEngineEvents returns engine events for an update with pagination.
func (s *SQLiteStore) GetEngineEvents(ctx context.Context, updateID string, offset, count int) ([]EngineEvent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT update_id, sequence, event FROM engine_events WHERE update_id=? ORDER BY sequence LIMIT ? OFFSET ?`,
		updateID, count, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []EngineEvent
	for rows.Next() {
		var e EngineEvent
		if err := rows.Scan(&e.UpdateID, &e.Sequence, &e.Event); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, nil
}

// --- Update History ---

// SaveUpdateHistory records a completed update in the history table.
func (s *SQLiteStore) SaveUpdateHistory(ctx context.Context, h *UpdateHistory) error {
	var endTime *int64
	if h.EndTime != nil {
		t := h.EndTime.Unix()
		endTime = &t
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO update_history (org_name, project_name, stack_name, version, update_id, kind, status, message, environment, config, start_time, end_time, resource_changes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.OrgName, h.ProjectName, h.StackName, h.Version, h.UpdateID, h.Kind, h.Status,
		h.Message, h.Environment, h.Config, h.StartTime.Unix(), endTime, h.ResourceChanges)
	return err
}

// GetUpdateHistory returns paginated update history for a stack.
func (s *SQLiteStore) GetUpdateHistory(ctx context.Context, org, project, stack string, pageSize, page int) ([]UpdateHistory, error) {
	if pageSize <= 0 {
		pageSize = 10
	}
	offset := page * pageSize

	rows, err := s.db.QueryContext(ctx,
		`SELECT org_name, project_name, stack_name, version, update_id, kind, status, message, environment, config, start_time, end_time, resource_changes
		 FROM update_history WHERE org_name=? AND project_name=? AND stack_name=?
		 ORDER BY version DESC LIMIT ? OFFSET ?`,
		org, project, stack, pageSize, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []UpdateHistory
	for rows.Next() {
		var h UpdateHistory
		var startTime int64
		var endTime *int64
		if err := rows.Scan(&h.OrgName, &h.ProjectName, &h.StackName, &h.Version, &h.UpdateID,
			&h.Kind, &h.Status, &h.Message, &h.Environment, &h.Config, &startTime, &endTime, &h.ResourceChanges); err != nil {
			return nil, err
		}
		h.StartTime = time.Unix(startTime, 0)
		h.EndTime = unixToTimePtr(endTime)
		history = append(history, h)
	}
	return history, nil
}

// GetUpdateHistoryByVersion returns a single update history entry by version.
func (s *SQLiteStore) GetUpdateHistoryByVersion(ctx context.Context, org, project, stack string, version int) (*UpdateHistory, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT org_name, project_name, stack_name, version, update_id, kind, status, message, environment, config, start_time, end_time, resource_changes
		 FROM update_history WHERE org_name=? AND project_name=? AND stack_name=? AND version=?`,
		org, project, stack, version)

	var h UpdateHistory
	var startTime int64
	var endTime *int64
	err := row.Scan(&h.OrgName, &h.ProjectName, &h.StackName, &h.Version, &h.UpdateID,
		&h.Kind, &h.Status, &h.Message, &h.Environment, &h.Config, &startTime, &endTime, &h.ResourceChanges)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	h.StartTime = time.Unix(startTime, 0)
	h.EndTime = unixToTimePtr(endTime)
	return &h, nil
}

// --- Tokens ---

// CreateToken stores a new authentication token.
func (s *SQLiteStore) CreateToken(ctx context.Context, t *Token) error {
	var expiresAt *int64
	if t.ExpiresAt != nil {
		e := t.ExpiresAt.Unix()
		expiresAt = &e
	}
	groupsJSON := ""
	if len(t.Groups) > 0 {
		b, err := json.Marshal(t.Groups)
		if err != nil {
			return fmt.Errorf("marshal groups: %w", err)
		}
		groupsJSON = string(b)
	}
	storedRefresh, err := s.encryptRefreshToken(t.RefreshToken)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO tokens (token_hash, user_name, description, refresh_token, groups, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.TokenHash, t.UserName, t.Description, storedRefresh, groupsJSON, time.Now().Unix(), expiresAt)
	return err
}

// scanToken scans a token row into a Token struct, decrypting the refresh token if an encryptor is set.
func (s *SQLiteStore) scanToken(scan func(dest ...any) error) (Token, error) {
	var t Token
	var createdAt int64
	var lastUsedAt, expiresAt *int64
	var groupsJSON string
	var storedRefresh string
	err := scan(&t.TokenHash, &t.UserName, &t.Description, &storedRefresh, &groupsJSON, &createdAt, &lastUsedAt, &expiresAt)
	if err != nil {
		return Token{}, err
	}
	t.RefreshToken, err = s.decryptRefreshToken(storedRefresh)
	if err != nil {
		return Token{}, fmt.Errorf("token %s: %w", t.TokenHash[:8], err)
	}
	if groupsJSON != "" {
		if err := json.Unmarshal([]byte(groupsJSON), &t.Groups); err != nil {
			slog.Warn("failed to unmarshal token groups", "user", t.UserName, "error", err)
		}
	}
	t.CreatedAt = time.Unix(createdAt, 0)
	t.LastUsedAt = unixToTimePtr(lastUsedAt)
	t.ExpiresAt = unixToTimePtr(expiresAt)
	return t, nil
}

// GetToken returns a token by its hash.
func (s *SQLiteStore) GetToken(ctx context.Context, tokenHash string) (*Token, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT token_hash, user_name, description, refresh_token, groups, created_at, last_used_at, expires_at FROM tokens WHERE token_hash=?`,
		tokenHash)

	t, err := s.scanToken(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// TouchToken updates the last-used timestamp for a token.
func (s *SQLiteStore) TouchToken(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE tokens SET last_used_at=? WHERE token_hash=?`,
		time.Now().Unix(), tokenHash)
	return err
}

// DeleteToken removes a token by its hash.
func (s *SQLiteStore) DeleteToken(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE token_hash=?`, tokenHash)
	return err
}

// DeleteTokensByUser removes all tokens for a user and returns the count deleted.
func (s *SQLiteStore) DeleteTokensByUser(ctx context.Context, userName string) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE user_name=?`, userName)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ListTokensByUser returns all tokens for a user, ordered by creation time.
func (s *SQLiteStore) ListTokensByUser(ctx context.Context, userName string) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT token_hash, user_name, description, refresh_token, groups, created_at, last_used_at, expires_at
		 FROM tokens WHERE user_name=? ORDER BY created_at DESC`, userName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		t, err := s.scanToken(rows.Scan)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// --- Secrets Keys ---

// SaveSecretsKey stores an encrypted DEK for a stack.
func (s *SQLiteStore) SaveSecretsKey(ctx context.Context, org, project, stack string, encryptedKey []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO secrets_keys (org_name, project_name, stack_name, encryption_key) VALUES (?, ?, ?, ?)`,
		org, project, stack, encryptedKey)
	return err
}

// GetSecretsKey returns the encrypted DEK for a stack.
func (s *SQLiteStore) GetSecretsKey(ctx context.Context, org, project, stack string) ([]byte, error) {
	var key []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT encryption_key FROM secrets_keys WHERE org_name=? AND project_name=? AND stack_name=?`,
		org, project, stack).Scan(&key)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return key, err
}

// ListSecretsKeys returns all encrypted DEKs for secrets key migration.
func (s *SQLiteStore) ListSecretsKeys(ctx context.Context) ([]SecretsKeyEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT org_name, project_name, stack_name, encryption_key FROM secrets_keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []SecretsKeyEntry
	for rows.Next() {
		var e SecretsKeyEntry
		if err := rows.Scan(&e.OrgName, &e.ProjectName, &e.StackName, &e.EncryptedKey); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
