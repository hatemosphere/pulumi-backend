package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/klauspost/compress/gzip"

	_ "modernc.org/sqlite"
)

const defaultMaxStateVersions = 50

// SQLiteStoreConfig holds tuning parameters for the SQLite store.
type SQLiteStoreConfig struct {
	MaxStateVersions  int // 0 = default (50), -1 = unlimited
	StackListPageSize int // 0 = default (100)
}

// SQLiteStore implements Store using SQLite in WAL mode.
type SQLiteStore struct {
	db                *sql.DB
	maxStateVersions  int
	stackListPageSize int
}

// NewSQLiteStore opens (or creates) a SQLite database at path with WAL mode enabled.
func NewSQLiteStore(path string, cfgs ...SQLiteStoreConfig) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=synchronous(normal)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Single writer, many readers — pool of 1 write conn + read conns.
	// However, to avoid "database is locked" errors with the current driver setup,
	// we strictly limit to 1 connection for now.
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

	s := &SQLiteStore{db: db, maxStateVersions: maxVer, stackListPageSize: pageSize}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Additive migrations for existing databases.
	for _, m := range []string{
		`ALTER TABLE stacks ADD COLUMN resource_count INTEGER NOT NULL DEFAULT 0`,
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
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    expires_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_updates_stack ON updates(org_name, project_name, stack_name);
CREATE INDEX IF NOT EXISTS idx_updates_active ON updates(org_name, project_name, stack_name, status) WHERE status IN ('not-started', 'in-progress');
CREATE INDEX IF NOT EXISTS idx_history_stack ON update_history(org_name, project_name, stack_name, version DESC);
`

// --- Stacks ---

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

	tagsJSON, _ := json.Marshal(st.Tags)
	_, err = tx.ExecContext(ctx,
		`INSERT INTO stacks (org_name, project_name, name, tags, current_version, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 0, ?, ?)`,
		st.OrgName, st.ProjectName, st.StackName, string(tagsJSON), now, now)
	if err != nil {
		return fmt.Errorf("create stack: %w", err)
	}

	return tx.Commit()
}

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
	for _, q := range []string{
		`DELETE FROM updates WHERE org_name=? AND project_name=? AND stack_name=?`,
		`DELETE FROM update_history WHERE org_name=? AND project_name=? AND stack_name=?`,
		`DELETE FROM stack_state WHERE org_name=? AND project_name=? AND stack_name=?`,
		`DELETE FROM secrets_keys WHERE org_name=? AND project_name=? AND stack_name=?`,
		`DELETE FROM stacks WHERE org_name=? AND project_name=? AND name=?`,
	} {
		if _, err = tx.ExecContext(ctx, q, org, project, stack); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListStacks(ctx context.Context, org, project string, continuationToken string) ([]Stack, string, error) {
	query := `SELECT org_name, project_name, name, tags, current_version, resource_count, created_at, updated_at FROM stacks WHERE 1=1`
	args := []any{}

	if org != "" {
		query += ` AND org_name=?`
		args = append(args, org)
	}
	if project != "" {
		query += ` AND project_name=?`
		args = append(args, project)
	}
	if continuationToken != "" {
		query += ` AND (org_name, project_name, name) > (?, ?, ?)`
		tokenParts := splitToken(continuationToken)
		if len(tokenParts) == 3 {
			args = append(args, tokenParts[0], tokenParts[1], tokenParts[2])
		} else {
			args = append(args, "", "", "")
		}
	}
	query += ` ORDER BY org_name, project_name, name LIMIT ?`
	args = append(args, s.stackListPageSize)

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

	var nextToken string
	if len(stacks) == s.stackListPageSize {
		last := stacks[len(stacks)-1]
		nextToken = last.OrgName + "/" + last.ProjectName + "/" + last.StackName
	}
	return stacks, nextToken, nil
}

func splitToken(token string) []string {
	// A naive split by '/'. In a real system, we should use a safer delimiter or encoding.
	// Pulumi names usually don't contain slashes.
	// Implement a manual split to handle exactly 3 parts.
	parts := make([]string, 0, 3)
	start := 0
	slashes := 0
	for i, r := range token {
		if r == '/' {
			slashes++
			if slashes <= 2 {
				parts = append(parts, token[start:i])
				start = i + 1
			}
		}
	}
	if start < len(token) {
		parts = append(parts, token[start:])
	}
	// Pad if necessary
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	return parts
}

func (s *SQLiteStore) UpdateStackTags(ctx context.Context, org, project, stack string, tags map[string]string) error {
	tagsJSON, _ := json.Marshal(tags)
	_, err := s.db.ExecContext(ctx,
		`UPDATE stacks SET tags=?, updated_at=? WHERE org_name=? AND project_name=? AND name=?`,
		string(tagsJSON), time.Now().Unix(), org, project, stack)
	return err
}

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
		return err
	}

	// Cascade to related tables.
	for _, q := range []string{
		`UPDATE stack_state SET project_name=?, stack_name=? WHERE org_name=? AND project_name=? AND stack_name=?`,
		`UPDATE updates SET project_name=?, stack_name=? WHERE org_name=? AND project_name=? AND stack_name=?`,
		`UPDATE update_history SET project_name=?, stack_name=? WHERE org_name=? AND project_name=? AND stack_name=?`,
		`UPDATE secrets_keys SET project_name=?, stack_name=? WHERE org_name=? AND project_name=? AND stack_name=?`,
	} {
		if _, err = tx.ExecContext(ctx, q, newProject, newName, org, oldProject, oldName); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) ProjectExists(ctx context.Context, org, project string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM stacks WHERE org_name=? AND project_name=?`,
		org, project).Scan(&count)
	return count > 0, err
}

// --- Stack State ---

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
			Version: 0, Deployment: []byte(`{"version":3,"deployment":{"manifest":{"time":"0001-01-01T00:00:00Z","magic":"","version":""},"resources":null}}`),
		}, nil
	}
	return s.GetStateVersion(ctx, org, project, stack, version)
}

// maybeGzipReader handles transparent decompression if the data starts with gzip magic bytes.
func maybeDecompress(data []byte) ([]byte, error) {
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		return io.ReadAll(gr)
	}
	return data, nil
}

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
	st.Deployment, err = maybeDecompress(st.Deployment)
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
	isCompressed := len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b
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
		empty := []byte(`{"version":3,"deployment":{"manifest":{"time":"0001-01-01T00:00:00Z","magic":"","version":""},"resources":null}}`)
		return empty, 0, false, nil
	}
	data, isCompressed, err := s.GetStateVersionRaw(ctx, org, project, stack, version)
	return data, version, isCompressed, err
}

func (s *SQLiteStore) SaveState(ctx context.Context, state *StackState) error {
	now := time.Now().Unix()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	// Check if already compressed (magic bytes: 0x1f 0x8b).
	var compressedDeployment []byte
	if len(state.Deployment) > 2 && state.Deployment[0] == 0x1f && state.Deployment[1] == 0x8b {
		compressedDeployment = state.Deployment
	} else {
		// GZIP compress the deployment.
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(state.Deployment); err != nil {
			return fmt.Errorf("compress deployment: %w", err)
		}
		if err := gw.Close(); err != nil {
			return fmt.Errorf("close gzip writer: %w", err)
		}
		compressedDeployment = buf.Bytes()
	}

	_, err = tx.ExecContext(ctx,
		`INSERT OR REPLACE INTO stack_state (org_name, project_name, stack_name, version, deployment, deployment_hash, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		state.OrgName, state.ProjectName, state.StackName, state.Version, compressedDeployment, state.Hash, now)
	if err != nil {
		return err
	}

	// Count resources in the deployment for the resource_count field.
	resourceCount := countResources(state.Deployment)

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

// countResources extracts the resource count from an uncompressed deployment JSON.
func countResources(deployment []byte) int {
	var doc struct {
		Deployment struct {
			Resources []json.RawMessage `json:"resources"`
		} `json:"deployment"`
	}
	if json.Unmarshal(deployment, &doc) == nil {
		return len(doc.Deployment.Resources)
	}
	return 0
}

// --- Updates ---

func (s *SQLiteStore) CreateUpdate(ctx context.Context, u *Update) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO updates (id, org_name, project_name, stack_name, kind, status, config, metadata, created_at)
		 VALUES (?, ?, ?, ?, ?, 'not-started', ?, ?, ?)`,
		u.ID, u.OrgName, u.ProjectName, u.StackName, u.Kind, u.Config, u.Metadata, time.Now().Unix())
	return err
}

func (s *SQLiteStore) GetUpdate(ctx context.Context, updateID string) (*Update, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, org_name, project_name, stack_name, kind, status, version, config, metadata,
		        token, token_expires_at, journal_version, created_at, started_at, completed_at, result
		 FROM updates WHERE id=?`, updateID)
	return s.scanUpdateRow(row)
}

func (s *SQLiteStore) StartUpdate(ctx context.Context, updateID string, version int, token string, tokenExpiresAt time.Time, journalVersion int) error {
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx,
		`UPDATE updates SET status='in-progress', version=?, token=?, token_expires_at=?, journal_version=?, started_at=?
		 WHERE id=?`,
		version, token, tokenExpiresAt.Unix(), journalVersion, now, updateID)
	return err
}

func (s *SQLiteStore) CompleteUpdate(ctx context.Context, updateID string, status string, result []byte) error {
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx,
		`UPDATE updates SET status=?, completed_at=?, result=? WHERE id=?`,
		status, now, result, updateID)
	return err
}

func (s *SQLiteStore) RenewLease(ctx context.Context, updateID string, newToken string, newExpiry time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE updates SET token=?, token_expires_at=? WHERE id=?`,
		newToken, newExpiry.Unix(), updateID)
	return err
}

func (s *SQLiteStore) GetActiveUpdate(ctx context.Context, org, project, stack string) (*Update, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, org_name, project_name, stack_name, kind, status, version, config, metadata,
		        token, token_expires_at, journal_version, created_at, started_at, completed_at, result
		 FROM updates WHERE org_name=? AND project_name=? AND stack_name=? AND status IN ('not-started', 'in-progress')
		 ORDER BY created_at DESC LIMIT 1`,
		org, project, stack)
	return s.scanUpdateRow(row)
}

func (s *SQLiteStore) scanUpdateRow(row *sql.Row) (*Update, error) {
	u := &Update{}
	var tokenExpiresAt, createdAt int64
	var startedAt, completedAt *int64
	err := row.Scan(&u.ID, &u.OrgName, &u.ProjectName, &u.StackName, &u.Kind, &u.Status,
		&u.Version, &u.Config, &u.Metadata, &u.Token, &tokenExpiresAt, &u.JournalVersion,
		&createdAt, &startedAt, &completedAt, &u.Result)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.TokenExpiresAt = time.Unix(tokenExpiresAt, 0)
	u.CreatedAt = time.Unix(createdAt, 0)
	if startedAt != nil {
		t := time.Unix(*startedAt, 0)
		u.StartedAt = &t
	}
	if completedAt != nil {
		t := time.Unix(*completedAt, 0)
		u.CompletedAt = &t
	}
	return u, nil
}

func (s *SQLiteStore) CancelUpdate(ctx context.Context, updateID string) error {
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx,
		`UPDATE updates SET status='cancelled', completed_at=? WHERE id=? AND status IN ('not-started', 'in-progress')`,
		now, updateID)
	return err
}

// --- Journal Entries ---

func (s *SQLiteStore) SaveJournalEntries(ctx context.Context, entries []JournalEntry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR REPLACE INTO journal_entries (update_id, sequence_id, entry) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx, e.UpdateID, e.SequenceID, e.Entry); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) GetJournalEntries(ctx context.Context, updateID string) ([]JournalEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT update_id, sequence_id, entry FROM journal_entries WHERE update_id=? ORDER BY sequence_id`,
		updateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []JournalEntry
	for rows.Next() {
		var e JournalEntry
		if err := rows.Scan(&e.UpdateID, &e.SequenceID, &e.Entry); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// --- Engine Events ---

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
		if endTime != nil {
			t := time.Unix(*endTime, 0)
			h.EndTime = &t
		}
		history = append(history, h)
	}
	return history, nil
}

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
	if endTime != nil {
		t := time.Unix(*endTime, 0)
		h.EndTime = &t
	}
	return &h, nil
}

// --- Tokens ---

func (s *SQLiteStore) CreateToken(ctx context.Context, t *Token) error {
	var expiresAt *int64
	if t.ExpiresAt != nil {
		e := t.ExpiresAt.Unix()
		expiresAt = &e
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens (token_hash, user_name, description, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		t.TokenHash, t.UserName, t.Description, time.Now().Unix(), expiresAt)
	return err
}

func (s *SQLiteStore) GetToken(ctx context.Context, tokenHash string) (*Token, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT token_hash, user_name, description, created_at, last_used_at, expires_at FROM tokens WHERE token_hash=?`,
		tokenHash)

	t := &Token{}
	var createdAt int64
	var lastUsedAt, expiresAt *int64
	err := row.Scan(&t.TokenHash, &t.UserName, &t.Description, &createdAt, &lastUsedAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.CreatedAt = time.Unix(createdAt, 0)
	if lastUsedAt != nil {
		lu := time.Unix(*lastUsedAt, 0)
		t.LastUsedAt = &lu
	}
	if expiresAt != nil {
		ea := time.Unix(*expiresAt, 0)
		t.ExpiresAt = &ea
	}
	return t, nil
}

func (s *SQLiteStore) TouchToken(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE tokens SET last_used_at=? WHERE token_hash=?`,
		time.Now().Unix(), tokenHash)
	return err
}

// --- Secrets Keys ---

func (s *SQLiteStore) SaveSecretsKey(ctx context.Context, org, project, stack string, encryptedKey []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO secrets_keys (org_name, project_name, stack_name, encryption_key) VALUES (?, ?, ?, ?)`,
		org, project, stack, encryptedKey)
	return err
}

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

// --- Backup ---

// Backup creates a consistent backup of the database at destPath using VACUUM INTO.
func (s *SQLiteStore) Backup(ctx context.Context, destPath string) error {
	_, err := s.db.ExecContext(ctx, "VACUUM INTO ?", destPath)
	return err
}
