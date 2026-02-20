package storage

import (
	"context"
	"time"
)

// Stack represents a stack record.
type Stack struct {
	OrgName       string
	ProjectName   string
	StackName     string
	Tags          map[string]string
	Version       int
	ResourceCount int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// StackState holds a versioned deployment snapshot for a stack.
type StackState struct {
	OrgName     string
	ProjectName string
	StackName   string
	Version     int
	Deployment  []byte // gzip-compressed JSON
	Hash        string // SHA-256 of uncompressed deployment JSON
	CreatedAt   time.Time
}

// Update represents an in-progress or completed update session.
type Update struct {
	ID             string
	OrgName        string
	ProjectName    string
	StackName      string
	Kind           string // preview, update, refresh, destroy
	Status         string // not-started, in-progress, succeeded, failed, cancelled
	Version        int
	Config         []byte // JSON
	Metadata       []byte // JSON
	Token          string
	TokenExpiresAt time.Time
	JournalVersion int
	CreatedAt      time.Time
	StartedAt      *time.Time
	CompletedAt    *time.Time
	Result         []byte // JSON
}

// JournalEntry represents a single journal entry for an update.
type JournalEntry struct {
	UpdateID   string
	SequenceID int64
	Entry      []byte // gzip-compressed JSON
}

// EngineEvent is a batched engine event for an update.
type EngineEvent struct {
	UpdateID string
	Sequence int
	Event    []byte // gzip-compressed JSON
}

// UpdateHistory is a materialized history record.
type UpdateHistory struct {
	OrgName         string
	ProjectName     string
	StackName       string
	Version         int
	UpdateID        string
	Kind            string
	Status          string
	Message         string
	Environment     []byte // JSON
	Config          []byte // JSON
	StartTime       time.Time
	EndTime         *time.Time
	ResourceChanges []byte // JSON
}

// Token represents an API access token.
type Token struct {
	TokenHash    string
	UserName     string
	Description  string
	RefreshToken string //nolint:gosec // field name, not a credential
	CreatedAt    time.Time
	LastUsedAt   *time.Time
	ExpiresAt    *time.Time
}

// Store is the storage interface for the backend.
type Store interface {
	// Lifecycle
	Close() error

	// Stacks
	CreateStack(ctx context.Context, s *Stack) error
	GetStack(ctx context.Context, org, project, stack string) (*Stack, error)
	DeleteStack(ctx context.Context, org, project, stack string) error
	ListStacks(ctx context.Context, org, project string, continuationToken string) ([]Stack, string, error)
	UpdateStackTags(ctx context.Context, org, project, stack string, tags map[string]string) error
	RenameStack(ctx context.Context, org, oldProject, oldName, newProject, newName string) error
	ProjectExists(ctx context.Context, org, project string) (bool, error)

	// Stack state
	GetCurrentState(ctx context.Context, org, project, stack string) (*StackState, error)
	GetStateVersion(ctx context.Context, org, project, stack string, version int) (*StackState, error)
	SaveState(ctx context.Context, state *StackState) error

	// Raw state access (zero-copy gzip export).
	// Returns the raw deployment bytes from SQLite without decompression.
	GetStateVersionRaw(ctx context.Context, org, project, stack string, version int) (data []byte, isCompressed bool, err error)
	// Returns the current state's raw deployment bytes.
	GetCurrentStateRaw(ctx context.Context, org, project, stack string) (data []byte, version int, isCompressed bool, err error)

	// Updates
	CreateUpdate(ctx context.Context, u *Update) error
	GetUpdate(ctx context.Context, updateID string) (*Update, error)
	StartUpdate(ctx context.Context, updateID string, version int, token string, tokenExpiresAt time.Time, journalVersion int) error
	CompleteUpdate(ctx context.Context, updateID string, status string, result []byte) error
	RenewLease(ctx context.Context, updateID string, newToken string, newExpiry time.Time) error
	GetActiveUpdate(ctx context.Context, org, project, stack string) (*Update, error)
	CancelUpdate(ctx context.Context, updateID string) error

	// Journal entries
	SaveJournalEntries(ctx context.Context, entries []JournalEntry) error
	GetJournalEntries(ctx context.Context, updateID string) ([]JournalEntry, error)
	GetMaxJournalSequence(ctx context.Context, updateID string) (int64, error)

	// Engine events
	SaveEngineEvents(ctx context.Context, events []EngineEvent) error
	GetEngineEvents(ctx context.Context, updateID string, offset, count int) ([]EngineEvent, error)

	// Update history
	SaveUpdateHistory(ctx context.Context, h *UpdateHistory) error
	GetUpdateHistory(ctx context.Context, org, project, stack string, pageSize, page int) ([]UpdateHistory, error)
	GetUpdateHistoryByVersion(ctx context.Context, org, project, stack string, version int) (*UpdateHistory, error)

	// Tokens
	CreateToken(ctx context.Context, t *Token) error
	GetToken(ctx context.Context, tokenHash string) (*Token, error)
	TouchToken(ctx context.Context, tokenHash string) error
	DeleteToken(ctx context.Context, tokenHash string) error
	DeleteTokensByUser(ctx context.Context, userName string) (int64, error)
	ListTokensByUser(ctx context.Context, userName string) ([]Token, error)

	// Secrets keys
	SaveSecretsKey(ctx context.Context, org, project, stack string, encryptedKey []byte) error
	GetSecretsKey(ctx context.Context, org, project, stack string) ([]byte, error)

	// Backup creates a consistent backup of the database at destPath using VACUUM INTO.
	Backup(ctx context.Context, destPath string) error
}
