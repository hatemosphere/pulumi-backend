package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/hatemosphere/pulumi-backend/internal/backup"
	"github.com/hatemosphere/pulumi-backend/internal/gziputil"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

var tracer = otel.Tracer("pulumi-backend/engine")

// Sentinel errors for update state conflicts (mapped to HTTP 409 in the API layer).
var (
	ErrUpdateNotInProgress  = errors.New("The Update has not started or The Update has been cancelled or The Update has already completed")
	ErrStackHasActiveUpdate = errors.New("Another update is currently in progress.")
	ErrNoActiveUpdate       = errors.New("The Update has not started")
)

// ManagerConfig holds tuning parameters for the engine manager.
type ManagerConfig struct {
	LeaseDuration      time.Duration
	CacheSize          int
	EventBufferSize    int
	EventFlushInterval time.Duration
	BackupDir          string
	BackupProviders    []backup.Provider
	BackupSchedule     time.Duration
	BackupRetention    int
}

// BackupResult holds the result of a backup operation.
type BackupResult struct {
	LocalPath  string
	RemoteKeys map[string]string // provider name → remote key
}

// Manager is the core engine orchestrating stacks, updates, and state.
type Manager struct {
	store         storage.Store
	secrets       *SecretsEngine
	cache         *lru.Cache[string, []byte] // key: org/project/stack, value: deployment JSON
	secretsCache  *lru.Cache[string, []byte] // key: org/project/stack, value: decrypted stack key
	stackLocks    sync.Map                   // key: org/project/stack -> *stackLock
	leaseDuration time.Duration
	backupDir     string

	// Remote backup providers (e.g., S3).
	backupProviders []backup.Provider
	backupRetention int
	backupScheduler *backup.Scheduler

	// Active update tracking.
	activeUpdates atomic.Int64

	// Async event buffering.
	eventMu   sync.Mutex
	eventBuf  []storage.EngineEvent
	eventMax  int
	flushStop chan struct{}
	flushDone chan struct{}
}

type stackLock struct {
	mu       sync.Mutex
	updateID string
	expiry   time.Time
}

// NewManager creates a new engine manager.
func NewManager(store storage.Store, secrets *SecretsEngine, cfgs ...ManagerConfig) (*Manager, error) {
	cfg := ManagerConfig{
		LeaseDuration:      5 * time.Minute,
		CacheSize:          256,
		EventBufferSize:    1000,
		EventFlushInterval: time.Second,
	}
	if len(cfgs) > 0 {
		c := cfgs[0]
		if c.LeaseDuration > 0 {
			cfg.LeaseDuration = c.LeaseDuration
		}
		if c.CacheSize > 0 {
			cfg.CacheSize = c.CacheSize
		}
		if c.EventBufferSize > 0 {
			cfg.EventBufferSize = c.EventBufferSize
		}
		if c.EventFlushInterval > 0 {
			cfg.EventFlushInterval = c.EventFlushInterval
		}
		cfg.BackupDir = c.BackupDir
		cfg.BackupProviders = c.BackupProviders
		cfg.BackupSchedule = c.BackupSchedule
		cfg.BackupRetention = c.BackupRetention
	}

	cache, err := lru.New[string, []byte](cfg.CacheSize)
	if err != nil {
		return nil, err
	}
	secretsCache, err := lru.NewWithEvict(cfg.CacheSize, func(_ string, value []byte) {
		for i := range value {
			value[i] = 0
		}
	})
	if err != nil {
		return nil, err
	}
	m := &Manager{
		store:           store,
		secrets:         secrets,
		cache:           cache,
		secretsCache:    secretsCache,
		leaseDuration:   cfg.LeaseDuration,
		backupDir:       cfg.BackupDir,
		backupProviders: cfg.BackupProviders,
		backupRetention: cfg.BackupRetention,
		eventMax:        cfg.EventBufferSize,
		flushStop:       make(chan struct{}),
		flushDone:       make(chan struct{}),
	}

	// Start the periodic event flusher.
	go m.eventFlusher(cfg.EventFlushInterval)

	// Start backup scheduler if configured.
	if cfg.BackupSchedule > 0 && (cfg.BackupDir != "" || len(cfg.BackupProviders) > 0) {
		m.backupScheduler = backup.NewScheduler(func(ctx context.Context) error {
			_, err := m.Backup(ctx)
			return err
		}, cfg.BackupSchedule)
	}

	return m, nil
}

// Shutdown flushes buffered events and stops background goroutines.
func (m *Manager) Shutdown() {
	close(m.flushStop)
	<-m.flushDone

	if m.backupScheduler != nil {
		m.backupScheduler.Shutdown()
	}
}

// ActiveUpdateCount returns the number of currently active (in-progress) updates.
// Ping checks that the underlying storage is reachable.
func (m *Manager) Ping(ctx context.Context) error {
	return m.store.Ping(ctx)
}

func (m *Manager) ActiveUpdateCount() int64 {
	return m.activeUpdates.Load()
}

func stackKey(org, project, stack string) string {
	return org + "/" + project + "/" + stack
}

// --- Stack Operations ---

func (m *Manager) CreateStack(ctx context.Context, org, project, stackName string, tags map[string]string) error {
	ctx, span := tracer.Start(ctx, "engine.CreateStack",
		trace.WithAttributes(attribute.String("stack", stackKey(org, project, stackName))))
	defer span.End()
	if tags == nil {
		tags = map[string]string{}
	}
	return m.store.CreateStack(ctx, &storage.Stack{
		OrgName:     org,
		ProjectName: project,
		StackName:   stackName,
		Tags:        tags,
	})
}

func (m *Manager) GetStack(ctx context.Context, org, project, stack string) (*storage.Stack, error) {
	return m.store.GetStack(ctx, org, project, stack)
}

func (m *Manager) DeleteStack(ctx context.Context, org, project, stack string, force bool) error {
	ctx, span := tracer.Start(ctx, "engine.DeleteStack",
		trace.WithAttributes(attribute.String("stack", stackKey(org, project, stack))))
	defer span.End()
	if !force {
		state, err := m.store.GetCurrentState(ctx, org, project, stack)
		if err != nil {
			return err
		}
		if state != nil && state.Version > 0 {
			// Check if there are resources.
			var deployment struct {
				Deployment struct {
					Resources []json.RawMessage `json:"resources"`
				} `json:"deployment"`
			}
			// Decompress if necessary before unmarshaling.
			deploymentData := state.Deployment
			if decompressed, err := gziputil.MaybeDecompress(state.Deployment); err == nil {
				deploymentData = decompressed
			}

			if err := json.Unmarshal(deploymentData, &deployment); err == nil {
				if len(deployment.Deployment.Resources) > 0 {
					return errors.New("Bad Request: Stack still contains resources.")
				}
			}
		}
	}
	m.cache.Remove(stackKey(org, project, stack))
	m.secretsCache.Remove(stackKey(org, project, stack))
	return m.store.DeleteStack(ctx, org, project, stack)
}

func (m *Manager) ListStacks(ctx context.Context, org, project, continuationToken string) ([]storage.Stack, string, error) {
	return m.store.ListStacks(ctx, org, project, continuationToken)
}

func (m *Manager) ProjectExists(ctx context.Context, org, project string) (bool, error) {
	return m.store.ProjectExists(ctx, org, project)
}

func (m *Manager) UpdateStackTags(ctx context.Context, org, project, stack string, tags map[string]string) error {
	return m.store.UpdateStackTags(ctx, org, project, stack, tags)
}

func (m *Manager) RenameStack(ctx context.Context, org, oldProject, oldName, newProject, newName string) error {
	ctx, span := tracer.Start(ctx, "engine.RenameStack")
	defer span.End()
	m.cache.Remove(stackKey(org, oldProject, oldName))
	m.secretsCache.Remove(stackKey(org, oldProject, oldName))
	return m.store.RenameStack(ctx, org, oldProject, oldName, newProject, newName)
}

// --- State Export/Import ---

func (m *Manager) ExportState(ctx context.Context, org, project, stack string, version *int) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "engine.ExportState",
		trace.WithAttributes(attribute.String("stack", stackKey(org, project, stack))))
	defer span.End()
	key := stackKey(org, project, stack)

	// Check cache for current version.
	if version == nil {
		if cachedCompressed, ok := m.cache.Get(key); ok {
			// Cache stores compressed data. Decompress for legacy export.
			return gziputil.Decompress(cachedCompressed)
		}
	}

	var data []byte
	var isCompressed bool
	var err error

	if version != nil {
		data, isCompressed, err = m.store.GetStateVersionRaw(ctx, org, project, stack, *version)
	} else {
		// GetCurrentStateRaw returns version too, but we only need data + isCompressed
		var ver int
		data, ver, isCompressed, err = m.store.GetCurrentStateRaw(ctx, org, project, stack)
		_ = ver
	}
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, errors.New("stack not found")
	}

	// Cache logic:
	// If compressed in DB -> Cache directly.
	// If uncompressed in DB -> Compress then Cache.
	if version == nil {
		if isCompressed {
			m.cache.Add(key, data)
		} else {
			if compressed, err := gziputil.Compress(data); err == nil {
				m.cache.Add(key, compressed)
			}
		}
	}

	// Return logic:
	// If was compressed -> Decompress to return.
	// If was uncompressed -> Return as is.
	if isCompressed {
		return gziputil.Decompress(data)
	}
	return data, nil
}

// ExportStateCompressed returns raw deployment bytes, potentially still gzip-compressed.
// Returns (data, isGzipCompressed, error). Used for zero-copy gzip export.
func (m *Manager) ExportStateCompressed(ctx context.Context, org, project, stack string, version *int) ([]byte, bool, error) {
	ctx, span := tracer.Start(ctx, "engine.ExportStateCompressed")
	defer span.End()
	key := stackKey(org, project, stack)

	// Check cache for current version.
	if version == nil {
		if cachedCompressed, ok := m.cache.Get(key); ok {
			// Cache hit! Return zero-copy compressed data.
			return cachedCompressed, true, nil
		}
	}

	var ver int
	if version != nil {
		ver = *version
	} else {
		st, err := m.store.GetStack(ctx, org, project, stack)
		if err != nil {
			return nil, false, err
		}
		if st == nil {
			return nil, false, errors.New("stack not found")
		}
		ver = st.Version
	}
	if ver == 0 {
		empty := []byte(`{"version":3,"deployment":{"manifest":{"time":"0001-01-01T00:00:00Z","magic":"","version":""},"resources":null}}`)
		return empty, false, nil
	}

	// Fetch raw (compressed) data from store.
	data, isCompressed, err := m.store.GetStateVersionRaw(ctx, org, project, stack, ver)
	if err != nil {
		return nil, false, err
	}
	if data == nil {
		return nil, false, fmt.Errorf("state version %d not found", ver)
	}

	// Populate cache if this is the current version and it IS compressed.
	if version == nil && isCompressed {
		m.cache.Add(key, data)
	} else if version == nil && !isCompressed {
		// If DB returned uncompressed (legacy?), compress and cache.
		if compressed, err := gziputil.Compress(data); err == nil {
			m.cache.Add(key, compressed)
			return compressed, true, nil
		}
	}

	return data, isCompressed, nil
}

func (m *Manager) ImportState(ctx context.Context, org, project, stack string, deployment []byte) error {
	ctx, span := tracer.Start(ctx, "engine.ImportState",
		trace.WithAttributes(attribute.String("stack", stackKey(org, project, stack))))
	defer span.End()
	key := stackKey(org, project, stack)

	st, err := m.store.GetStack(ctx, org, project, stack)
	if err != nil {
		return err
	}
	if st == nil {
		return errors.New("stack not found")
	}

	newVersion := st.Version + 1
	hash := sha256.Sum256(deployment)

	// Count resources before compressing (avoids decompression in storage layer).
	resourceCount := storage.CountResources(deployment)

	// Compress before saving to cache and store (so we don't double compress in store).
	compressed, err := gziputil.Compress(deployment)
	if err != nil {
		return fmt.Errorf("compress deployment: %w", err)
	}

	err = m.store.SaveState(ctx, &storage.StackState{
		OrgName:       org,
		ProjectName:   project,
		StackName:     stack,
		Version:       newVersion,
		Deployment:    compressed,
		Hash:          hex.EncodeToString(hash[:]),
		ResourceCount: resourceCount,
	})
	if err != nil {
		return err
	}

	m.cache.Add(key, compressed)
	return nil
}

// --- Update Lifecycle ---

type CreateUpdateResult struct {
	UpdateID string
}

func (m *Manager) CreateUpdate(ctx context.Context, org, project, stack, kind string, config, metadata json.RawMessage) (*CreateUpdateResult, error) {
	ctx, span := tracer.Start(ctx, "engine.CreateUpdate",
		trace.WithAttributes(attribute.String("stack", stackKey(org, project, stack)), attribute.String("kind", kind)))
	defer span.End()
	// Check for active updates on this stack.
	active, err := m.store.GetActiveUpdate(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	if active != nil {
		// Check if the lease has expired.
		if active.Status == "in-progress" && time.Now().After(active.TokenExpiresAt) {
			// Auto-cancel expired update. If cancel fails, abort so the next
			// attempt retries cleanup rather than leaving a stale record.
			if err := m.store.CancelUpdate(ctx, active.ID); err != nil {
				slog.Error("failed to cancel expired update", "updateID", active.ID, "error", err)
				return nil, ErrStackHasActiveUpdate
			}
			m.releaseStackLock(org, project, stack)
			m.activeUpdates.Add(-1)
		} else if active.Status != "not-started" || !time.Now().After(active.TokenExpiresAt.Add(m.leaseDuration)) {
			return nil, ErrStackHasActiveUpdate
		}
	}

	updateID := uuid.New().String()
	if config == nil {
		config = json.RawMessage(`{}`)
	}
	if metadata == nil {
		metadata = json.RawMessage(`{}`)
	}

	err = m.store.CreateUpdate(ctx, &storage.Update{
		ID:          updateID,
		OrgName:     org,
		ProjectName: project,
		StackName:   stack,
		Kind:        kind,
		Config:      config,
		Metadata:    metadata,
	})
	if err != nil {
		return nil, err
	}

	return &CreateUpdateResult{UpdateID: updateID}, nil
}

type StartUpdateResult struct {
	Version         int
	Token           string
	TokenExpiration int64
	JournalVersion  int
}

func (m *Manager) StartUpdate(ctx context.Context, updateID string, tags map[string]string, requestedJournalVersion int) (*StartUpdateResult, error) {
	ctx, span := tracer.Start(ctx, "engine.StartUpdate",
		trace.WithAttributes(attribute.String("update_id", updateID)))
	defer span.End()
	u, err := m.store.GetUpdate(ctx, updateID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, errors.New("update not found")
	}

	// Acquire stack lock.
	if !m.tryAcquireStackLock(u.OrgName, u.ProjectName, u.StackName, updateID) {
		return nil, ErrStackHasActiveUpdate
	}

	// Get next version.
	st, err := m.store.GetStack(ctx, u.OrgName, u.ProjectName, u.StackName)
	if err != nil {
		m.releaseStackLock(u.OrgName, u.ProjectName, u.StackName)
		return nil, err
	}
	if st == nil {
		m.releaseStackLock(u.OrgName, u.ProjectName, u.StackName)
		return nil, errors.New("stack not found")
	}
	newVersion := st.Version + 1

	// Update tags if provided. Fail-fast: the upstream handles this atomically,
	// so if tags can't be persisted the CLI should retry rather than proceed
	// with stale metadata.
	if len(tags) > 0 {
		if err := m.store.UpdateStackTags(ctx, u.OrgName, u.ProjectName, u.StackName, tags); err != nil {
			m.releaseStackLock(u.OrgName, u.ProjectName, u.StackName)
			slog.Error("failed to update stack tags", "error", err)
			return nil, errors.New("failed to update stack tags")
		}
	}

	// Generate lease token.
	token := uuid.New().String()
	expiry := time.Now().Add(m.leaseDuration)

	// Accept journaling if requested.
	journalVersion := 0
	if requestedJournalVersion == 1 {
		journalVersion = 1
	}

	err = m.store.StartUpdate(ctx, updateID, newVersion, token, expiry, journalVersion)
	if err != nil {
		m.releaseStackLock(u.OrgName, u.ProjectName, u.StackName)
		return nil, err
	}

	m.activeUpdates.Add(1)

	return &StartUpdateResult{
		Version:         newVersion,
		Token:           token,
		TokenExpiration: expiry.Unix(),
		JournalVersion:  journalVersion,
	}, nil
}

func (m *Manager) CompleteUpdate(ctx context.Context, updateID string, status string, result json.RawMessage) error {
	ctx, span := tracer.Start(ctx, "engine.CompleteUpdate",
		trace.WithAttributes(attribute.String("update_id", updateID), attribute.String("status", status)))
	defer span.End()
	// Flush any buffered events for this update before completing.
	if err := m.flushEvents(ctx); err != nil {
		slog.Warn("failed to flush events before completing update", "error", err)
	}

	u, err := m.requireInProgress(ctx, updateID)
	if err != nil {
		return err
	}

	// If journaling was used, replay journal to reconstruct final state.
	// replayAndSaveJournal handles both SaveState and cache update.
	if u.JournalVersion > 0 && status == "succeeded" {
		if _, err := m.replayAndSaveJournal(ctx, u); err != nil {
			return fmt.Errorf("journal replay: %w", err)
		}
	}

	// Record history.
	now := time.Now()
	startTime := now
	if u.StartedAt != nil {
		startTime = *u.StartedAt
	}
	if err := m.store.SaveUpdateHistory(ctx, &storage.UpdateHistory{
		OrgName:         u.OrgName,
		ProjectName:     u.ProjectName,
		StackName:       u.StackName,
		Version:         u.Version,
		UpdateID:        u.ID,
		Kind:            u.Kind,
		Status:          status,
		Config:          u.Config,
		StartTime:       startTime,
		EndTime:         &now,
		ResourceChanges: result,
	}); err != nil {
		return fmt.Errorf("save update history: %w", err)
	}

	// Complete the update.
	err = m.store.CompleteUpdate(ctx, updateID, status, result)
	if err != nil {
		return err
	}

	// Release stack lock.
	m.releaseStackLock(u.OrgName, u.ProjectName, u.StackName)
	m.activeUpdates.Add(-1)
	return nil
}

type RenewLeaseResult struct {
	Token           string
	TokenExpiration int64
}

func (m *Manager) RenewLease(ctx context.Context, updateID string, duration time.Duration) (*RenewLeaseResult, error) {
	if duration <= 0 {
		duration = m.leaseDuration
	}
	newToken := uuid.New().String()
	newExpiry := time.Now().Add(duration)
	err := m.store.RenewLease(ctx, updateID, newToken, newExpiry)
	if err != nil {
		return nil, err
	}

	// Update the in-memory lock expiry.
	u, err := m.store.GetUpdate(ctx, updateID)
	if err != nil {
		slog.Warn("failed to fetch update for lease audit", "error", err, "update_id", updateID)
	}
	if u != nil {
		key := stackKey(u.OrgName, u.ProjectName, u.StackName)
		if v, ok := m.stackLocks.Load(key); ok {
			sl := v.(*stackLock)
			sl.expiry = newExpiry
		}
	}

	return &RenewLeaseResult{
		Token:           newToken,
		TokenExpiration: newExpiry.Unix(),
	}, nil
}

func (m *Manager) CancelUpdate(ctx context.Context, org, project, stack string) error {
	active, err := m.store.GetActiveUpdate(ctx, org, project, stack)
	if err != nil {
		return err
	}
	if active == nil {
		return ErrNoActiveUpdate
	}
	err = m.store.CancelUpdate(ctx, active.ID)
	if err != nil {
		return err
	}
	m.releaseStackLock(org, project, stack)
	m.activeUpdates.Add(-1)
	return nil
}

func (m *Manager) GetUpdate(ctx context.Context, updateID string) (*storage.Update, error) {
	return m.store.GetUpdate(ctx, updateID)
}

func (m *Manager) GetActiveUpdate(ctx context.Context, org, project, stack string) (*storage.Update, error) {
	return m.store.GetActiveUpdate(ctx, org, project, stack)
}

// --- Checkpoints ---

// requireInProgress fetches the update and verifies it is in "in-progress" state.
func (m *Manager) requireInProgress(ctx context.Context, updateID string) (*storage.Update, error) {
	u, err := m.store.GetUpdate(ctx, updateID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, errors.New("update not found")
	}
	if u.Status != "in-progress" {
		return nil, ErrUpdateNotInProgress
	}
	return u, nil
}

func (m *Manager) SaveCheckpoint(ctx context.Context, updateID string, deployment []byte) error {
	ctx, span := tracer.Start(ctx, "engine.SaveCheckpoint",
		trace.WithAttributes(attribute.Int("bytes", len(deployment))))
	defer span.End()
	u, err := m.requireInProgress(ctx, updateID)
	if err != nil {
		return err
	}

	// Count resources on uncompressed data before compressing.
	resourceCount := storage.CountResources(deployment)

	// Compress before saving.
	compressed, err := gziputil.Compress(deployment)
	if err != nil {
		return fmt.Errorf("compress deployment: %w", err)
	}

	hash := sha256.Sum256(deployment)
	err = m.store.SaveState(ctx, &storage.StackState{
		OrgName:       u.OrgName,
		ProjectName:   u.ProjectName,
		StackName:     u.StackName,
		Version:       u.Version,
		Deployment:    compressed,
		Hash:          hex.EncodeToString(hash[:]),
		ResourceCount: resourceCount,
	})
	if err != nil {
		return err
	}

	m.cache.Add(stackKey(u.OrgName, u.ProjectName, u.StackName), compressed)
	return nil
}

// SaveCheckpointDelta applies a text diff to the previous state to produce the new state.
func (m *Manager) SaveCheckpointDelta(ctx context.Context, updateID string, expectedHash string, delta string, sequenceNumber int) error {
	ctx, span := tracer.Start(ctx, "engine.SaveCheckpointDelta",
		trace.WithAttributes(attribute.Int("delta_bytes", len(delta)), attribute.Int("sequence", sequenceNumber)))
	defer span.End()
	u, err := m.requireInProgress(ctx, updateID)
	if err != nil {
		return err
	}

	// Get current state to apply delta.
	current, err := m.store.GetCurrentState(ctx, u.OrgName, u.ProjectName, u.StackName)
	if err != nil {
		return err
	}

	// Apply the delta (unified diff format).
	newDeployment, err := applyDelta(current.Deployment, delta)
	if err != nil {
		return fmt.Errorf("apply delta: %w", err)
	}

	// Verify hash.
	actualHash := sha256.Sum256(newDeployment)
	actualHashStr := hex.EncodeToString(actualHash[:])
	if actualHashStr != expectedHash {
		return fmt.Errorf("hash mismatch after applying delta: expected %s, got %s", expectedHash, actualHashStr)
	}

	return m.SaveCheckpoint(ctx, updateID, newDeployment)
}

// --- Journal Entries ---

func (m *Manager) SaveJournalEntries(ctx context.Context, updateID string, entries []json.RawMessage) error {
	ctx, span := tracer.Start(ctx, "engine.SaveJournalEntries",
		trace.WithAttributes(attribute.Int("count", len(entries))))
	defer span.End()
	// Get the current max sequence for this update.
	maxSeq, err := m.store.GetMaxJournalSequence(ctx, updateID)
	if err != nil {
		return err
	}

	storageEntries := make([]storage.JournalEntry, len(entries))
	for i, raw := range entries {
		// Extract sequence_id from the entry if present.
		var entry struct {
			SequenceID int64 `json:"sequenceID"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			slog.Warn("failed to extract sequenceID from journal entry", "error", err)
		}
		seq := entry.SequenceID
		if seq == 0 {
			maxSeq++
			seq = maxSeq
		}
		storageEntries[i] = storage.JournalEntry{
			UpdateID:   updateID,
			SequenceID: seq,
			Entry:      raw,
		}
	}

	return m.store.SaveJournalEntries(ctx, storageEntries)
}

// --- Engine Events (async buffered) ---

func (m *Manager) SaveEngineEvents(ctx context.Context, updateID string, events []json.RawMessage) error {
	storageEvents := make([]storage.EngineEvent, len(events))
	for i, raw := range events {
		var ev struct {
			Sequence int `json:"sequence"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			slog.Warn("failed to extract sequence from engine event", "error", err)
		}
		storageEvents[i] = storage.EngineEvent{
			UpdateID: updateID,
			Sequence: ev.Sequence,
			Event:    raw,
		}
	}

	m.eventMu.Lock()
	m.eventBuf = append(m.eventBuf, storageEvents...)
	shouldFlush := len(m.eventBuf) >= m.eventMax
	m.eventMu.Unlock()

	if shouldFlush {
		return m.flushEvents(ctx)
	}
	return nil
}

func (m *Manager) GetEngineEvents(ctx context.Context, updateID string, offset, count int) ([]storage.EngineEvent, error) {
	// Flush buffered events and read while holding the lock so no concurrent
	// flush can start between our flush and our SQLite read.
	m.eventMu.Lock()
	_ = m.flushEventsLocked(ctx)
	events, err := m.store.GetEngineEvents(ctx, updateID, offset, count)
	m.eventMu.Unlock()
	return events, err
}

// flushEvents writes all buffered events to storage.
func (m *Manager) flushEvents(ctx context.Context) error {
	m.eventMu.Lock()
	defer m.eventMu.Unlock()
	return m.flushEventsLocked(ctx)
}

// flushEventsLocked writes buffered events to storage. Caller must hold eventMu.
func (m *Manager) flushEventsLocked(ctx context.Context) error {
	if len(m.eventBuf) == 0 {
		return nil
	}
	buf := m.eventBuf
	m.eventBuf = nil

	if err := m.store.SaveEngineEvents(ctx, buf); err != nil {
		slog.Error("failed to flush events", "error", err, "count", len(buf))
		m.eventBuf = append(buf, m.eventBuf...)
		return err
	}
	return nil
}

// eventFlusher runs periodically to flush buffered events.
func (m *Manager) eventFlusher(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(m.flushDone)

	for {
		select {
		case <-ticker.C:
			_ = m.flushEvents(context.Background())
		case <-m.flushStop:
			_ = m.flushEvents(context.Background())
			return
		}
	}
}

// --- History ---

func (m *Manager) GetHistory(ctx context.Context, org, project, stack string, pageSize, page int) ([]storage.UpdateHistory, error) {
	return m.store.GetUpdateHistory(ctx, org, project, stack, pageSize, page)
}

func (m *Manager) GetHistoryByVersion(ctx context.Context, org, project, stack string, version int) (*storage.UpdateHistory, error) {
	return m.store.GetUpdateHistoryByVersion(ctx, org, project, stack, version)
}

// --- Secrets ---

func (m *Manager) EncryptValue(ctx context.Context, org, project, stack string, plaintext []byte) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "engine.EncryptValue")
	defer span.End()
	key, err := m.getOrCreateSecretsKey(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	return m.secrets.Encrypt(key, plaintext)
}

func (m *Manager) DecryptValue(ctx context.Context, org, project, stack string, ciphertext []byte) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "engine.DecryptValue")
	defer span.End()
	key, err := m.getOrCreateSecretsKey(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	return m.secrets.Decrypt(key, ciphertext)
}

func (m *Manager) getOrCreateSecretsKey(ctx context.Context, org, project, stack string) ([]byte, error) {
	key := stackKey(org, project, stack)
	if cached, ok := m.secretsCache.Get(key); ok {
		return cached, nil
	}

	existing, err := m.store.GetSecretsKey(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		decrypted, err := m.secrets.DecryptKey(ctx, existing)
		if err != nil {
			return nil, err
		}
		m.secretsCache.Add(key, decrypted)
		return decrypted, nil
	}

	// Generate a new per-stack key and encrypt it with the master key.
	stackKey, encryptedStackKey, err := m.secrets.GenerateStackKey(ctx)
	if err != nil {
		return nil, err
	}
	if err := m.store.SaveSecretsKey(ctx, org, project, stack, encryptedStackKey); err != nil {
		return nil, err
	}
	m.secretsCache.Add(key, stackKey)
	return stackKey, nil
}

// --- Stack Locking ---

func (m *Manager) tryAcquireStackLock(org, project, stack, updateID string) bool {
	key := stackKey(org, project, stack)
	actual, _ := m.stackLocks.LoadOrStore(key, &stackLock{})
	sl := actual.(*stackLock)

	sl.mu.Lock()
	defer sl.mu.Unlock()

	// If there's an existing lock that hasn't expired, reject.
	if sl.updateID != "" && time.Now().Before(sl.expiry) {
		return false
	}

	sl.updateID = updateID
	sl.expiry = time.Now().Add(m.leaseDuration)
	return true
}

func (m *Manager) releaseStackLock(org, project, stack string) {
	key := stackKey(org, project, stack)
	if v, ok := m.stackLocks.Load(key); ok {
		sl := v.(*stackLock)
		sl.mu.Lock()
		sl.updateID = ""
		sl.expiry = time.Time{}
		sl.mu.Unlock()
	}
}

// ValidateUpdateToken checks if the given token matches the active update.
func (m *Manager) ValidateUpdateToken(ctx context.Context, updateID, token string) error {
	u, err := m.store.GetUpdate(ctx, updateID)
	if err != nil {
		return err
	}
	if u == nil {
		return errors.New("update not found")
	}
	if u.Token != token {
		return errors.New("invalid update token")
	}
	if time.Now().After(u.TokenExpiresAt) {
		return errors.New("update token expired")
	}
	return nil
}

// --- Backup ---

// Backup creates a consistent database backup and uploads to configured remote providers.
func (m *Manager) Backup(ctx context.Context) (*BackupResult, error) {
	ctx, span := tracer.Start(ctx, "engine.Backup")
	defer span.End()
	if m.backupDir == "" && len(m.backupProviders) == 0 {
		return nil, errors.New("no backup destination configured (use -backup-dir and/or -backup-s3-bucket)")
	}

	// Determine backup file location.
	dir := m.backupDir
	if dir == "" {
		dir = os.TempDir()
	}
	filename := fmt.Sprintf("backup-%s.db", time.Now().Format("20060102-150405"))
	localPath := filepath.Join(dir, filename)

	if err := m.store.Backup(ctx, localPath); err != nil {
		return nil, fmt.Errorf("vacuum into: %w", err)
	}

	result := &BackupResult{
		RemoteKeys: make(map[string]string),
	}

	if m.backupDir != "" {
		result.LocalPath = localPath
	}

	// Upload to remote providers.
	for _, p := range m.backupProviders {
		key, err := p.Upload(ctx, localPath)
		if err != nil {
			slog.Error("backup upload failed", "provider", p.Name(), "error", err)
			continue
		}
		result.RemoteKeys[p.Name()] = key

		// Prune old backups if retention is configured.
		if m.backupRetention > 0 {
			pruned, prunErr := backup.Prune(ctx, p, m.backupRetention)
			if prunErr != nil {
				slog.Error("backup pruning failed", "provider", p.Name(), "error", prunErr)
			} else if pruned > 0 {
				slog.Info("old backups pruned", "provider", p.Name(), "pruned", pruned)
			}
		}
	}

	// Clean up temp file if no local backup dir (file was only needed for upload).
	if m.backupDir == "" {
		os.Remove(localPath) //nolint:errcheck
	}

	return result, nil
}
