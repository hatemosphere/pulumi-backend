package engine

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// ManagerConfig holds tuning parameters for the engine manager.
type ManagerConfig struct {
	LeaseDuration      time.Duration
	CacheSize          int
	EventBufferSize    int
	EventFlushInterval time.Duration
	BackupDir          string
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
	}

	cache, err := lru.New[string, []byte](cfg.CacheSize)
	if err != nil {
		return nil, err
	}
	secretsCache, err := lru.New[string, []byte](cfg.CacheSize)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		store:         store,
		secrets:       secrets,
		cache:         cache,
		secretsCache:  secretsCache,
		leaseDuration: cfg.LeaseDuration,
		backupDir:     cfg.BackupDir,
		eventMax:      cfg.EventBufferSize,
		flushStop:     make(chan struct{}),
		flushDone:     make(chan struct{}),
	}

	// Start the periodic event flusher.
	go m.eventFlusher(cfg.EventFlushInterval)

	return m, nil
}

// Shutdown flushes buffered events and stops the background flusher.
func (m *Manager) Shutdown() {
	close(m.flushStop)
	<-m.flushDone
}

// ActiveUpdateCount returns the number of currently active (in-progress) updates.
func (m *Manager) ActiveUpdateCount() int64 {
	return m.activeUpdates.Load()
}

func stackKey(org, project, stack string) string {
	return org + "/" + project + "/" + stack
}

// --- Stack Operations ---

func (m *Manager) CreateStack(ctx context.Context, org, project, stackName string, tags map[string]string) error {
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
			if decompressed, err := maybeDecompress(state.Deployment); err == nil {
				deploymentData = decompressed
			}

			if err := json.Unmarshal(deploymentData, &deployment); err == nil {
				if len(deployment.Deployment.Resources) > 0 {
					return fmt.Errorf("stack still has %d resources; use force to delete anyway", len(deployment.Deployment.Resources))
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
	m.cache.Remove(stackKey(org, oldProject, oldName))
	m.secretsCache.Remove(stackKey(org, oldProject, oldName))
	return m.store.RenameStack(ctx, org, oldProject, oldName, newProject, newName)
}

// --- State Export/Import ---

func (m *Manager) ExportState(ctx context.Context, org, project, stack string, version *int) ([]byte, error) {
	key := stackKey(org, project, stack)

	// Check cache for current version.
	if version == nil {
		if cachedCompressed, ok := m.cache.Get(key); ok {
			// Cache stores compressed data. Decompress for legacy export.
			return decompress(cachedCompressed)
		}
	}

	var state *storage.StackState
	var err error
	if version != nil {
		state, err = m.store.GetStateVersion(ctx, org, project, stack, *version)
	} else {
		state, err = m.store.GetCurrentState(ctx, org, project, stack)
	}
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errors.New("stack not found")
	}

	// Cache current state (we need to compress it first since store returns uncompressed).
	if version == nil {
		compressed, err := compress(state.Deployment)
		if err == nil {
			m.cache.Add(key, compressed)
		}
	}
	return state.Deployment, nil
}

// ExportStateCompressed returns raw deployment bytes, potentially still gzip-compressed.
// Returns (data, isGzipCompressed, error). Used for zero-copy gzip export.
func (m *Manager) ExportStateCompressed(ctx context.Context, org, project, stack string, version *int) ([]byte, bool, error) {
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
		if compressed, err := compress(data); err == nil {
			m.cache.Add(key, compressed)
			return compressed, true, nil
		}
	}

	return data, isCompressed, nil
}

func (m *Manager) ImportState(ctx context.Context, org, project, stack string, deployment []byte) error {
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

	// Compress before saving to cache and store (so we don't double compress in store).
	compressed, err := compress(deployment)
	if err != nil {
		return fmt.Errorf("compress deployment: %w", err)
	}

	err = m.store.SaveState(ctx, &storage.StackState{
		OrgName:     org,
		ProjectName: project,
		StackName:   stack,
		Version:     newVersion,
		Deployment:  compressed, // Send compressed data
		Hash:        hex.EncodeToString(hash[:]),
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
				return nil, fmt.Errorf("cancel expired update %s: %w", active.ID, err)
			}
			m.releaseStackLock(org, project, stack)
			m.activeUpdates.Add(-1)
		} else if active.Status != "not-started" || !time.Now().After(active.TokenExpiresAt.Add(m.leaseDuration)) {
			return nil, fmt.Errorf("stack already has an active update: %s", active.ID)
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
	u, err := m.store.GetUpdate(ctx, updateID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("update not found: %s", updateID)
	}

	// Acquire stack lock.
	if !m.tryAcquireStackLock(u.OrgName, u.ProjectName, u.StackName, updateID) {
		return nil, errors.New("stack is locked by another update")
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
			return nil, fmt.Errorf("update stack tags: %w", err)
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
	// Flush any buffered events for this update before completing.
	if err := m.flushEvents(ctx); err != nil {
		slog.Warn("failed to flush events before completing update", "error", err)
	}

	u, err := m.store.GetUpdate(ctx, updateID)
	if err != nil {
		return err
	}
	if u == nil {
		return errors.New("update not found")
	}

	// If journaling was used, replay journal to reconstruct final state.
	if u.JournalVersion > 0 && status == "succeeded" {
		resultJSON, err := m.replayAndSaveJournal(ctx, u)
		if err != nil {
			return fmt.Errorf("journal replay: %w", err)
		}

		// Only save state if journal replay produced data (e.g. preview has no journal entries).
		if resultJSON != nil {
			compressed, err := compress(resultJSON)
			if err == nil {
				m.cache.Add(stackKey(u.OrgName, u.ProjectName, u.StackName), compressed)
			}

			hash := sha256.Sum256(resultJSON)
			err = m.store.SaveState(ctx, &storage.StackState{
				OrgName:     u.OrgName,
				ProjectName: u.ProjectName,
				StackName:   u.StackName,
				Version:     u.Version,
				Deployment:  compressed,
				Hash:        hex.EncodeToString(hash[:]),
			})
			if err != nil {
				return err
			}
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
	u, _ := m.store.GetUpdate(ctx, updateID)
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
		return errors.New("no active update to cancel")
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

func (m *Manager) SaveCheckpoint(ctx context.Context, updateID string, deployment []byte) error {
	u, err := m.store.GetUpdate(ctx, updateID)
	if err != nil {
		return err
	}
	if u == nil {
		return errors.New("update not found")
	}

	// Compress before saving.
	compressed, err := compress(deployment)
	if err != nil {
		return fmt.Errorf("compress deployment: %w", err)
	}

	hash := sha256.Sum256(deployment)
	err = m.store.SaveState(ctx, &storage.StackState{
		OrgName:     u.OrgName,
		ProjectName: u.ProjectName,
		StackName:   u.StackName,
		Version:     u.Version,
		Deployment:  compressed, // Send compressed data
		Hash:        hex.EncodeToString(hash[:]),
	})
	if err != nil {
		return err
	}

	m.cache.Add(stackKey(u.OrgName, u.ProjectName, u.StackName), compressed)
	return nil
}

// Helpers for compression
func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

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

func decompress(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	return io.ReadAll(gr)
}

// SaveCheckpointDelta applies a text diff to the previous state to produce the new state.
func (m *Manager) SaveCheckpointDelta(ctx context.Context, updateID string, expectedHash string, delta string, sequenceNumber int) error {
	u, err := m.store.GetUpdate(ctx, updateID)
	if err != nil {
		return err
	}
	if u == nil {
		return errors.New("update not found")
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
	// Get the current max sequence for this update.
	existing, err := m.store.GetJournalEntries(ctx, updateID)
	if err != nil {
		return err
	}
	var maxSeq int64
	for _, e := range existing {
		if e.SequenceID > maxSeq {
			maxSeq = e.SequenceID
		}
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
	key, err := m.getOrCreateSecretsKey(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	return m.secrets.Encrypt(key, plaintext)
}

func (m *Manager) DecryptValue(ctx context.Context, org, project, stack string, ciphertext []byte) ([]byte, error) {
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
		decrypted, err := m.secrets.DecryptKey(existing)
		if err != nil {
			return nil, err
		}
		m.secretsCache.Add(key, decrypted)
		return decrypted, nil
	}

	// Generate a new per-stack key and encrypt it with the master key.
	stackKey, encryptedStackKey, err := m.secrets.GenerateStackKey()
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

// Backup creates a consistent backup of the database.
// Returns the path to the backup file.
func (m *Manager) Backup(ctx context.Context) (string, error) {
	if m.backupDir == "" {
		return "", errors.New("backup directory not configured (use -backup-dir flag)")
	}
	path := filepath.Join(m.backupDir, fmt.Sprintf("backup-%s.db", time.Now().Format("20060102-150405")))
	return path, m.store.Backup(ctx, path)
}
