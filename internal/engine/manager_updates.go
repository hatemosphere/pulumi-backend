package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/segmentio/encoding/json"

	"github.com/google/uuid"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/hatemosphere/pulumi-backend/internal/gziputil"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// CreateUpdateResult holds the ID of a newly created update.
type CreateUpdateResult struct {
	UpdateID string
}

// cleanupExpiredUpdate attempts to auto-cancel an expired in-progress update.
func (m *Manager) cleanupExpiredUpdate(ctx context.Context, org, project, stack string, active *storage.Update) error {
	if active.Status == "in-progress" && m.clock.Now().After(active.TokenExpiresAt) {
		if err := m.store.CancelUpdate(ctx, active.ID); err != nil {
			slog.Error("failed to cancel expired update", "updateID", active.ID, "error", err)
			return ErrStackHasActiveUpdate
		}
		m.releaseStackLock(org, project, stack)
		m.activeUpdates.Add(-1)
		return nil
	}
	return ErrStackHasActiveUpdate
}

// CreateUpdate registers a new update.
func (m *Manager) CreateUpdate(ctx context.Context, org, project, stack, kind string, config, metadata json.RawMessage) (*CreateUpdateResult, error) {
	ctx, span := tracer.Start(ctx, "engine.CreateUpdate",
		trace.WithAttributes(attribute.String("stack", stackKey(org, project, stack)), attribute.String("kind", kind)))
	defer span.End()

	active, err := m.store.GetActiveUpdate(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	if active != nil {
		if err := m.cleanupExpiredUpdate(ctx, org, project, stack, active); err != nil {
			return nil, err
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

// StartUpdateResult holds the version, lease token, and journal version for a started update.
type StartUpdateResult struct {
	Version         int
	Token           string
	TokenExpiration int64
	JournalVersion  int
}

// StartUpdate transitions an update to in-progress, acquiring the stack lock and lease.
func (m *Manager) StartUpdate(ctx context.Context, updateID string, tags map[string]string, requestedJournalVersion int) (*StartUpdateResult, error) {
	ctx, span := tracer.Start(ctx, "engine.StartUpdate",
		trace.WithAttributes(attribute.String("update_id", updateID)))
	defer span.End()
	u, err := m.store.GetUpdate(ctx, updateID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrUpdateNotFound
	}

	if !m.tryAcquireStackLock(u.OrgName, u.ProjectName, u.StackName, updateID) {
		return nil, ErrStackHasActiveUpdate
	}

	st, err := m.store.GetStack(ctx, u.OrgName, u.ProjectName, u.StackName)
	if err != nil {
		m.releaseStackLock(u.OrgName, u.ProjectName, u.StackName)
		return nil, err
	}
	if st == nil {
		m.releaseStackLock(u.OrgName, u.ProjectName, u.StackName)
		return nil, ErrStackNotFound
	}
	newVersion := st.Version + 1

	if len(tags) > 0 {
		if err := m.store.UpdateStackTags(ctx, u.OrgName, u.ProjectName, u.StackName, tags); err != nil {
			m.releaseStackLock(u.OrgName, u.ProjectName, u.StackName)
			return nil, fmt.Errorf("update stack tags: %w", err)
		}
	}

	token := uuid.New().String()
	expiry := m.clock.Now().Add(m.leaseDuration)

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

// CompleteUpdate finalizes an update, replaying journals if needed and recording history.
func (m *Manager) CompleteUpdate(ctx context.Context, updateID string, status string, result json.RawMessage) error {
	ctx, span := tracer.Start(ctx, "engine.CompleteUpdate",
		trace.WithAttributes(attribute.String("update_id", updateID), attribute.String("status", status)))
	defer span.End()
	if err := m.flushEvents(ctx); err != nil {
		slog.Warn("failed to flush events before completing update", "error", err)
	}

	u, err := m.requireInProgress(ctx, updateID)
	if err != nil {
		return err
	}

	if u.JournalVersion > 0 && status == "succeeded" {
		if _, err := m.replayAndSaveJournal(ctx, u); err != nil {
			return fmt.Errorf("journal replay: %w", err)
		}
	}

	now := m.clock.Now()
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

	err = m.store.CompleteUpdate(ctx, updateID, status, result)
	if err != nil {
		return err
	}

	m.releaseStackLock(u.OrgName, u.ProjectName, u.StackName)
	m.activeUpdates.Add(-1)
	return nil
}

// RenewLeaseResult holds the new lease token and its expiration.
type RenewLeaseResult struct {
	Token           string
	TokenExpiration int64
}

// RenewLease extends the lease for an active update with a new token and expiry.
func (m *Manager) RenewLease(ctx context.Context, updateID string, duration time.Duration) (*RenewLeaseResult, error) {
	if duration <= 0 {
		duration = m.leaseDuration
	}
	newToken := uuid.New().String()
	newExpiry := m.clock.Now().Add(duration)
	err := m.store.RenewLease(ctx, updateID, newToken, newExpiry)
	if err != nil {
		return nil, err
	}

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

// CancelUpdate cancels the active update on a stack, releasing the lock.
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

// GetUpdate returns the update record for the given ID, or nil if not found.
func (m *Manager) GetUpdate(ctx context.Context, updateID string) (*storage.Update, error) {
	return m.store.GetUpdate(ctx, updateID)
}

// GetActiveUpdate returns the in-progress update for a stack, or nil if none.
func (m *Manager) GetActiveUpdate(ctx context.Context, org, project, stack string) (*storage.Update, error) {
	return m.store.GetActiveUpdate(ctx, org, project, stack)
}

// requireInProgress fetches the update and verifies it is in "in-progress" state.
func (m *Manager) requireInProgress(ctx context.Context, updateID string) (*storage.Update, error) {
	u, err := m.store.GetUpdate(ctx, updateID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrUpdateNotFound
	}
	if u.Status != "in-progress" {
		return nil, ErrUpdateNotInProgress
	}
	return u, nil
}

// SaveCheckpoint persists a full deployment checkpoint for an in-progress update.
func (m *Manager) SaveCheckpoint(ctx context.Context, updateID string, deployment []byte) error {
	ctx, span := tracer.Start(ctx, "engine.SaveCheckpoint",
		trace.WithAttributes(attribute.Int("bytes", len(deployment))))
	defer span.End()
	u, err := m.requireInProgress(ctx, updateID)
	if err != nil {
		return err
	}

	resourceCount := storage.CountResources(deployment)
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

	current, err := m.store.GetCurrentState(ctx, u.OrgName, u.ProjectName, u.StackName)
	if err != nil {
		return err
	}

	newDeployment, err := applyDelta(current.Deployment, delta)
	if err != nil {
		return fmt.Errorf("apply delta: %w", err)
	}

	actualHash := sha256.Sum256(newDeployment)
	actualHashStr := hex.EncodeToString(actualHash[:])
	if actualHashStr != expectedHash {
		return fmt.Errorf("hash mismatch after applying delta: expected %s, got %s", expectedHash, actualHashStr)
	}

	return m.SaveCheckpoint(ctx, updateID, newDeployment)
}

// SaveJournalEntries appends journal entries for an update, assigning sequence IDs as needed.
func (m *Manager) SaveJournalEntries(ctx context.Context, updateID string, entries []json.RawMessage) error {
	ctx, span := tracer.Start(ctx, "engine.SaveJournalEntries",
		trace.WithAttributes(attribute.Int("count", len(entries))))
	defer span.End()
	maxSeq, err := m.store.GetMaxJournalSequence(ctx, updateID)
	if err != nil {
		return err
	}

	storageEntries := make([]storage.JournalEntry, len(entries))
	for i, raw := range entries {
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
