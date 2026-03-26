package engine

import (
	"context"
	"log/slog"
	"time"

	"github.com/segmentio/encoding/json"

	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// SaveEngineEvents buffers engine events for async flush to storage.
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

	m.events.mu.Lock()
	m.events.buf = append(m.events.buf, storageEvents...)
	shouldFlush := len(m.events.buf) >= m.events.max
	m.events.mu.Unlock()

	if shouldFlush {
		return m.flushEvents(ctx)
	}
	return nil
}

// GetEngineEvents flushes buffered events and returns events for an update starting at offset.
func (m *Manager) GetEngineEvents(ctx context.Context, updateID string, offset, count int) ([]storage.EngineEvent, error) {
	m.events.mu.Lock()
	_ = m.flushEventsLocked(ctx)
	events, err := m.store.GetEngineEvents(ctx, updateID, offset, count)
	m.events.mu.Unlock()
	return events, err
}

// flushEvents writes all buffered events to storage.
func (m *Manager) flushEvents(ctx context.Context) error {
	m.events.mu.Lock()
	defer m.events.mu.Unlock()
	return m.flushEventsLocked(ctx)
}

// flushEventsLocked writes buffered events to storage. Caller must hold events.mu.
func (m *Manager) flushEventsLocked(ctx context.Context) error {
	if len(m.events.buf) == 0 {
		return nil
	}
	buf := m.events.buf
	m.events.buf = nil

	if err := m.store.SaveEngineEvents(ctx, buf); err != nil {
		slog.Error("failed to flush events", "error", err, "count", len(buf))
		m.events.buf = append(buf, m.events.buf...)
		return err
	}
	return nil
}

// eventFlusher runs periodically to flush buffered events.
func (m *Manager) eventFlusher(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(m.events.done)

	for {
		select {
		case <-ticker.C:
			_ = m.flushEvents(m.backgroundCtx)
		case <-m.events.stop:
			_ = m.flushEvents(m.backgroundCtx)
			return
		}
	}
}

// GetHistory returns a page of update history for a stack.
func (m *Manager) GetHistory(ctx context.Context, org, project, stack string, pageSize, page int) ([]storage.UpdateHistory, error) {
	return m.store.GetUpdateHistory(ctx, org, project, stack, pageSize, page)
}

// GetHistoryByVersion returns a single update history entry by version number.
func (m *Manager) GetHistoryByVersion(ctx context.Context, org, project, stack string, version int) (*storage.UpdateHistory, error) {
	return m.store.GetUpdateHistoryByVersion(ctx, org, project, stack, version)
}

func (m *Manager) tryAcquireStackLock(org, project, stack, updateID string) bool {
	key := stackKey(org, project, stack)
	actual, _ := m.stackLocks.LoadOrStore(key, &stackLock{})
	sl := actual.(*stackLock)

	sl.mu.Lock()
	defer sl.mu.Unlock()

	if sl.updateID != "" && m.clock.Now().Before(sl.expiry) {
		return false
	}

	sl.updateID = updateID
	sl.expiry = m.clock.Now().Add(m.leaseDuration)
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
		return ErrUpdateNotFound
	}
	if u.Token != token {
		return ErrInvalidUpdateToken
	}
	if m.clock.Now().After(u.TokenExpiresAt) {
		return ErrUpdateTokenExpired
	}
	return nil
}
