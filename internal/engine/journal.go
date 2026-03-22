package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/segmentio/encoding/json"

	"github.com/hatemosphere/pulumi-backend/internal/gziputil"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// Journal entry kinds (matching Pulumi's JournalEntryKind).
const (
	JournalBegin            = 0
	JournalSuccess          = 1
	JournalFailure          = 2
	JournalRefreshSuccess   = 3
	JournalOutputs          = 4
	JournalWrite            = 5
	JournalSecretsManager   = 6
	JournalRebuiltBaseState = 7
)

// journalEntry is the deserialized form of a journal entry from the CLI.
// Field names and JSON tags must match apitype.JournalEntry exactly.
type journalEntry struct {
	Version               int              `json:"version"`
	Kind                  int              `json:"kind"`
	SequenceID            int64            `json:"sequenceID"`
	OperationID           int64            `json:"operationID"`
	RemoveOld             *int64           `json:"removeOld"`
	RemoveNew             *int64           `json:"removeNew"`
	PendingReplacementOld *int64           `json:"pendingReplacementOld,omitempty"`
	PendingReplacementNew *int64           `json:"pendingReplacementNew,omitempty"`
	DeleteOld             *int64           `json:"deleteOld,omitempty"`
	DeleteNew             *int64           `json:"deleteNew,omitempty"`
	State                 *json.RawMessage `json:"state,omitempty"`
	Operation             *json.RawMessage `json:"operation,omitempty"`
	IsRefresh             bool             `json:"isRefresh,omitempty"`
	SecretsProvider       *json.RawMessage `json:"secretsProvider,omitempty"`
	NewSnapshot           *json.RawMessage `json:"newSnapshot,omitempty"`
}

// deployment is the shape of a Pulumi deployment for journal replay.
type deployment struct {
	Manifest        json.RawMessage   `json:"manifest"`
	SecretsProvider json.RawMessage   `json:"secrets_providers,omitempty"`
	Resources       []json.RawMessage `json:"resources"`
	PendingOps      []json.RawMessage `json:"pending_operations,omitempty"`
}

// checkpoint wraps a versioned deployment.
type checkpoint struct {
	Version    int        `json:"version"`
	Deployment deployment `json:"deployment"`
}

// replayAndSaveJournal fetches journal entries, replays them against the base state,
// and saves the resulting snapshot. Returns the resulting deployment JSON.
func (m *Manager) replayAndSaveJournal(ctx context.Context, u *storage.Update) ([]byte, error) {
	// Get base state.
	baseState, err := m.store.GetCurrentState(ctx, u.OrgName, u.ProjectName, u.StackName)
	if err != nil {
		return nil, fmt.Errorf("get base state: %w", err)
	}

	var base checkpoint
	if baseState != nil && len(baseState.Deployment) > 0 {
		if err := json.Unmarshal(baseState.Deployment, &base); err != nil {
			return nil, fmt.Errorf("unmarshal base state: %w", err)
		}
	} else {
		base = checkpoint{Version: 3, Deployment: deployment{}}
	}

	// Get journal entries.
	entries, err := m.store.GetJournalEntries(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("get journal entries: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil // Nothing to replay.
	}

	// Parse and sort entries.
	parsed := make([]journalEntry, 0, len(entries))
	for _, e := range entries {
		var je journalEntry
		if err := json.Unmarshal(e.Entry, &je); err != nil {
			return nil, fmt.Errorf("unmarshal journal entry seq=%d: %w", e.SequenceID, err)
		}
		je.SequenceID = e.SequenceID
		parsed = append(parsed, je)
	}
	sort.Slice(parsed, func(i, j int) bool {
		return parsed[i].SequenceID < parsed[j].SequenceID
	})

	// Replay entries against base state.
	result, err := replayJournalEntries(base, parsed)
	if err != nil {
		return nil, fmt.Errorf("replay: %w", err)
	}

	// Marshal and save.
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}

	resourceCount := storage.CountResources(resultJSON)

	// Compress before saving to cache and store.
	compressed, err := gziputil.Compress(resultJSON)
	if err != nil {
		return nil, fmt.Errorf("compress journal result: %w", err)
	}

	hash := sha256.Sum256(resultJSON)
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
		return nil, err
	}

	// Update the cache so ExportState returns fresh compressed state.
	m.cache.Add(stackKey(u.OrgName, u.ProjectName, u.StackName), compressed)
	return resultJSON, nil
}

// opState tracks the lifecycle of a single journal operation.
type opState struct {
	begun     bool
	completed bool
	entry     journalEntry
}

// replayState holds all tracking variables during journal replay.
type replayState struct {
	ops                  map[int64]*opState
	newResources         []json.RawMessage
	newResourceIndices   map[int64]int             // operationID -> index in newResources
	newResourcesToRemove map[int64]bool            // operationIDs of new resources to drop
	baseIndicesToRemove  map[int64]bool            // base resource indices to remove
	baseIndicesToUpdate  map[int64]json.RawMessage // base resource index -> new state
	secretsProvider      json.RawMessage
	hasRefresh           bool
}

func newReplayState(base checkpoint) *replayState {
	return &replayState{
		ops:                  map[int64]*opState{},
		newResources:         []json.RawMessage{},
		newResourceIndices:   map[int64]int{},
		newResourcesToRemove: map[int64]bool{},
		baseIndicesToRemove:  map[int64]bool{},
		baseIndicesToUpdate:  map[int64]json.RawMessage{},
		secretsProvider:      base.Deployment.SecretsProvider,
	}
}

func handleBegin(e *journalEntry, rs *replayState) {
	rs.ops[e.OperationID] = &opState{begun: true, entry: *e}
}

func handleSuccess(e *journalEntry, rs *replayState) {
	if op, ok := rs.ops[e.OperationID]; ok {
		op.completed = true
	}
	if e.IsRefresh {
		rs.hasRefresh = true
	}
	// Add or update the resource.
	if e.State != nil {
		if idx, ok := rs.newResourceIndices[e.OperationID]; ok {
			rs.newResources[idx] = *e.State
		} else {
			rs.newResourceIndices[e.OperationID] = len(rs.newResources)
			rs.newResources = append(rs.newResources, *e.State)
		}
	}
	// Mark base resources for removal.
	if e.RemoveOld != nil {
		rs.baseIndicesToRemove[*e.RemoveOld] = true
	}
	if e.RemoveNew != nil {
		rs.newResourcesToRemove[*e.RemoveNew] = true
	}
	if e.DeleteOld != nil {
		rs.baseIndicesToRemove[*e.DeleteOld] = true
	}
	if e.DeleteNew != nil {
		rs.newResourcesToRemove[*e.DeleteNew] = true
	}
}

func handleRefreshSuccess(e *journalEntry, rs *replayState) {
	if op, ok := rs.ops[e.OperationID]; ok {
		op.completed = true
	}
	rs.hasRefresh = true
	// Non-persisted refresh: update resources in-place to preserve ordering.
	if e.RemoveOld != nil {
		if e.State != nil {
			rs.baseIndicesToUpdate[*e.RemoveOld] = *e.State
		} else {
			rs.baseIndicesToRemove[*e.RemoveOld] = true
		}
	}
	if e.RemoveNew != nil {
		if e.State != nil {
			if idx, ok := rs.newResourceIndices[*e.RemoveNew]; ok {
				rs.newResources[idx] = *e.State
			}
		} else {
			rs.newResourcesToRemove[*e.RemoveNew] = true
		}
	}
}

func handleFailure(e *journalEntry, rs *replayState) {
	if op, ok := rs.ops[e.OperationID]; ok {
		op.completed = true
	}
}

func handleOutputs(e *journalEntry, rs *replayState) {
	if e.State == nil {
		return
	}
	if e.RemoveOld != nil {
		rs.baseIndicesToUpdate[*e.RemoveOld] = *e.State
	}
	if e.RemoveNew != nil {
		if idx, ok := rs.newResourceIndices[*e.RemoveNew]; ok {
			rs.newResources[idx] = *e.State
		}
	}
	// Fallback: try by operationID for older CLI versions.
	if e.RemoveOld == nil && e.RemoveNew == nil {
		if idx, ok := rs.newResourceIndices[e.OperationID]; ok {
			rs.newResources[idx] = *e.State
		}
	}
}

func handleWrite(e *journalEntry, rs *replayState, base *checkpoint) {
	if e.NewSnapshot == nil {
		return
	}
	var snap deployment
	if err := json.Unmarshal(*e.NewSnapshot, &snap); err == nil {
		base.Deployment = snap
		rs.baseIndicesToRemove = map[int64]bool{}
		rs.baseIndicesToUpdate = map[int64]json.RawMessage{}
	}
}

func handleSecretsManager(e *journalEntry, rs *replayState) {
	if e.SecretsProvider != nil {
		rs.secretsProvider = *e.SecretsProvider
	}
}

func handleRebuiltBaseState(e *journalEntry, rs *replayState, base *checkpoint) {
	if e.NewSnapshot == nil {
		return
	}
	var snap deployment
	if err := json.Unmarshal(*e.NewSnapshot, &snap); err == nil {
		base.Deployment = snap
		// Reset all tracking — the new base includes everything accumulated so far.
		rs.baseIndicesToRemove = map[int64]bool{}
		rs.baseIndicesToUpdate = map[int64]json.RawMessage{}
		rs.newResources = nil
		rs.newResourceIndices = map[int64]int{}
		rs.newResourcesToRemove = map[int64]bool{}
		rs.ops = map[int64]*opState{}
	}
}

// replayJournalEntries replays journal entries against a base checkpoint to produce a new checkpoint.
//
// The algorithm follows Pulumi's reconstruction logic:
// 1. Start from base snapshot
// 2. Track new resources added by SUCCESS entries
// 3. Track resources marked for deletion (removeOld/removeNew/deleteOld/deleteNew)
// 4. Track pending operations from BEGIN entries (cleared by SUCCESS/FAILURE)
// 5. Merge: new resources + untouched base resources = final resources
// 6. Collect pending ops from any incomplete operations
func replayJournalEntries(base checkpoint, entries []journalEntry) (checkpoint, error) {
	rs := newReplayState(base)

	for i := range entries {
		e := &entries[i]
		switch e.Kind {
		case JournalBegin:
			handleBegin(e, rs)
		case JournalSuccess:
			handleSuccess(e, rs)
		case JournalRefreshSuccess:
			handleRefreshSuccess(e, rs)
		case JournalFailure:
			handleFailure(e, rs)
		case JournalOutputs:
			handleOutputs(e, rs)
		case JournalWrite:
			handleWrite(e, rs, &base)
		case JournalSecretsManager:
			handleSecretsManager(e, rs)
		case JournalRebuiltBaseState:
			handleRebuiltBaseState(e, rs, &base)
		}
	}

	// Merge: collect untouched base resources.
	var finalResources []json.RawMessage
	for i, r := range base.Deployment.Resources {
		idx64 := int64(i)
		if rs.baseIndicesToRemove[idx64] {
			continue
		}
		if updated, ok := rs.baseIndicesToUpdate[idx64]; ok {
			finalResources = append(finalResources, updated)
		} else {
			finalResources = append(finalResources, r)
		}
	}

	// Build reverse index: resource index -> operationID.
	indexToOpID := make(map[int]int64, len(rs.newResourceIndices))
	for opID, idx := range rs.newResourceIndices {
		indexToOpID[idx] = opID
	}

	// Append new resources (skipping any that were marked for removal).
	for i, r := range rs.newResources {
		if opID, ok := indexToOpID[i]; ok && rs.newResourcesToRemove[opID] {
			continue
		}
		finalResources = append(finalResources, r)
	}

	// If refresh was involved, rebuild dependencies (prune dangling refs).
	if rs.hasRefresh {
		rebuildDependencies(finalResources)
	}

	// Collect pending operations from incomplete operations.
	var pendingOps []json.RawMessage
	for _, op := range rs.ops {
		if op.begun && !op.completed && op.entry.Operation != nil {
			pendingOps = append(pendingOps, *op.entry.Operation)
		}
	}
	// Also carry forward base pending CREATE ops (those without matching journal entries).
	pendingOps = append(pendingOps, base.Deployment.PendingOps...)

	return checkpoint{
		Version: 3,
		Deployment: deployment{
			Manifest:        base.Deployment.Manifest,
			SecretsProvider: rs.secretsProvider,
			Resources:       finalResources,
			PendingOps:      pendingOps,
		},
	}, nil
}

// rebuildDependencies prunes dangling dependency references from resources.
// This is necessary after refresh operations which may delete resources.
func rebuildDependencies(resources []json.RawMessage) {
	urnSet := make(map[string]bool, len(resources))
	for _, r := range resources {
		var res struct {
			URN string `json:"urn"`
		}
		if json.Unmarshal(r, &res) == nil && res.URN != "" {
			urnSet[res.URN] = true
		}
	}

	for i, r := range resources {
		var res map[string]any
		if json.Unmarshal(r, &res) != nil {
			continue
		}
		changed := false

		if deps, ok := res["dependencies"].([]any); ok {
			filtered := make([]any, 0, len(deps))
			for _, d := range deps {
				if s, ok := d.(string); ok && urnSet[s] {
					filtered = append(filtered, d)
				}
			}
			if len(filtered) != len(deps) {
				res["dependencies"] = filtered
				changed = true
			}
		}

		if parent, ok := res["parent"].(string); ok && parent != "" && !urnSet[parent] {
			delete(res, "parent")
			changed = true
		}

		if pd, ok := res["propertyDependencies"].(map[string]any); ok {
			for key, val := range pd {
				deps, ok := val.([]any)
				if !ok {
					continue
				}
				filtered := make([]any, 0, len(deps))
				for _, d := range deps {
					if s, ok := d.(string); ok && urnSet[s] {
						filtered = append(filtered, d)
					}
				}
				if len(filtered) != len(deps) {
					if len(filtered) == 0 {
						delete(pd, key)
					} else {
						pd[key] = filtered
					}
					changed = true
				}
			}
			if len(pd) == 0 {
				delete(res, "propertyDependencies")
				changed = true
			}
		}

		if changed {
			newR, _ := json.Marshal(res)
			resources[i] = newR
		}
	}
}
