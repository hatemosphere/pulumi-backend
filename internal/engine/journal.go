package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

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

	hash := sha256.Sum256(resultJSON)
	err = m.store.SaveState(ctx, &storage.StackState{
		OrgName:     u.OrgName,
		ProjectName: u.ProjectName,
		StackName:   u.StackName,
		Version:     u.Version,
		Deployment:  resultJSON,
		Hash:        hex.EncodeToString(hash[:]),
	})
	if err != nil {
		return nil, err
	}

	// Update the cache so ExportState returns fresh state.
	m.cache.Add(stackKey(u.OrgName, u.ProjectName, u.StackName), resultJSON)
	return resultJSON, nil
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
	type opState struct {
		begun     bool
		completed bool
		entry     journalEntry
	}

	ops := map[int64]*opState{}
	newResources := []json.RawMessage{}                // resources added/updated by SUCCESS
	newResourceIndices := map[int64]int{}              // operationID -> index in newResources
	newResourcesToRemove := map[int64]bool{}           // operationIDs of new resources to drop
	baseIndicesToRemove := map[int64]bool{}            // base resource indices to remove
	baseIndicesToUpdate := map[int64]json.RawMessage{} // base resource index -> new state
	secretsProvider := base.Deployment.SecretsProvider
	hasRefresh := false

	for _, e := range entries {
		switch e.Kind {
		case JournalBegin:
			ops[e.OperationID] = &opState{begun: true, entry: e}

		case JournalSuccess:
			if op, ok := ops[e.OperationID]; ok {
				op.completed = true
			}
			if e.IsRefresh {
				hasRefresh = true
			}
			// Add or update the resource.
			if e.State != nil {
				if idx, ok := newResourceIndices[e.OperationID]; ok {
					newResources[idx] = *e.State
				} else {
					newResourceIndices[e.OperationID] = len(newResources)
					newResources = append(newResources, *e.State)
				}
			}
			// Mark base resources for removal.
			if e.RemoveOld != nil {
				baseIndicesToRemove[*e.RemoveOld] = true
			}
			if e.RemoveNew != nil {
				newResourcesToRemove[*e.RemoveNew] = true
			}
			if e.DeleteOld != nil {
				baseIndicesToRemove[*e.DeleteOld] = true
			}
			if e.DeleteNew != nil {
				newResourcesToRemove[*e.DeleteNew] = true
			}

		case JournalRefreshSuccess:
			if op, ok := ops[e.OperationID]; ok {
				op.completed = true
			}
			hasRefresh = true
			// Non-persisted refresh: update resources in-place to preserve ordering.
			if e.RemoveOld != nil {
				if e.State != nil {
					baseIndicesToUpdate[*e.RemoveOld] = *e.State
				} else {
					baseIndicesToRemove[*e.RemoveOld] = true
				}
			}
			if e.RemoveNew != nil {
				if e.State != nil {
					// Update new resource in-place.
					if idx, ok := newResourceIndices[*e.RemoveNew]; ok {
						newResources[idx] = *e.State
					}
				} else {
					newResourcesToRemove[*e.RemoveNew] = true
				}
			}

		case JournalFailure:
			if op, ok := ops[e.OperationID]; ok {
				op.completed = true
			}

		case JournalOutputs:
			// Update outputs on an existing resource using RemoveOld/RemoveNew.
			if e.State != nil {
				if e.RemoveOld != nil {
					baseIndicesToUpdate[*e.RemoveOld] = *e.State
				}
				if e.RemoveNew != nil {
					if idx, ok := newResourceIndices[*e.RemoveNew]; ok {
						newResources[idx] = *e.State
					}
				}
				// Fallback: try by operationID for older CLI versions.
				if e.RemoveOld == nil && e.RemoveNew == nil {
					if idx, ok := newResourceIndices[e.OperationID]; ok {
						newResources[idx] = *e.State
					}
				}
			}

		case JournalWrite:
			// A full snapshot write (e.g., initial base state from engine).
			if e.NewSnapshot != nil {
				var snap deployment
				if err := json.Unmarshal(*e.NewSnapshot, &snap); err == nil {
					base.Deployment = snap
					// Reset tracking since base changed.
					baseIndicesToRemove = map[int64]bool{}
					baseIndicesToUpdate = map[int64]json.RawMessage{}
				}
			}

		case JournalSecretsManager:
			if e.SecretsProvider != nil {
				secretsProvider = *e.SecretsProvider
			}

		case JournalRebuiltBaseState:
			if e.NewSnapshot != nil {
				var snap deployment
				if err := json.Unmarshal(*e.NewSnapshot, &snap); err == nil {
					base.Deployment = snap
					// Reset all tracking — the new base includes everything accumulated so far.
					baseIndicesToRemove = map[int64]bool{}
					baseIndicesToUpdate = map[int64]json.RawMessage{}
					newResources = nil
					newResourceIndices = map[int64]int{}
					newResourcesToRemove = map[int64]bool{}
					ops = map[int64]*opState{}
				}
			}
		}
	}

	// Merge: collect untouched base resources.
	var finalResources []json.RawMessage
	for i, r := range base.Deployment.Resources {
		idx64 := int64(i)
		if baseIndicesToRemove[idx64] {
			continue
		}
		if updated, ok := baseIndicesToUpdate[idx64]; ok {
			finalResources = append(finalResources, updated)
		} else {
			finalResources = append(finalResources, r)
		}
	}

	// Append new resources (skipping any that were marked for removal).
	for i, r := range newResources {
		opID := int64(-1)
		for oid, idx := range newResourceIndices {
			if idx == i {
				opID = oid
				break
			}
		}
		if opID >= 0 && newResourcesToRemove[opID] {
			continue
		}
		finalResources = append(finalResources, r)
	}

	// If refresh was involved, rebuild dependencies (prune dangling refs).
	if hasRefresh {
		rebuildDependencies(finalResources)
	}

	// Collect pending operations from incomplete operations.
	var pendingOps []json.RawMessage
	for _, op := range ops {
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
			SecretsProvider: secretsProvider,
			Resources:       finalResources,
			PendingOps:      pendingOps,
		},
	}, nil
}

// rebuildDependencies prunes dangling dependency references from resources.
// This is necessary after refresh operations which may delete resources.
// rebuildDependencies prunes dangling dependency references from resources.
// This is necessary after refresh operations which may delete resources.
func rebuildDependencies(resources []json.RawMessage) {
	// Collect all URNs present in the final resource set.
	urnSet := make(map[string]bool, len(resources))
	for _, r := range resources {
		// Optimization: Use a minimal struct for fast URN extraction.
		var res struct {
			URN string `json:"urn"`
		}
		if json.Unmarshal(r, &res) == nil && res.URN != "" {
			urnSet[res.URN] = true
		}
	}

	// Prune dangling references.
	for i, r := range resources {
		// Optimization: Use a struct pre-check to validate dependencies without full parsing.
		// If all dependencies are valid, we can skip the heavy map parsing entirely.
		var candidate struct {
			Dependencies         []string            `json:"dependencies"`
			Parent               string              `json:"parent"`
			PropertyDependencies map[string][]string `json:"propertyDependencies"`
		}

		// If unmarshal fails, we can't optimize, so proceed to full parsing.
		// Use a lightweight unmarshal that ignores other fields.
		if json.Unmarshal(r, &candidate) == nil {
			allValid := true

			// Check dependencies.
			for _, d := range candidate.Dependencies {
				if !urnSet[d] {
					allValid = false
					break
				}
			}

			// Check parent.
			if allValid && candidate.Parent != "" && !urnSet[candidate.Parent] {
				allValid = false
			}

			// Check propertyDependencies.
			if allValid {
				for _, deps := range candidate.PropertyDependencies {
					for _, d := range deps {
						if !urnSet[d] {
							allValid = false
							break
						}
					}
					if !allValid {
						break
					}
				}
			}

			// If everything is valid, we don't need to prune anything.
			if allValid {
				continue
			}
		}

		// Fallback: Unmarshal into map for modification.
		var res map[string]json.RawMessage
		if json.Unmarshal(r, &res) != nil {
			continue
		}
		changed := false

		// Prune dependencies.
		if depsRaw, ok := res["dependencies"]; ok {
			var deps []string
			if json.Unmarshal(depsRaw, &deps) == nil {
				filtered := make([]string, 0, len(deps))
				for _, d := range deps {
					if urnSet[d] {
						filtered = append(filtered, d)
					}
				}
				if len(filtered) != len(deps) {
					newDeps, _ := json.Marshal(filtered)
					res["dependencies"] = newDeps
					changed = true
				}
			}
		}

		// Prune parent if dangling.
		if parentRaw, ok := res["parent"]; ok {
			var parent string
			if json.Unmarshal(parentRaw, &parent) == nil && parent != "" && !urnSet[parent] {
				delete(res, "parent")
				changed = true
			}
		}

		// Prune propertyDependencies.
		if pdRaw, ok := res["propertyDependencies"]; ok {
			var pd map[string][]string
			if json.Unmarshal(pdRaw, &pd) == nil {
				pdChanged := false
				for key, deps := range pd {
					filtered := make([]string, 0, len(deps))
					for _, d := range deps {
						if urnSet[d] {
							filtered = append(filtered, d)
						}
					}
					if len(filtered) != len(deps) {
						pd[key] = filtered
						pdChanged = true
					}
				}
				if pdChanged {
					newPD, _ := json.Marshal(pd)
					res["propertyDependencies"] = newPD
					changed = true
				}
			}
		}

		if changed {
			newR, _ := json.Marshal(res)
			resources[i] = newR
		}
	}
}
