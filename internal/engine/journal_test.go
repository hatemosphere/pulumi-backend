package engine

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create a JSON RawMessage from a string.
func raw(s string) *json.RawMessage {
	r := json.RawMessage(s)
	return &r
}

// Helper to create int64 pointer
func i64(i int64) *int64 {
	return &i
}

func TestReplayJournalEntries_Basic(t *testing.T) {
	base := checkpoint{
		Version: 3,
		Deployment: deployment{
			Manifest:  json.RawMessage(`{}`),
			Resources: []json.RawMessage{json.RawMessage(`{"urn":"urn:pulumi:stack::proj::type::res1"}`)},
		},
	}

	entries := []journalEntry{
		{
			Kind:        JournalBegin,
			SequenceID:  1,
			OperationID: 1,
			Operation:   raw(`{"urn":"urn:pulumi:stack::proj::type::res2"}`), // Pending create
		},
		{
			Kind:        JournalSuccess,
			SequenceID:  2,
			OperationID: 1,
			State:       raw(`{"urn":"urn:pulumi:stack::proj::type::res2","id":"id2"}`),
			// No RemoveOld/RemoveNew means pure addition
		},
	}

	final, err := replayJournalEntries(base, entries)
	require.NoError(t, err)

	assert.Len(t, final.Deployment.Resources, 2)
	assert.JSONEq(t, `{"urn":"urn:pulumi:stack::proj::type::res1"}`, string(final.Deployment.Resources[0]))
	assert.JSONEq(t, `{"urn":"urn:pulumi:stack::proj::type::res2","id":"id2"}`, string(final.Deployment.Resources[1]))
	assert.Empty(t, final.Deployment.PendingOps, "Pending ops should be cleared on success")
}

func TestReplayJournalEntries_Update(t *testing.T) {
	base := checkpoint{
		Version: 3,
		Deployment: deployment{
			Resources: []json.RawMessage{
				json.RawMessage(`{"urn":"urn:pulumi:stack::proj::type::res1","prop":"old"}`),
			},
		},
	}

	entries := []journalEntry{
		{
			Kind:        JournalBegin,
			SequenceID:  1,
			OperationID: 1,
		},
		{
			Kind:        JournalSuccess,
			SequenceID:  2,
			OperationID: 1,
			State:       raw(`{"urn":"urn:pulumi:stack::proj::type::res1","prop":"new"}`),
			RemoveOld:   i64(0), // Replace index 0
		},
	}

	final, err := replayJournalEntries(base, entries)
	require.NoError(t, err)

	assert.Len(t, final.Deployment.Resources, 1)
	assert.JSONEq(t, `{"urn":"urn:pulumi:stack::proj::type::res1","prop":"new"}`, string(final.Deployment.Resources[0]))
}

func TestReplayJournalEntries_Delete(t *testing.T) {
	base := checkpoint{
		Version: 3,
		Deployment: deployment{
			Resources: []json.RawMessage{
				json.RawMessage(`{"urn":"res1"}`),
				json.RawMessage(`{"urn":"res2"}`),
			},
		},
	}

	entries := []journalEntry{
		{
			Kind:        JournalBegin,
			SequenceID:  1,
			OperationID: 1,
		},
		{
			Kind:        JournalSuccess,
			SequenceID:  2,
			OperationID: 1,
			DeleteOld:   i64(0), // Delete index 0 (res1)
		},
	}

	final, err := replayJournalEntries(base, entries)
	require.NoError(t, err)

	assert.Len(t, final.Deployment.Resources, 1)
	assert.JSONEq(t, `{"urn":"res2"}`, string(final.Deployment.Resources[0]))
}

func TestReplayJournalEntries_Interleaved(t *testing.T) {
	// Simulate parallel updates:
	// Op1: Creates res3
	// Op2: Deletes res1
	base := checkpoint{
		Version: 3,
		Deployment: deployment{
			Resources: []json.RawMessage{
				json.RawMessage(`{"urn":"res1"}`),
				json.RawMessage(`{"urn":"res2"}`),
			},
		},
	}

	entries := []journalEntry{
		{Kind: JournalBegin, SequenceID: 1, OperationID: 1}, // Start Create res3
		{Kind: JournalBegin, SequenceID: 2, OperationID: 2}, // Start Delete res1

		// Finish Delete res1 first
		{
			Kind:        JournalSuccess,
			SequenceID:  3,
			OperationID: 2,
			DeleteOld:   i64(0),
		},

		// Finish Create res3
		{
			Kind:        JournalSuccess,
			SequenceID:  4,
			OperationID: 1,
			State:       raw(`{"urn":"res3"}`),
		},
	}

	final, err := replayJournalEntries(base, entries)
	require.NoError(t, err)

	// Expected: res2 (preserved), res3 (added). res1 (deleted).
	assert.Len(t, final.Deployment.Resources, 2)
	assert.JSONEq(t, `{"urn":"res2"}`, string(final.Deployment.Resources[0]))
	assert.JSONEq(t, `{"urn":"res3"}`, string(final.Deployment.Resources[1]))
}

func TestReplayJournalEntries_Refresh(t *testing.T) {
	// Refresh updates resources in-place.
	base := checkpoint{
		Version: 3,
		Deployment: deployment{
			Resources: []json.RawMessage{
				json.RawMessage(`{"urn":"res1","val":"old"}`),
			},
		},
	}

	entries := []journalEntry{
		{
			Kind:        JournalRefreshSuccess,
			SequenceID:  1,
			OperationID: 1,
			State:       raw(`{"urn":"res1","val":"refreshed"}`),
			IsRefresh:   true,
			RemoveOld:   i64(0), // Update index 0
		},
	}

	final, err := replayJournalEntries(base, entries)
	require.NoError(t, err)

	assert.Len(t, final.Deployment.Resources, 1)
	assert.JSONEq(t, `{"urn":"res1","val":"refreshed"}`, string(final.Deployment.Resources[0]))
}

func TestReplayJournalEntries_PendingOps(t *testing.T) {
	// Verify that ops started but not finished end up in PendingOps
	base := checkpoint{
		Deployment: deployment{
			Resources: []json.RawMessage{},
		},
	}

	entries := []journalEntry{
		{
			Kind:        JournalBegin,
			SequenceID:  1,
			OperationID: 100,
			Operation:   raw(`{"urn":"res1","type":"creating"}`),
		},
		// No matching Success/Failure
	}

	final, err := replayJournalEntries(base, entries)
	require.NoError(t, err)

	assert.Len(t, final.Deployment.PendingOps, 1)
	assert.JSONEq(t, `{"urn":"res1","type":"creating"}`, string(final.Deployment.PendingOps[0]))
}

func TestReplayJournalEntries_SnapshotReset(t *testing.T) {
	// Verify JournalWrite and JournalRebuiltBaseState which reset the base.
	base := checkpoint{
		Version: 3,
		Deployment: deployment{
			Resources: []json.RawMessage{json.RawMessage(`{"urn":"initial"}`)},
		},
	}

	entries := []journalEntry{
		// 1. Add a resource
		{
			Kind:        JournalSuccess,
			SequenceID:  1,
			OperationID: 1,
			State:       raw(`{"urn":"added"}`),
		},
		// 2. Full reset via JournalRebuiltBaseState
		{
			Kind:        JournalRebuiltBaseState,
			SequenceID:  2,
			NewSnapshot: raw(`{"manifest":{},"resources":[{"urn":"reset_base"}]}`),
		},
		// 3. Add another resource after reset
		{
			Kind:        JournalSuccess,
			SequenceID:  3,
			OperationID: 2,
			State:       raw(`{"urn":"added_after_reset"}`),
		},
	}

	final, err := replayJournalEntries(base, entries)
	require.NoError(t, err)

	// "initial" and "added" should be gone.
	// "reset_base" should be present (from snapshot).
	// "added_after_reset" should be present.
	assert.Len(t, final.Deployment.Resources, 2)
	assert.JSONEq(t, `{"urn":"reset_base"}`, string(final.Deployment.Resources[0]))
	assert.JSONEq(t, `{"urn":"added_after_reset"}`, string(final.Deployment.Resources[1]))
}

func TestRebuildDependencies(t *testing.T) {
	// Test pruning of dangling dependencies.
	// res2 depends on res1. res1 is removed. res2.dependencies should be cleaned.
	resources := []json.RawMessage{
		json.RawMessage(`{"urn":"res2","dependencies":["res1","other"],"parent":"res1"}`),
		json.RawMessage(`{"urn":"other"}`), // res1 is missing
	}

	rebuildDependencies(resources)

	// Check res2
	var res2 struct {
		Dependencies []string `json:"dependencies"`
		Parent       string   `json:"parent"`
	}
	err := json.Unmarshal(resources[0], &res2)
	require.NoError(t, err)

	assert.Equal(t, []string{"other"}, res2.Dependencies, "Should keep valid dep 'other'")
	assert.Empty(t, res2.Parent, "Should clear dangling parent 'res1'")
}
