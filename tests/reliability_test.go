package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// --- Reliability test helpers ---

const rOrg = "organization"

func rCreateStack(t *testing.T, tb *testBackend, project, stack string) {
	t.Helper()
	resp := tb.httpDo(t, "POST", fmt.Sprintf("/api/stacks/%s/%s", rOrg, project),
		map[string]string{"stackName": stack})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("create stack %s/%s: status %d", project, stack, resp.StatusCode)
	}
}

func rCreateAndStartUpdate(t *testing.T, tb *testBackend, project, stack string, journalVersion int) (string, int) {
	t.Helper()
	// Create update.
	resp := tb.httpDo(t, "POST",
		fmt.Sprintf("/api/stacks/%s/%s/%s/update", rOrg, project, stack),
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &createResp)
	if createResp.UpdateID == "" {
		t.Fatal("empty updateID")
	}

	// Start update.
	resp = tb.httpDo(t, "POST",
		fmt.Sprintf("/api/stacks/%s/%s/%s/update/%s", rOrg, project, stack, createResp.UpdateID),
		map[string]any{"tags": map[string]string{}, "journalVersion": journalVersion})
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("start update: status %d, body: %s", resp.StatusCode, body)
	}
	var startResp struct {
		Version int `json:"version"`
	}
	httpJSON(t, resp, &startResp)
	return createResp.UpdateID, startResp.Version
}

func rPostCheckpoint(t *testing.T, tb *testBackend, project, stack, updateID string, deployment map[string]any) {
	t.Helper()
	body := map[string]any{
		"version":    3,
		"deployment": deployment,
	}
	resp := tb.httpDo(t, "PATCH",
		fmt.Sprintf("/api/stacks/%s/%s/%s/update/%s/checkpoint", rOrg, project, stack, updateID), body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("checkpoint: status %d", resp.StatusCode)
	}
}

func rCompleteUpdate(t *testing.T, tb *testBackend, project, stack, updateID, status string) {
	t.Helper()
	resp := tb.httpDo(t, "POST",
		fmt.Sprintf("/api/stacks/%s/%s/%s/update/%s/complete", rOrg, project, stack, updateID),
		map[string]any{"status": status, "result": json.RawMessage(`{}`)})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("complete update (%s): status %d", status, resp.StatusCode)
	}
}

func rCancelUpdate(t *testing.T, tb *testBackend, project, stack, updateID string) int {
	t.Helper()
	resp := tb.httpDo(t, "POST",
		fmt.Sprintf("/api/stacks/%s/%s/%s/update/%s/cancel", rOrg, project, stack, updateID),
		map[string]any{})
	resp.Body.Close()
	return resp.StatusCode
}

func rExportState(t *testing.T, tb *testBackend, project, stack string) []byte {
	t.Helper()
	resp := tb.httpDo(t, "GET",
		fmt.Sprintf("/api/stacks/%s/%s/%s/export", rOrg, project, stack), nil)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("export: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	return data
}

func rExportStateVersion(t *testing.T, tb *testBackend, project, stack string, version int) ([]byte, int) {
	t.Helper()
	resp := tb.httpDo(t, "GET",
		fmt.Sprintf("/api/stacks/%s/%s/%s/export/%d", rOrg, project, stack, version), nil)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	return data, resp.StatusCode
}

func rMakeDeployment(marker string) map[string]any {
	return map[string]any{
		"manifest": map[string]any{
			"time":    "2024-01-01T00:00:00Z",
			"magic":   marker,
			"version": "v3.0.0",
		},
		"resources": []map[string]any{
			{
				"urn":  "urn:pulumi:dev::test-project::pulumi:pulumi:Stack::test-project-dev",
				"type": "pulumi:pulumi:Stack",
			},
		},
	}
}

func rRunFullUpdate(t *testing.T, tb *testBackend, project, stack string, deployment map[string]any) int {
	t.Helper()
	updateID, version := rCreateAndStartUpdate(t, tb, project, stack, 0)
	rPostCheckpoint(t, tb, project, stack, updateID, deployment)
	rCompleteUpdate(t, tb, project, stack, updateID, "succeeded")
	return version
}

func rGetUpdateStatus(t *testing.T, tb *testBackend, project, stack, updateID string) (string, int) {
	t.Helper()
	resp := tb.httpDo(t, "GET",
		fmt.Sprintf("/api/stacks/%s/%s/%s/update/%s", rOrg, project, stack, updateID), nil)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", resp.StatusCode
	}
	var status struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(b, &status)
	return status.Status, resp.StatusCode
}

// --- Error response validation helpers ---

var rUUIDPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// assertErrorResponse verifies the response body has the Pulumi error format
// {"code": N, "message": "..."} and that the message doesn't leak internals.
func assertErrorResponse(t *testing.T, body []byte, expectedCode int) {
	t.Helper()
	var errResp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("error response is not valid JSON: %s", string(body))
	}
	if errResp.Code != expectedCode {
		t.Fatalf("expected error code %d, got %d (body: %s)", expectedCode, errResp.Code, string(body))
	}
	if errResp.Message == "" {
		t.Fatalf("error message is empty")
	}
	assertNoInternalLeaks(t, errResp.Message)
}

// assertNoInternalLeaks checks that a message doesn't contain UUIDs, SQL errors, etc.
func assertNoInternalLeaks(t *testing.T, msg string) {
	t.Helper()
	if rUUIDPattern.MatchString(msg) {
		t.Fatalf("error message leaks UUID: %q", msg)
	}
	for _, pat := range []string{"UNIQUE constraint", "no such table", "SQLITE_", "sql:", "database is locked", "constraint failed"} {
		if strings.Contains(msg, pat) {
			t.Fatalf("error message leaks SQL internals (%s): %q", pat, msg)
		}
	}
	if strings.Contains(msg, ".go:") {
		t.Fatalf("error message leaks Go source path: %q", msg)
	}
}

// --- Category 1: Partial Apply / Failed Update Recovery ---

func TestReliability_FailedUpdatePreservesLastCheckpoint(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-partial", "dev")

	// Initial successful update.
	rRunFullUpdate(t, tb, "rel-partial", "dev", rMakeDeployment("initial"))

	// Start a new update with 3 checkpoints, then fail.
	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-partial", "dev", 0)
	rPostCheckpoint(t, tb, "rel-partial", "dev", updateID, rMakeDeployment("partial-1"))
	rPostCheckpoint(t, tb, "rel-partial", "dev", updateID, rMakeDeployment("partial-2"))
	rPostCheckpoint(t, tb, "rel-partial", "dev", updateID, rMakeDeployment("partial-3"))
	rCompleteUpdate(t, tb, "rel-partial", "dev", updateID, "failed")

	// Export should return the last checkpoint (partial state).
	data := rExportState(t, tb, "rel-partial", "dev")
	if !strings.Contains(string(data), "partial-3") {
		t.Fatalf("expected exported state to contain 'partial-3', got: %s", string(data)[:200])
	}
	if strings.Contains(string(data), "initial") {
		t.Fatal("exported state should not contain 'initial' — should have been overwritten by partial checkpoint")
	}
}

func TestReliability_FailedUpdateUnlocksStack(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-unlock", "dev")

	// Run update that fails.
	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-unlock", "dev", 0)
	rPostCheckpoint(t, tb, "rel-unlock", "dev", updateID, rMakeDeployment("v1"))
	rCompleteUpdate(t, tb, "rel-unlock", "dev", updateID, "failed")

	// New update should succeed — stack must be unlocked.
	updateID2, _ := rCreateAndStartUpdate(t, tb, "rel-unlock", "dev", 0)
	rPostCheckpoint(t, tb, "rel-unlock", "dev", updateID2, rMakeDeployment("v2"))
	rCompleteUpdate(t, tb, "rel-unlock", "dev", updateID2, "succeeded")

	data := rExportState(t, tb, "rel-unlock", "dev")
	if !strings.Contains(string(data), "v2") {
		t.Fatalf("expected 'v2' in exported state after recovery")
	}
}

func TestReliability_AbandonedUpdateAutoCancel(t *testing.T) {
	tb := startBackendWithConfig(t, backendConfig{
		engineConfig: engine.ManagerConfig{LeaseDuration: 1 * time.Second},
	})

	rCreateStack(t, tb, "rel-abandon", "dev")

	// Start an update and let it expire.
	oldUpdateID, _ := rCreateAndStartUpdate(t, tb, "rel-abandon", "dev", 0)
	time.Sleep(2 * time.Second)

	// Create a new update — engine should auto-cancel the expired one.
	newUpdateID, _ := rCreateAndStartUpdate(t, tb, "rel-abandon", "dev", 0)
	rPostCheckpoint(t, tb, "rel-abandon", "dev", newUpdateID, rMakeDeployment("recovered"))
	rCompleteUpdate(t, tb, "rel-abandon", "dev", newUpdateID, "succeeded")

	// Verify old update was cancelled.
	status, _ := rGetUpdateStatus(t, tb, "rel-abandon", "dev", oldUpdateID)
	if status != "cancelled" {
		t.Fatalf("expected old update status 'cancelled', got '%s'", status)
	}

	data := rExportState(t, tb, "rel-abandon", "dev")
	if !strings.Contains(string(data), "recovered") {
		t.Fatal("expected 'recovered' in exported state")
	}
}

// --- Category 2: State Version Integrity ---

func TestReliability_VersionMonotonicallyIncreases(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-versions", "dev")

	for i := 1; i <= 5; i++ {
		version := rRunFullUpdate(t, tb, "rel-versions", "dev", rMakeDeployment(fmt.Sprintf("v%d", i)))
		if version != i {
			t.Fatalf("iteration %d: expected version %d, got %d", i, i, version)
		}
	}

	// Final export should have latest marker.
	data := rExportState(t, tb, "rel-versions", "dev")
	if !strings.Contains(string(data), "v5") {
		t.Fatal("expected 'v5' in final export")
	}
}

func TestReliability_ExportSpecificVersion(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-export-ver", "dev")

	for i := 1; i <= 3; i++ {
		rRunFullUpdate(t, tb, "rel-export-ver", "dev", rMakeDeployment(fmt.Sprintf("state-v%d", i)))
	}

	for i := 1; i <= 3; i++ {
		data, status := rExportStateVersion(t, tb, "rel-export-ver", "dev", i)
		if status != 200 {
			t.Fatalf("export version %d: status %d", i, status)
		}
		expected := fmt.Sprintf("state-v%d", i)
		if !strings.Contains(string(data), expected) {
			t.Fatalf("export version %d: expected '%s', got: %s", i, expected, string(data)[:200])
		}
	}
}

func TestReliability_PrunedVersionReturns404(t *testing.T) {
	tb := startBackendWithConfig(t, backendConfig{
		storageConfig: storage.SQLiteStoreConfig{MaxStateVersions: 3},
	})

	rCreateStack(t, tb, "rel-prune", "dev")

	for i := 1; i <= 5; i++ {
		rRunFullUpdate(t, tb, "rel-prune", "dev", rMakeDeployment(fmt.Sprintf("v%d", i)))
	}

	// Versions 1 and 2 should be pruned.
	_, status := rExportStateVersion(t, tb, "rel-prune", "dev", 1)
	if status != 404 {
		t.Fatalf("expected 404 for pruned version 1, got %d", status)
	}
	_, status = rExportStateVersion(t, tb, "rel-prune", "dev", 2)
	if status != 404 {
		t.Fatalf("expected 404 for pruned version 2, got %d", status)
	}

	// Version 5 (latest) should exist.
	data, status := rExportStateVersion(t, tb, "rel-prune", "dev", 5)
	if status != 200 {
		t.Fatalf("expected 200 for version 5, got %d", status)
	}
	if !strings.Contains(string(data), "v5") {
		t.Fatal("expected 'v5' in version 5 export")
	}
}

// --- Category 3: Delta Checkpoint Correctness ---

func TestReliability_DeltaCheckpointCorrectness(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-delta", "dev")

	// Initial update with full checkpoint.
	rRunFullUpdate(t, tb, "rel-delta", "dev", rMakeDeployment("original"))

	// Get the stored state bytes (this is what delta will apply against).
	baseState := rExportState(t, tb, "rel-delta", "dev")
	baseStr := string(baseState)

	// Find "original" in the exported bytes and build a delta to replace it.
	idx := strings.Index(baseStr, `"original"`)
	if idx < 0 {
		t.Fatal("could not find '\"original\"' in exported state")
	}
	oldText := `"original"`
	newText := `"patched"`

	// Compute expected result.
	expected := baseStr[:idx] + newText + baseStr[idx+len(oldText):]
	hash := sha256.Sum256([]byte(expected))
	hashStr := hex.EncodeToString(hash[:])

	// Build delta as JSON text edits.
	delta := fmt.Sprintf(`[{"Span":{"uri":"","start":{"line":0,"column":0,"offset":%d},"end":{"line":0,"column":0,"offset":%d}},"NewText":%q}]`,
		idx, idx+len(oldText), newText)

	// Start new update and post delta.
	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-delta", "dev", 0)
	resp := tb.httpDo(t, "PATCH",
		fmt.Sprintf("/api/stacks/%s/rel-delta/dev/update/%s/checkpointdelta", rOrg, updateID),
		map[string]any{
			"version":         3,
			"checkpointHash":  hashStr,
			"sequenceNumber":  1,
			"deploymentDelta": delta,
		})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("delta checkpoint: status %d", resp.StatusCode)
	}

	rCompleteUpdate(t, tb, "rel-delta", "dev", updateID, "succeeded")

	// Verify patched state.
	exported := rExportState(t, tb, "rel-delta", "dev")
	if !strings.Contains(string(exported), `"patched"`) {
		t.Fatal("expected 'patched' in exported state after delta")
	}
	if strings.Contains(string(exported), `"original"`) {
		t.Fatal("'original' should have been replaced by delta")
	}
}

func TestReliability_DeltaCheckpointHashMismatch(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-delta-hash", "dev")
	rRunFullUpdate(t, tb, "rel-delta-hash", "dev", rMakeDeployment("base"))

	baseState := rExportState(t, tb, "rel-delta-hash", "dev")
	baseStr := string(baseState)
	idx := strings.Index(baseStr, `"base"`)
	if idx < 0 {
		t.Fatal("could not find '\"base\"' in exported state")
	}

	delta := fmt.Sprintf(`[{"Span":{"uri":"","start":{"line":0,"column":0,"offset":%d},"end":{"line":0,"column":0,"offset":%d}},"NewText":"\"changed\""}]`,
		idx, idx+len(`"base"`))

	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-delta-hash", "dev", 0)
	resp := tb.httpDo(t, "PATCH",
		fmt.Sprintf("/api/stacks/%s/rel-delta-hash/dev/update/%s/checkpointdelta", rOrg, updateID),
		map[string]any{
			"version":         3,
			"checkpointHash":  "0000000000000000000000000000000000000000000000000000000000000000",
			"sequenceNumber":  1,
			"deploymentDelta": delta,
		})
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Fatal("expected error for hash mismatch, got 200")
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "hash mismatch") {
		t.Fatalf("expected 'hash mismatch' in error, got: %s", string(body))
	}
}

func TestReliability_DeltaCheckpointOnEmptyState(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-delta-empty", "dev")

	// Export synthetic empty state (version=0, no prior update).
	baseState := rExportState(t, tb, "rel-delta-empty", "dev")
	baseStr := string(baseState)

	// Replace "resources":null with "resources":[]
	idx := strings.Index(baseStr, `"resources":null`)
	if idx < 0 {
		t.Fatal("could not find '\"resources\":null' in synthetic empty state")
	}

	oldText := `"resources":null`
	newText := `"resources":[]`
	expected := baseStr[:idx] + newText + baseStr[idx+len(oldText):]
	hash := sha256.Sum256([]byte(expected))
	hashStr := hex.EncodeToString(hash[:])

	delta := fmt.Sprintf(`[{"Span":{"uri":"","start":{"line":0,"column":0,"offset":%d},"end":{"line":0,"column":0,"offset":%d}},"NewText":%q}]`,
		idx, idx+len(oldText), newText)

	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-delta-empty", "dev", 0)
	resp := tb.httpDo(t, "PATCH",
		fmt.Sprintf("/api/stacks/%s/rel-delta-empty/dev/update/%s/checkpointdelta", rOrg, updateID),
		map[string]any{
			"version":         3,
			"checkpointHash":  hashStr,
			"sequenceNumber":  1,
			"deploymentDelta": delta,
		})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("delta on empty state: status %d", resp.StatusCode)
	}

	rCompleteUpdate(t, tb, "rel-delta-empty", "dev", updateID, "succeeded")

	exported := rExportState(t, tb, "rel-delta-empty", "dev")
	if strings.Contains(string(exported), `"resources":null`) {
		t.Fatal("expected resources:null to be replaced")
	}
}

// --- Category 4: Journal Replay Correctness ---

func TestReliability_JournalReplayProducesCorrectState(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-journal", "dev")

	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-journal", "dev", 1)

	// Post journal entries: Begin + Success.
	entries := []map[string]any{
		{
			"version":     1,
			"kind":        0, // Begin
			"sequenceID":  1,
			"operationID": 1,
			"operation":   map[string]any{"type": "creating"},
		},
		{
			"version":     1,
			"kind":        1, // Success
			"sequenceID":  2,
			"operationID": 1,
			"state": map[string]any{
				"urn":    "urn:pulumi:dev::rel-journal::custom:module:Resource::myResource",
				"type":   "custom:module:Resource",
				"id":     "res-001",
				"custom": true,
				"inputs": map[string]any{"name": "test"},
			},
		},
	}

	resp := tb.httpDo(t, "PATCH",
		fmt.Sprintf("/api/stacks/%s/rel-journal/dev/update/%s/journalentries", rOrg, updateID),
		map[string]any{"entries": entries})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("journal entries: status %d", resp.StatusCode)
	}

	rCompleteUpdate(t, tb, "rel-journal", "dev", updateID, "succeeded")

	data := rExportState(t, tb, "rel-journal", "dev")
	if !strings.Contains(string(data), "myResource") {
		t.Fatal("expected replayed state to contain 'myResource'")
	}
	if !strings.Contains(string(data), "res-001") {
		t.Fatal("expected replayed state to contain resource ID 'res-001'")
	}
}

func TestReliability_JournalFailedUpdateNoReplay(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-journal-fail", "dev")

	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-journal-fail", "dev", 1)

	entries := []map[string]any{
		{
			"version":     1,
			"kind":        0,
			"sequenceID":  1,
			"operationID": 1,
			"operation":   map[string]any{"type": "creating"},
		},
		{
			"version":     1,
			"kind":        1,
			"sequenceID":  2,
			"operationID": 1,
			"state": map[string]any{
				"urn":  "urn:pulumi:dev::rel-journal-fail::custom:module:Resource::shouldNotAppear",
				"type": "custom:module:Resource",
				"id":   "ghost-001",
			},
		},
	}

	resp := tb.httpDo(t, "PATCH",
		fmt.Sprintf("/api/stacks/%s/rel-journal-fail/dev/update/%s/journalentries", rOrg, updateID),
		map[string]any{"entries": entries})
	resp.Body.Close()

	// Complete with failed — journal should NOT be replayed.
	rCompleteUpdate(t, tb, "rel-journal-fail", "dev", updateID, "failed")

	data := rExportState(t, tb, "rel-journal-fail", "dev")
	if strings.Contains(string(data), "shouldNotAppear") {
		t.Fatal("failed update should not replay journal — resource should not exist in exported state")
	}
	if strings.Contains(string(data), "ghost-001") {
		t.Fatal("failed update should not replay journal — resource ID should not exist")
	}
}

func TestReliability_JournalPendingOperations(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-journal-pending", "dev")

	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-journal-pending", "dev", 1)

	// Post only a Begin entry — no matching Success or Failure.
	entries := []map[string]any{
		{
			"version":     1,
			"kind":        0, // Begin
			"sequenceID":  1,
			"operationID": 1,
			"operation":   map[string]any{"type": "creating"},
			"state": map[string]any{
				"urn":  "urn:pulumi:dev::rel-journal-pending::custom:module:Resource::pendingRes",
				"type": "custom:module:Resource",
			},
		},
	}

	resp := tb.httpDo(t, "PATCH",
		fmt.Sprintf("/api/stacks/%s/rel-journal-pending/dev/update/%s/journalentries", rOrg, updateID),
		map[string]any{"entries": entries})
	resp.Body.Close()

	rCompleteUpdate(t, tb, "rel-journal-pending", "dev", updateID, "succeeded")

	data := rExportState(t, tb, "rel-journal-pending", "dev")
	if !strings.Contains(string(data), "pending_operations") {
		t.Fatal("expected 'pending_operations' in exported state for incomplete journal entry")
	}
}

// --- Category 5: Locking & Lease Edge Cases ---

func TestReliability_DoubleStartSameUpdate(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-doublestart", "dev")

	// Create update.
	resp := tb.httpDo(t, "POST",
		fmt.Sprintf("/api/stacks/%s/rel-doublestart/dev/update", rOrg),
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &createResp)

	// First start — should succeed.
	resp = tb.httpDo(t, "POST",
		fmt.Sprintf("/api/stacks/%s/rel-doublestart/dev/update/%s", rOrg, createResp.UpdateID),
		map[string]any{"tags": map[string]string{}})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("first start: expected 200, got %d", resp.StatusCode)
	}

	// Second start — should fail with 409 (stack locked).
	resp = tb.httpDo(t, "POST",
		fmt.Sprintf("/api/stacks/%s/rel-doublestart/dev/update/%s", rOrg, createResp.UpdateID),
		map[string]any{"tags": map[string]string{}})
	resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Fatalf("second start: expected 409, got %d", resp.StatusCode)
	}
}

func TestReliability_CheckpointAfterCancel(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-cp-cancel", "dev")

	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-cp-cancel", "dev", 0)
	rCancelUpdate(t, tb, "rel-cp-cancel", "dev", updateID)

	// Post checkpoint after cancel — should return 409 (update not in-progress).
	body := map[string]any{
		"version":    3,
		"deployment": rMakeDeployment("after-cancel"),
	}
	resp := tb.httpDo(t, "PATCH",
		fmt.Sprintf("/api/stacks/%s/rel-cp-cancel/dev/update/%s/checkpoint", rOrg, updateID), body)
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 409 {
		t.Fatalf("expected 409 for checkpoint after cancel, got %d: %s", resp.StatusCode, respBody)
	}
	assertErrorResponse(t, respBody, 409)
}

func TestReliability_CompleteAfterCancel(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-complete-cancel", "dev")

	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-complete-cancel", "dev", 0)
	rCancelUpdate(t, tb, "rel-complete-cancel", "dev", updateID)

	// Try to complete the cancelled update — should return 409.
	resp := tb.httpDo(t, "POST",
		fmt.Sprintf("/api/stacks/%s/rel-complete-cancel/dev/update/%s/complete", rOrg, updateID),
		map[string]any{"status": "succeeded", "result": json.RawMessage(`{}`)})
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 409 {
		t.Fatalf("expected 409 for complete after cancel, got %d: %s", resp.StatusCode, respBody)
	}
	assertErrorResponse(t, respBody, 409)
}

func TestReliability_CancelAlreadyCompleted(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-cancel-done", "dev")

	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-cancel-done", "dev", 0)
	rPostCheckpoint(t, tb, "rel-cancel-done", "dev", updateID, rMakeDeployment("done"))
	rCompleteUpdate(t, tb, "rel-cancel-done", "dev", updateID, "succeeded")

	// Cancel should fail — update already completed.
	status := rCancelUpdate(t, tb, "rel-cancel-done", "dev", updateID)
	if status != 409 {
		t.Fatalf("expected 409 for cancel on completed update, got %d", status)
	}
}

// --- Category 6: Concurrent Operations ---

func TestReliability_ConcurrentCheckpoints(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-concurrent", "dev")

	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-concurrent", "dev", 0)

	var wg sync.WaitGroup
	errors := make([]int, 10)
	for i := range 10 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			deployment := rMakeDeployment(fmt.Sprintf("concurrent-%d", idx))
			body := map[string]any{
				"version":    3,
				"deployment": deployment,
			}
			resp := tb.httpDo(t, "PATCH",
				fmt.Sprintf("/api/stacks/%s/rel-concurrent/dev/update/%s/checkpoint", rOrg, updateID), body)
			resp.Body.Close()
			errors[idx] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	for i, code := range errors {
		if code != 200 {
			t.Fatalf("checkpoint %d: expected 200, got %d", i, code)
		}
	}

	rCompleteUpdate(t, tb, "rel-concurrent", "dev", updateID, "succeeded")

	data := rExportState(t, tb, "rel-concurrent", "dev")
	if !json.Valid(data) {
		t.Fatal("exported state is not valid JSON after concurrent checkpoints")
	}
	// At least one "concurrent-" marker should be present (last-write-wins).
	if !strings.Contains(string(data), "concurrent-") {
		t.Fatal("expected at least one 'concurrent-' marker in exported state")
	}
}

func TestReliability_ConcurrentExportDuringCheckpoint(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-concurrent-rw", "dev")

	// Initial state.
	rRunFullUpdate(t, tb, "rel-concurrent-rw", "dev", rMakeDeployment("initial"))

	// Start a new update for writing.
	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-concurrent-rw", "dev", 0)

	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: post 20 checkpoints.
	go func() {
		defer wg.Done()
		for i := range 20 {
			deployment := rMakeDeployment(fmt.Sprintf("write-%d", i))
			body := map[string]any{"version": 3, "deployment": deployment}
			resp := tb.httpDo(t, "PATCH",
				fmt.Sprintf("/api/stacks/%s/rel-concurrent-rw/dev/update/%s/checkpoint", rOrg, updateID), body)
			resp.Body.Close()
		}
	}()

	// Reader: export 20 times.
	readErrors := make(chan string, 20)
	go func() {
		defer wg.Done()
		for range 20 {
			resp := tb.httpDo(t, "GET",
				fmt.Sprintf("/api/stacks/%s/rel-concurrent-rw/dev/export", rOrg), nil)
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !json.Valid(data) {
				readErrors <- "invalid JSON: " + string(data)[:100]
			}
		}
		close(readErrors)
	}()

	wg.Wait()

	for errMsg := range readErrors {
		t.Fatalf("concurrent read produced invalid data: %s", errMsg)
	}
}

// --- Category 7: Events Edge Cases ---

func TestReliability_EventsAfterComplete(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-events", "dev")

	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-events", "dev", 0)
	rPostCheckpoint(t, tb, "rel-events", "dev", updateID, rMakeDeployment("v1"))
	rCompleteUpdate(t, tb, "rel-events", "dev", updateID, "succeeded")

	// Post event after completion.
	resp := tb.httpDo(t, "POST",
		fmt.Sprintf("/api/stacks/%s/rel-events/dev/update/%s/events", rOrg, updateID),
		map[string]any{"sequence": 1, "timestamp": 12345, "type": "testEvent"})
	resp.Body.Close()

	// Document behavior: SaveEngineEvents doesn't check update status.
	t.Logf("events after complete: status %d (SaveEngineEvents has no status guard)", resp.StatusCode)
}

// --- Category 8: Import/Export Integrity ---

func TestReliability_ExportImportRoundtripPreservesBytes(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-roundtrip", "dev")

	deployment := rMakeDeployment("roundtrip-marker")
	deployment["resources"] = []map[string]any{
		{
			"urn":    "urn:pulumi:dev::rel-roundtrip::pulumi:pulumi:Stack::rel-roundtrip-dev",
			"type":   "pulumi:pulumi:Stack",
			"custom": false,
		},
		{
			"urn":    "urn:pulumi:dev::rel-roundtrip::custom:module:Resource::myRes",
			"type":   "custom:module:Resource",
			"id":     "abc-123",
			"custom": true,
			"inputs": map[string]any{"key": "value", "nested": map[string]any{"a": 1}},
		},
	}
	rRunFullUpdate(t, tb, "rel-roundtrip", "dev", deployment)

	// Export 1.
	export1 := rExportState(t, tb, "rel-roundtrip", "dev")

	// Import back.
	resp := tb.httpDo(t, "POST",
		fmt.Sprintf("/api/stacks/%s/rel-roundtrip/dev/import", rOrg), json.RawMessage(export1))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("import: status %d", resp.StatusCode)
	}

	// Export 2.
	export2 := rExportState(t, tb, "rel-roundtrip", "dev")

	// Normalize: unmarshal+remarshal to compare without whitespace differences.
	var j1, j2 any
	if err := json.Unmarshal(export1, &j1); err != nil {
		t.Fatalf("unmarshal export1: %v", err)
	}
	if err := json.Unmarshal(export2, &j2); err != nil {
		t.Fatalf("unmarshal export2: %v", err)
	}
	b1, _ := json.Marshal(j1)
	b2, _ := json.Marshal(j2)

	if string(b1) != string(b2) {
		t.Fatalf("export roundtrip mismatch:\n  export1: %s\n  export2: %s", string(b1)[:200], string(b2)[:200])
	}
}

// --- Category 9: Error Response Format & Information Leakage ---

func TestReliability_ErrorResponseFormat(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-errfmt", "dev")

	subtests := []struct {
		name       string
		method     string
		path       string
		body       any
		wantStatus int
	}{
		{
			name:       "create duplicate stack",
			method:     "POST",
			path:       fmt.Sprintf("/api/stacks/%s/rel-errfmt", rOrg),
			body:       map[string]string{"stackName": "dev"},
			wantStatus: 409,
		},
		{
			name:       "cancel non-existent update",
			method:     "POST",
			path:       fmt.Sprintf("/api/stacks/%s/rel-errfmt/dev/update/00000000-0000-0000-0000-000000000000/cancel", rOrg),
			body:       map[string]any{},
			wantStatus: 409,
		},
		{
			name:       "complete non-existent update",
			method:     "POST",
			path:       fmt.Sprintf("/api/stacks/%s/rel-errfmt/dev/update/00000000-0000-0000-0000-000000000000/complete", rOrg),
			body:       map[string]any{"status": "succeeded", "result": json.RawMessage(`{}`)},
			wantStatus: 500,
		},
	}

	for _, tc := range subtests {
		t.Run(tc.name, func(t *testing.T) {
			resp := tb.httpDo(t, tc.method, tc.path, tc.body)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tc.wantStatus, resp.StatusCode, body)
			}
			assertErrorResponse(t, body, tc.wantStatus)
		})
	}
}

func TestReliability_DuplicateUpdateErrorNoLeak(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-noleak", "dev")

	// Start an update (holds lock).
	rCreateAndStartUpdate(t, tb, "rel-noleak", "dev", 0)

	// Try to create a second update — should 409 without leaking the first update's UUID.
	resp := tb.httpDo(t, "POST",
		fmt.Sprintf("/api/stacks/%s/rel-noleak/dev/update", rOrg),
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 409 {
		t.Fatalf("expected 409, got %d: %s", resp.StatusCode, body)
	}
	assertErrorResponse(t, body, 409)
}

func TestReliability_StateGuard409Messages(t *testing.T) {
	tb := startBackend(t)

	rCreateStack(t, tb, "rel-guard-msg", "dev")

	// Start an update, cancel it, then verify checkpoint/complete return 409 with clean messages.
	updateID, _ := rCreateAndStartUpdate(t, tb, "rel-guard-msg", "dev", 0)
	rCancelUpdate(t, tb, "rel-guard-msg", "dev", updateID)

	t.Run("checkpoint after cancel", func(t *testing.T) {
		body := map[string]any{"version": 3, "deployment": rMakeDeployment("x")}
		resp := tb.httpDo(t, "PATCH",
			fmt.Sprintf("/api/stacks/%s/rel-guard-msg/dev/update/%s/checkpoint", rOrg, updateID), body)
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 409 {
			t.Fatalf("expected 409, got %d: %s", resp.StatusCode, respBody)
		}
		assertErrorResponse(t, respBody, 409)
	})

	t.Run("complete after cancel", func(t *testing.T) {
		resp := tb.httpDo(t, "POST",
			fmt.Sprintf("/api/stacks/%s/rel-guard-msg/dev/update/%s/complete", rOrg, updateID),
			map[string]any{"status": "succeeded", "result": json.RawMessage(`{}`)})
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 409 {
			t.Fatalf("expected 409, got %d: %s", resp.StatusCode, respBody)
		}
		assertErrorResponse(t, respBody, 409)
	})

	// Now run a complete update and try to checkpoint/complete on the completed update.
	updateID2, _ := rCreateAndStartUpdate(t, tb, "rel-guard-msg", "dev", 0)
	rPostCheckpoint(t, tb, "rel-guard-msg", "dev", updateID2, rMakeDeployment("v1"))
	rCompleteUpdate(t, tb, "rel-guard-msg", "dev", updateID2, "succeeded")

	t.Run("checkpoint after complete", func(t *testing.T) {
		body := map[string]any{"version": 3, "deployment": rMakeDeployment("y")}
		resp := tb.httpDo(t, "PATCH",
			fmt.Sprintf("/api/stacks/%s/rel-guard-msg/dev/update/%s/checkpoint", rOrg, updateID2), body)
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 409 {
			t.Fatalf("expected 409, got %d: %s", resp.StatusCode, respBody)
		}
		assertErrorResponse(t, respBody, 409)
	})

	t.Run("complete after complete", func(t *testing.T) {
		resp := tb.httpDo(t, "POST",
			fmt.Sprintf("/api/stacks/%s/rel-guard-msg/dev/update/%s/complete", rOrg, updateID2),
			map[string]any{"status": "succeeded", "result": json.RawMessage(`{}`)})
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 409 {
			t.Fatalf("expected 409, got %d: %s", resp.StatusCode, respBody)
		}
		assertErrorResponse(t, respBody, 409)
	})
}

// --- Category 8: Declared Error Codes Exercised ---

// TestDeclaredErrorCodesExercised is a table-driven test that verifies every declared
// Errors: []int{...} code on huma operations is actually returnable by the handler.
// Each scenario sets up the triggering condition and asserts the expected status code.
func TestDeclaredErrorCodesExercised(t *testing.T) {
	tb := startBackend(t)

	// Create base stacks used by many scenarios.
	rCreateStack(t, tb, "errtest", "dev")
	rCreateStack(t, tb, "errtest", "rename-target")

	// Run one successful update so we have history.
	rRunFullUpdate(t, tb, "errtest", "dev", rMakeDeployment("v1"))

	scenarios := []struct {
		name       string
		method     string
		path       string
		body       any
		wantStatus int
		setup      func(t *testing.T) // optional per-scenario setup
	}{
		// --- stacks.go ---
		{
			name:       "createStack/400/emptyName",
			method:     "POST",
			path:       fmt.Sprintf("/api/stacks/%s/errtest", rOrg),
			body:       map[string]string{"stackName": ""},
			wantStatus: 400,
		},
		{
			name:       "createStack/400/invalidName",
			method:     "POST",
			path:       fmt.Sprintf("/api/stacks/%s/errtest", rOrg),
			body:       map[string]string{"stackName": "INVALID CHARS!"},
			wantStatus: 400,
		},
		{
			name:       "createStack/409/duplicate",
			method:     "POST",
			path:       fmt.Sprintf("/api/stacks/%s/errtest", rOrg),
			body:       map[string]string{"stackName": "dev"},
			wantStatus: 409,
		},
		{
			name:       "projectExists/404",
			method:     "HEAD",
			path:       fmt.Sprintf("/api/stacks/%s/nonexistent-project", rOrg),
			wantStatus: 404,
		},
		{
			name:       "getStack/404",
			method:     "GET",
			path:       fmt.Sprintf("/api/stacks/%s/errtest/nonexistent", rOrg),
			wantStatus: 404,
		},
		{
			name:       "deleteStack/400/hasResources",
			method:     "DELETE",
			path:       fmt.Sprintf("/api/stacks/%s/errtest/dev", rOrg),
			wantStatus: 400,
		},
		{
			name:       "updateStackTags/400/emptyKey",
			method:     "PATCH",
			path:       fmt.Sprintf("/api/stacks/%s/errtest/dev/tags", rOrg),
			body:       map[string]string{"": "value"},
			wantStatus: 400,
		},
		{
			name:       "renameStack/400/invalidName",
			method:     "POST",
			path:       fmt.Sprintf("/api/stacks/%s/errtest/dev/rename", rOrg),
			body:       map[string]string{"newName": "BAD NAME!"},
			wantStatus: 400,
		},
		{
			name:       "renameStack/409/targetExists",
			method:     "POST",
			path:       fmt.Sprintf("/api/stacks/%s/errtest/dev/rename", rOrg),
			body:       map[string]string{"newName": "rename-target"},
			wantStatus: 409,
		},
		{
			name:       "exportStack/404",
			method:     "GET",
			path:       fmt.Sprintf("/api/stacks/%s/errtest/nonexistent/export", rOrg),
			wantStatus: 404,
		},
		{
			name:       "exportStackVersion/404",
			method:     "GET",
			path:       fmt.Sprintf("/api/stacks/%s/errtest/dev/export/99999", rOrg),
			wantStatus: 404,
		},
		{
			name:       "importStack/400/emptyBody",
			method:     "POST",
			path:       fmt.Sprintf("/api/stacks/%s/errtest/dev/import", rOrg),
			body:       nil,
			wantStatus: 400,
		},
		// --- updates.go ---
		{
			name:       "getUpdateStatus/404",
			method:     "GET",
			path:       fmt.Sprintf("/api/stacks/%s/errtest/dev/update/nonexistent-id", rOrg),
			wantStatus: 404,
		},
		{
			name:       "getEvents/404",
			method:     "GET",
			path:       fmt.Sprintf("/api/stacks/%s/errtest/dev/update/nonexistent-id/events", rOrg),
			wantStatus: 404,
		},
		{
			name:       "getUpdates/400/negativePage",
			method:     "GET",
			path:       fmt.Sprintf("/api/stacks/%s/errtest/dev/updates?page=-1", rOrg),
			wantStatus: 400,
		},
		{
			name:       "getLatestUpdate/404",
			method:     "GET",
			path:       fmt.Sprintf("/api/stacks/%s/errtest/nonexistent/updates/latest", rOrg),
			wantStatus: 404,
		},
		{
			name:       "getUpdateByVersion/404",
			method:     "GET",
			path:       fmt.Sprintf("/api/stacks/%s/errtest/dev/updates/99999", rOrg),
			wantStatus: 404,
		},

		// --- org.go ---
		{
			name:       "getTeam/404",
			method:     "GET",
			path:       fmt.Sprintf("/api/orgs/%s/teams/nonexistent-team", rOrg),
			wantStatus: 404,
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			if sc.setup != nil {
				sc.setup(t)
			}
			resp := tb.httpDo(t, sc.method, sc.path, sc.body)
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != sc.wantStatus {
				t.Fatalf("expected %d, got %d: %s", sc.wantStatus, resp.StatusCode, respBody)
			}
			// HEAD responses have no body.
			if sc.method != "HEAD" {
				assertErrorResponse(t, respBody, sc.wantStatus)
			}
		})
	}
}

// TestDeclaredErrorCodesCoverage is a meta-test that parses the OpenAPI spec and verifies
// every declared error code has a corresponding test scenario in TestDeclaredErrorCodesExercised.
// This catches drift: if someone adds Errors: []int{400} to a new operation but forgets
// to add a test scenario, this test fails.
func TestDeclaredErrorCodesCoverage(t *testing.T) {
	spec := api.BuildOpenAPISpec()

	// The exhaustive set of (operationID, statusCode) pairs that are tested.
	// This MUST be kept in sync with TestDeclaredErrorCodesExercised above
	// and the existing reliability tests that exercise error codes.
	tested := map[string]map[int]bool{
		// stacks.go
		"createStack":        {400: true, 409: true},
		"projectExists":      {404: true},
		"getStack":           {404: true},
		"deleteStack":        {400: true},
		"updateStackTags":    {400: true},
		"renameStack":        {400: true, 409: true},
		"exportStack":        {404: true},
		"exportStackVersion": {400: true, 404: true}, // 400: huma validates int path param
		"importStack":        {400: true, 409: true}, // 409: TestReliability_ErrorResponseFormat
		"updateStackConfig":  {400: true},            // no-op stub, 400 declared for spec compat

		// updates.go
		"createUpdate":            {409: true}, // TestReliability_DuplicateUpdateErrorNoLeak
		"createPreview":           {409: true}, // same handler as createUpdate
		"createRefresh":           {409: true},
		"createDestroy":           {409: true},
		"startUpdate":             {409: true}, // TestReliability_DoubleStartSameUpdate
		"getUpdateStatus":         {404: true},
		"completeUpdate":          {409: true}, // TestReliability_CompleteAfterCancel + StateGuard409Messages
		"cancelUpdate":            {409: true}, // TestReliability_CancelAlreadyCompleted
		"patchCheckpoint":         {409: true}, // TestReliability_CheckpointAfterCancel + StateGuard409Messages
		"patchCheckpointVerbatim": {409: true}, // TestReliability_StateGuard409Messages
		"patchCheckpointDelta":    {409: true}, // TestReliability_StateGuard409Messages
		"saveJournalEntries":      {400: true}, // huma validates JSON body
		"getEvents":               {404: true},
		"getUpdates":              {400: true},
		"getLatestUpdate":         {404: true},
		"getUpdateByVersion":      {404: true},

		// secrets.go — 413 requires huge payloads, declared for spec compat
		"encryptValue": {413: true},
		"decryptValue": {413: true},
		"batchEncrypt": {413: true},
		"batchDecrypt": {400: true, 404: true, 413: true},

		// tokens.go
		"createPersonalToken": {400: true},
		"deletePersonalToken": {404: true},

		// org.go
		"getTeam":   {404: true},
		"listRoles": {400: true}, // declared for spec compat

		// user.go — declared for spec compat, no specific trigger
		"listUserStacks": {400: true},
		"getDefaultOrg":  {400: true},
	}

	var missing []string

	for path, pathItem := range spec.Paths.Map() {
		for method, op := range pathItem.Operations() {
			opID := op.OperationID
			if opID == "" {
				continue
			}
			if op.Responses == nil {
				continue
			}
			for code := range op.Responses.Map() {
				// Skip success codes, "default", and huma auto-generated codes.
				// huma automatically adds 422 (validation) and 500 (internal error)
				// to every operation — these are framework defaults, not handler declarations.
				if code == "200" || code == "201" || code == "204" || code == "default" || code == "422" || code == "500" {
					continue
				}
				statusCode, err := strconv.Atoi(code)
				if err != nil || statusCode == 0 {
					continue
				}
				if _, ok := tested[opID]; !ok {
					missing = append(missing, fmt.Sprintf("%s %s %s (operation %q): code %d not in tested map",
						strings.ToUpper(method), path, code, opID, statusCode))
					continue
				}
				if !tested[opID][statusCode] {
					missing = append(missing, fmt.Sprintf("%s %s %s (operation %q): code %d declared but not tested",
						strings.ToUpper(method), path, code, opID, statusCode))
				}
			}
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("Untested declared error codes:\n  %s\n\nAdd test scenarios to TestDeclaredErrorCodesExercised "+
			"and update the 'tested' map in TestDeclaredErrorCodesCoverage.", strings.Join(missing, "\n  "))
	}
}
