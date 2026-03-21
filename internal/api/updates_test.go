package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestGetUpdateStatusAPI(t *testing.T) {
	store := new(MockStore)
	mgr, _ := engine.NewManager(store, nil)
	t.Cleanup(mgr.Shutdown)
	srv := &Server{engine: mgr}
	_, api := humatest.New(t)
	srv.registerUpdates(api)

	store.On("GetUpdate", mock.Anything, "up-1").Return(&storage.Update{
		ID:     "up-1",
		Status: "succeeded",
	}, nil)

	resp := api.Get("/api/stacks/org/proj/stack/update/up-1")
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.JSONEq(t, `{"status":"succeeded","events":[]}`, resp.Body.String())
}

func TestGetUpdateStatusAPI_NotFound(t *testing.T) {
	store := new(MockStore)
	mgr, _ := engine.NewManager(store, nil)
	t.Cleanup(mgr.Shutdown)
	srv := &Server{engine: mgr}
	_, api := humatest.New(t)
	srv.registerUpdates(api)

	store.On("GetUpdate", mock.Anything, "missing").Return((*storage.Update)(nil), nil)

	resp := api.Get("/api/stacks/org/proj/stack/update/missing")
	assert.Equal(t, http.StatusNotFound, resp.Code)
	assert.Contains(t, resp.Body.String(), `"update not found"`)
}

func TestGetUpdateStatusAPI_InProgressHasContinuationToken(t *testing.T) {
	store := new(MockStore)
	mgr, _ := engine.NewManager(store, nil)
	t.Cleanup(mgr.Shutdown)
	srv := &Server{engine: mgr}
	_, api := humatest.New(t)
	srv.registerUpdates(api)

	store.On("GetUpdate", mock.Anything, "up-2").Return(&storage.Update{
		ID:     "up-2",
		Status: "in-progress",
	}, nil)

	resp := api.Get("/api/stacks/org/proj/stack/update/up-2")
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), `"continuationToken":""`)
}

func TestSanitizeError(t *testing.T) {
	t.Parallel()

	conflictErr := engine.ErrStackHasActiveUpdate
	longMessage := strings.Repeat("x", 201)

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "conflict passthrough", err: conflictErr, want: conflictErr.Error()},
		{name: "sql detail redacted", err: errors.New("database is locked"), want: "internal error"},
		{name: "wrapped sql detail redacted", err: fmt.Errorf("save state: %w", errors.New("constraint failed")), want: "internal error"},
		{name: "unix path redacted", err: errors.New("open /Users/alice/secrets.db: permission denied"), want: "internal error"},
		{name: "wrapped unix path redacted", err: fmt.Errorf("backup failed: %w", errors.New("open /tmp/state.db: permission denied")), want: "internal error"},
		{name: "windows path redacted", err: errors.New(`open C:\temp\secrets.db: access denied`), want: "internal error"},
		{name: "uuid redacted", err: errors.New("update 123e4567-e89b-12d3-a456-426614174000 failed"), want: "internal error"},
		{name: "long message redacted", err: errors.New(longMessage), want: "internal error"},
		{name: "safe message preserved", err: errors.New("stack already exists"), want: "stack already exists"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sanitizeError(tt.err))
		})
	}
}

func TestUpdateHandlers_Lifecycle(t *testing.T) {
	api := newTestAPI(t)
	setup := api.createStackAndUpdate(t, "dev")
	api.startUpdate(t, "dev", setup.updateID, map[string]any{"tags": map[string]string{}, "journalVersion": 0})

	// Status should be in-progress.
	rec := api.do(http.MethodGet, api.updatePath("dev", setup.updateID), nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var statusResp struct {
		Status            string  `json:"status"`
		ContinuationToken *string `json:"continuationToken"`
	}
	api.jsonBody(rec, &statusResp)
	assert.Equal(t, "in-progress", statusResp.Status)
	assert.NotNil(t, statusResp.ContinuationToken)

	// Renew lease.
	rec = api.do(http.MethodPost, api.updatePath("dev", setup.updateID)+"/renew_lease", map[string]any{"duration": 300})
	require.Equal(t, http.StatusOK, rec.Code)
	var renewResp struct {
		Token           string `json:"token"`
		TokenExpiration int64  `json:"tokenExpiration"`
	}
	api.jsonBody(rec, &renewResp)
	assert.NotEmpty(t, renewResp.Token)
	assert.NotZero(t, renewResp.TokenExpiration)

	// Post events.
	rec = api.do(http.MethodPost, api.updatePath("dev", setup.updateID)+"/events",
		map[string]any{"sequence": 1, "timestamp": 12345, "type": "preludeEvent"})
	assert.Equal(t, http.StatusOK, rec.Code)

	rec = api.do(http.MethodPost, api.updatePath("dev", setup.updateID)+"/events/batch",
		map[string]any{"events": []map[string]any{
			{"sequence": 2, "timestamp": 12346, "type": "resourcePreEvent"},
			{"sequence": 3, "timestamp": 12347, "type": "resourceOutputsEvent"},
		}})
	assert.Equal(t, http.StatusOK, rec.Code)

	// Get events.
	rec = api.do(http.MethodGet, api.updatePath("dev", setup.updateID)+"/events", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var eventsResp struct {
		Events            []json.RawMessage `json:"events"`
		ContinuationToken *string           `json:"continuationToken"`
	}
	api.jsonBody(rec, &eventsResp)
	assert.Len(t, eventsResp.Events, 3)
	assert.NotNil(t, eventsResp.ContinuationToken)

	// Save checkpoint.
	rec = api.do(http.MethodPatch, api.updatePath("dev", setup.updateID)+"/checkpoint", map[string]any{
		"version": 3,
		"deployment": map[string]any{
			"manifest":  map[string]any{"time": "2024-01-01T00:00:00Z", "magic": "test", "version": "v3.0.0"},
			"resources": []map[string]any{{"urn": "urn:pulumi:dev::test-project::pulumi:pulumi:Stack::test-project-dev", "type": "pulumi:pulumi:Stack"}},
		},
	})
	assert.Equal(t, http.StatusOK, rec.Code)

	// Complete.
	rec = api.do(http.MethodPost, api.updatePath("dev", setup.updateID)+"/complete",
		map[string]any{"status": "succeeded", "result": map[string]any{}})
	assert.Equal(t, http.StatusOK, rec.Code)

	// Final status.
	rec = api.do(http.MethodGet, api.updatePath("dev", setup.updateID), nil)
	var finalStatus struct {
		Status            string  `json:"status"`
		ContinuationToken *string `json:"continuationToken"`
	}
	api.jsonBody(rec, &finalStatus)
	assert.Equal(t, "succeeded", finalStatus.Status)
	assert.Nil(t, finalStatus.ContinuationToken)

	// Events after completion have no continuationToken.
	rec = api.do(http.MethodGet, api.updatePath("dev", setup.updateID)+"/events", nil)
	var finalEvents struct {
		ContinuationToken *string `json:"continuationToken"`
	}
	api.jsonBody(rec, &finalEvents)
	assert.Nil(t, finalEvents.ContinuationToken)
}

func TestUpdateHandlers_StartNonExistentStackFails(t *testing.T) {
	api := newTestAPI(t)

	rec := api.do(http.MethodPost, "/api/stacks/organization/no-project/no-stack/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	api.jsonBody(rec, &createResp)

	rec = api.do(http.MethodPost, "/api/stacks/organization/no-project/no-stack/update/"+createResp.UpdateID, map[string]any{})
	assert.NotEqual(t, http.StatusOK, rec.Code)
}

func TestUpdateHandlers_DuplicateLocking(t *testing.T) {
	api := newTestAPI(t)
	setup := api.createStackAndUpdate(t, "dev")
	api.startUpdate(t, "dev", setup.updateID, nil)

	// Second create should fail with 409.
	rec := api.do(http.MethodPost, api.stackPath("dev")+"/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestUpdateHandlers_CompleteWithFailedStatus(t *testing.T) {
	api := newTestAPI(t)
	setup := api.createStackAndUpdate(t, "dev")
	api.startUpdate(t, "dev", setup.updateID, nil)

	rec := api.do(http.MethodPost, api.updatePath("dev", setup.updateID)+"/complete",
		map[string]any{"status": "failed", "result": map[string]any{}})
	assert.Equal(t, http.StatusOK, rec.Code)

	// History should show failed.
	rec = api.do(http.MethodGet, api.stackPath("dev")+"/updates", nil)
	var histResp struct {
		Updates []struct {
			Result string `json:"result"`
		} `json:"updates"`
	}
	api.jsonBody(rec, &histResp)
	require.NotEmpty(t, histResp.Updates)
	assert.Equal(t, "failed", histResp.Updates[0].Result)

	// Stack should be unlocked.
	rec = api.do(http.MethodPost, api.stackPath("dev")+"/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestUpdateHandlers_Cancel(t *testing.T) {
	api := newTestAPI(t)
	setup := api.createStackAndUpdate(t, "dev")
	api.startUpdate(t, "dev", setup.updateID, nil)

	rec := api.do(http.MethodPost, api.updatePath("dev", setup.updateID)+"/cancel", map[string]any{})
	assert.Equal(t, http.StatusOK, rec.Code)

	// Stack should be unlocked.
	rec = api.do(http.MethodGet, api.stackPath("dev"), nil)
	var body map[string]any
	api.jsonBody(rec, &body)
	assert.Nil(t, body["activeUpdate"])
}

func TestUpdateHandlers_ConcurrentDifferentStacks(t *testing.T) {
	api := newTestAPI(t)
	api.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": "stack-a"})
	api.do(http.MethodPost, "/api/stacks/organization/test-project", map[string]string{"stackName": "stack-b"})

	var wg sync.WaitGroup
	errs := make([]error, 2)
	updateIDs := make([]string, 2)

	for i, stack := range []string{"stack-a", "stack-b"} {
		wg.Add(1)
		go func(idx int, name string) {
			defer wg.Done()
			rec := api.do(http.MethodPost, api.stackPath(name)+"/update",
				map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
			var resp struct {
				UpdateID string `json:"updateID"`
			}
			api.jsonBody(rec, &resp)
			if resp.UpdateID == "" {
				errs[idx] = fmt.Errorf("empty updateID for %s", name)
				return
			}
			updateIDs[idx] = resp.UpdateID
			rec = api.do(http.MethodPost, api.updatePath(name, resp.UpdateID), map[string]any{})
			if rec.Code != http.StatusOK {
				errs[idx] = fmt.Errorf("start update for %s returned %d", name, rec.Code)
			}
		}(i, stack)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "stack %d", i)
	}
	for i, stack := range []string{"stack-a", "stack-b"} {
		rec := api.do(http.MethodGet, api.stackPath(stack), nil)
		var body map[string]any
		api.jsonBody(rec, &body)
		assert.Equal(t, updateIDs[i], body["activeUpdate"], stack)
	}
}

func TestUpdateHandlers_CheckpointVerbatim(t *testing.T) {
	api := newTestAPI(t)
	setup := api.createStackAndUpdate(t, "dev")
	api.startUpdate(t, "dev", setup.updateID, nil)

	deployment := `{"version":3,"deployment":{"manifest":{"time":"2024-01-01T00:00:00Z"},"resources":[]}}`
	rec := api.do(http.MethodPatch, api.updatePath("dev", setup.updateID)+"/checkpointverbatim", map[string]any{
		"version":           3,
		"untypedDeployment": json.RawMessage(deployment),
		"sequenceNumber":    1,
	})
	assert.Equal(t, http.StatusOK, rec.Code)

	// Complete.
	api.do(http.MethodPost, api.updatePath("dev", setup.updateID)+"/complete",
		map[string]any{"status": "succeeded", "result": map[string]any{}})

	// Verify state was saved.
	rec = api.do(http.MethodGet, api.stackPath("dev")+"/export", nil)
	assert.Contains(t, rec.Body.String(), "deployment")
}

func TestUpdateHandlers_JournalEntries(t *testing.T) {
	api := newTestAPI(t)
	setup := api.createStackAndUpdate(t, "dev")
	rec := api.startUpdate(t, "dev", setup.updateID, map[string]any{"tags": map[string]string{}, "journalVersion": 1})
	var startResp struct {
		JournalVersion int `json:"journalVersion"`
	}
	api.jsonBody(rec, &startResp)
	assert.Equal(t, 1, startResp.JournalVersion)

	rec = api.do(http.MethodPatch, api.updatePath("dev", setup.updateID)+"/journalentries", map[string]any{
		"entries": []map[string]any{
			{"sequenceID": 1, "kind": "begin"},
			{"sequenceID": 2, "kind": "save"},
		},
	})
	assert.Equal(t, http.StatusOK, rec.Code)
}
