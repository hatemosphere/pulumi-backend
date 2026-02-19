package tests

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// ===== Auth =====

func TestAuthMissingHeader(t *testing.T) {
	tb := startBackend(t)

	req, _ := http.NewRequest("GET", tb.URL+"/api/user", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAuthInvalidFormat(t *testing.T) {
	tb := startBackend(t)

	req, _ := http.NewRequest("GET", tb.URL+"/api/user", nil)
	req.Header.Set("Authorization", "Bearer some-jwt-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAuthUpdateTokenFormat(t *testing.T) {
	tb := startBackend(t)

	req, _ := http.NewRequest("GET", tb.URL+"/api/user", nil)
	req.Header.Set("Authorization", "update-token some-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for update-token auth, got %d", resp.StatusCode)
	}
}

// ===== Health Check =====

func TestHealthCheck(t *testing.T) {
	tb := startBackend(t)

	req, _ := http.NewRequest("GET", tb.URL+"/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	var body map[string]string
	httpJSON(t, resp, &body)

	if body["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", body["status"])
	}
}

func TestHealthCheckJSON(t *testing.T) {
	tb := startBackend(t)

	req, _ := http.NewRequest("GET", tb.URL+"/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("expected Content-Type=application/json, got %s", resp.Header.Get("Content-Type"))
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ===== Capabilities =====

func TestCapabilitiesResponse(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "GET", "/api/capabilities", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body struct {
		Capabilities []struct {
			Capability    string          `json:"capability"`
			Version       int             `json:"version"`
			Configuration json.RawMessage `json:"configuration"`
		} `json:"capabilities"`
	}
	httpJSON(t, resp, &body)

	if len(body.Capabilities) < 2 {
		t.Fatalf("expected at least 2 capabilities, got %d", len(body.Capabilities))
	}

	foundDelta := false
	foundBatch := false
	for _, cap := range body.Capabilities {
		switch cap.Capability {
		case "delta-checkpoint-uploads-v2":
			foundDelta = true
			if cap.Version != 2 {
				t.Fatalf("expected delta version 2, got %d", cap.Version)
			}
			var config struct {
				CutoffSize int `json:"checkpointCutoffSizeBytes"`
			}
			_ = json.Unmarshal(cap.Configuration, &config)
			if config.CutoffSize == 0 {
				t.Fatal("expected non-zero checkpointCutoffSizeBytes")
			}
		case "batch-encrypt":
			foundBatch = true
		}
	}
	if !foundDelta {
		t.Fatal("missing delta-checkpoint-uploads-v2 capability")
	}
	if !foundBatch {
		t.Fatal("missing batch-encrypt capability")
	}
}

// ===== User / Org =====

func TestUserResponse(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "GET", "/api/user", nil)
	var body map[string]any
	httpJSON(t, resp, &body)

	if body["githubLogin"] != "test-user" {
		t.Fatalf("expected githubLogin=test-user, got %v", body["githubLogin"])
	}
	if body["tokenInfo"] == nil {
		t.Fatal("expected tokenInfo field to be present")
	}
	if body["organizations"] == nil {
		t.Fatal("expected organizations field")
	}
}

func TestDefaultOrgResponse(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "GET", "/api/user/organizations/default", nil)
	var body map[string]any
	httpJSON(t, resp, &body)

	// Must be PascalCase, not camelCase.
	if body["GitHubLogin"] != "organization" {
		t.Fatalf("expected GitHubLogin=organization (PascalCase), got body: %v", body)
	}
	if body["githubLogin"] != nil {
		t.Fatal("should not have camelCase githubLogin in default org response")
	}
}

func TestCLIVersion(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "GET", "/api/cli/version", nil)
	var body map[string]any
	httpJSON(t, resp, &body)

	if body["latestVersion"] == nil {
		t.Fatal("expected latestVersion field")
	}
	if body["oldestWithoutWarning"] == nil {
		t.Fatal("expected oldestWithoutWarning field")
	}
}

func TestUserStacksFilterByProject(t *testing.T) {
	tb := startBackend(t)

	// Create stacks across multiple projects.
	for _, project := range []string{"alpha", "beta"} {
		for _, stack := range []string{"dev", "prod"} {
			resp := tb.httpDo(t, "POST", "/api/stacks/organization/"+project,
				map[string]string{"stackName": stack})
			resp.Body.Close()
		}
	}

	// List stacks filtered by project=alpha.
	resp := tb.httpDo(t, "GET", "/api/user/stacks?organization=organization&project=alpha", nil)
	var listResp struct {
		Stacks []struct {
			ProjectName string `json:"projectName"`
			StackName   string `json:"stackName"`
		} `json:"stacks"`
	}
	httpJSON(t, resp, &listResp)

	for _, s := range listResp.Stacks {
		if s.ProjectName != "alpha" {
			t.Fatalf("expected only alpha stacks, got project=%s", s.ProjectName)
		}
	}
	if len(listResp.Stacks) != 2 {
		t.Fatalf("expected 2 alpha stacks, got %d", len(listResp.Stacks))
	}
}

func TestOrgStacksListing(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/project-a",
		map[string]string{"stackName": "dev"})
	resp.Body.Close()
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/project-b",
		map[string]string{"stackName": "prod"})
	resp.Body.Close()

	resp = tb.httpDo(t, "GET", "/api/stacks/organization", nil)
	var listResp struct {
		Stacks []struct {
			OrgName     string `json:"orgName"`
			ProjectName string `json:"projectName"`
			StackName   string `json:"stackName"`
		} `json:"stacks"`
	}
	httpJSON(t, resp, &listResp)

	if len(listResp.Stacks) != 2 {
		t.Fatalf("expected 2 stacks, got %d", len(listResp.Stacks))
	}
	for _, s := range listResp.Stacks {
		if s.OrgName != "organization" {
			t.Fatalf("expected org=organization, got %s", s.OrgName)
		}
	}
}

// ===== Stack CRUD via HTTP =====

func TestProjectExistsEndpoint(t *testing.T) {
	tb := startBackend(t)

	// HEAD for non-existent project -> 404.
	resp := tb.httpDo(t, "HEAD", "/api/stacks/organization/test-project", nil)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for non-existent project, got %d", resp.StatusCode)
	}

	// Create a stack to make the project exist.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project", map[string]string{"stackName": "dev"})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for create stack, got %d", resp.StatusCode)
	}

	// HEAD for existing project -> 200.
	resp = tb.httpDo(t, "HEAD", "/api/stacks/organization/test-project", nil)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for existing project, got %d", resp.StatusCode)
	}
}

func TestCreateStackMissingName(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project", map[string]string{})
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for missing stackName, got %d", resp.StatusCode)
	}
}

func TestGetNonExistentStack(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/nonexistent", nil)
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for non-existent stack, got %d", resp.StatusCode)
	}
}

func TestDeleteNonExistentStack(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "DELETE", "/api/stacks/organization/test-project/nonexistent", nil)
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 for deleting non-existent stack (idempotent), got %d", resp.StatusCode)
	}
}

func TestRenameStackHTTP(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "old-name"})
	resp.Body.Close()

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/old-name/rename",
		map[string]string{"newName": "new-name"})
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 for rename, got %d", resp.StatusCode)
	}

	// Old name should 404.
	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/old-name", nil)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for old name, got %d", resp.StatusCode)
	}

	// New name should exist.
	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/new-name", nil)
	var stackResp struct {
		StackName string `json:"stackName"`
	}
	httpJSON(t, resp, &stackResp)
	if stackResp.StackName != "new-name" {
		t.Fatalf("expected stackName=new-name, got %s", stackResp.StackName)
	}
}

// ===== Stack Tags via HTTP =====

func TestStackTagsHTTP(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project", map[string]string{"stackName": "dev"})
	resp.Body.Close()

	tags := map[string]string{"env": "production", "team": "platform"}
	resp = tb.httpDo(t, "PATCH", "/api/stacks/organization/test-project/dev/tags", tags)
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 for tag update, got %d", resp.StatusCode)
	}

	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev", nil)
	var stackResp struct {
		Tags map[string]string `json:"tags"`
	}
	httpJSON(t, resp, &stackResp)
	if stackResp.Tags["env"] != "production" {
		t.Fatalf("expected env=production, got %v", stackResp.Tags)
	}
	if stackResp.Tags["team"] != "platform" {
		t.Fatalf("expected team=platform, got %v", stackResp.Tags)
	}

	// Replace all tags.
	resp = tb.httpDo(t, "PATCH", "/api/stacks/organization/test-project/dev/tags",
		map[string]string{"env": "staging"})
	resp.Body.Close()

	var stackResp2 struct {
		Tags map[string]string `json:"tags"`
	}
	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev", nil)
	httpJSON(t, resp, &stackResp2)
	if stackResp2.Tags["env"] != "staging" {
		t.Fatalf("expected env=staging after replace, got %v", stackResp2.Tags)
	}
	if stackResp2.Tags["team"] != "" {
		t.Fatalf("expected team tag to be gone after replace-all, got %v", stackResp2.Tags)
	}
}

// ===== Export =====

func TestExportFreshStackReturnsEmptyDeployment(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "empty"})
	resp.Body.Close()

	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/empty/export", nil)
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 404 {
		t.Fatalf("expected 200 or 404 for fresh stack export, got %d", resp.StatusCode)
	}
}

// ===== Import =====

func TestImportReturnsUpdateID(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "dev"})
	resp.Body.Close()

	deployment := map[string]any{
		"version": 3,
		"deployment": map[string]any{
			"manifest":  map[string]any{"time": "2024-01-01T00:00:00Z"},
			"resources": []any{},
		},
	}
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/import", deployment)
	var importResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &importResp)

	if importResp.UpdateID == "" {
		t.Fatal("expected updateID in import response")
	}

	// The update should be completed.
	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/update/"+importResp.UpdateID, nil)
	var statusResp struct {
		Status string `json:"status"`
	}
	httpJSON(t, resp, &statusResp)
	if statusResp.Status != "succeeded" {
		t.Fatalf("expected import update status=succeeded, got %s", statusResp.Status)
	}
}

// ===== Update Lifecycle via HTTP =====

func TestUpdateLifecycleHTTP(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project", map[string]string{"stackName": "dev"})
	resp.Body.Close()

	// Create an update.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID         string `json:"updateID"`
		RequiredPolicies []any  `json:"requiredPolicies"`
		Messages         []any  `json:"messages"`
	}
	httpJSON(t, resp, &createResp)
	if createResp.UpdateID == "" {
		t.Fatal("expected updateID in create response")
	}
	if createResp.RequiredPolicies == nil {
		t.Fatal("expected requiredPolicies array (even if empty)")
	}

	// Start the update.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID,
		map[string]any{"tags": map[string]string{}, "journalVersion": 0})
	var startResp struct {
		Version         int    `json:"version"`
		Token           string `json:"token"`
		TokenExpiration int64  `json:"tokenExpiration"`
		JournalVersion  int    `json:"journalVersion"`
	}
	httpJSON(t, resp, &startResp)
	if startResp.Version == 0 {
		t.Fatal("expected non-zero version from start")
	}
	if startResp.Token == "" {
		t.Fatal("expected token from start")
	}
	if startResp.TokenExpiration == 0 {
		t.Fatal("expected non-zero tokenExpiration from start")
	}

	// Get update status — should be in-progress.
	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID, nil)
	var statusResp struct {
		Status            string  `json:"status"`
		Events            []any   `json:"events"`
		ContinuationToken *string `json:"continuationToken"`
	}
	httpJSON(t, resp, &statusResp)
	if statusResp.Status != "in-progress" {
		t.Fatalf("expected in-progress, got %s", statusResp.Status)
	}
	if statusResp.ContinuationToken == nil {
		t.Fatal("expected non-nil continuationToken for in-progress update")
	}

	// Renew lease.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/renew_lease",
		map[string]any{"duration": 300})
	var renewResp struct {
		Token           string `json:"token"`
		TokenExpiration int64  `json:"tokenExpiration"`
	}
	httpJSON(t, resp, &renewResp)
	if renewResp.Token == "" {
		t.Fatal("expected token from renew")
	}
	if renewResp.TokenExpiration == 0 {
		t.Fatal("expected tokenExpiration from renew")
	}

	// Post an event.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/events",
		map[string]any{"sequence": 1, "timestamp": 12345, "type": "preludeEvent"})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for event post, got %d", resp.StatusCode)
	}

	// Post batch events.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/events/batch",
		map[string]any{"events": []map[string]any{
			{"sequence": 2, "timestamp": 12346, "type": "resourcePreEvent"},
			{"sequence": 3, "timestamp": 12347, "type": "resourceOutputsEvent"},
		}})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for batch event post, got %d", resp.StatusCode)
	}

	// Get events.
	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/events", nil)
	var eventsResp struct {
		Status            string            `json:"status"`
		Events            []json.RawMessage `json:"events"`
		ContinuationToken *string           `json:"continuationToken"`
	}
	httpJSON(t, resp, &eventsResp)
	if len(eventsResp.Events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(eventsResp.Events))
	}
	if eventsResp.ContinuationToken == nil {
		t.Fatal("expected continuationToken for in-progress update")
	}

	// Save a checkpoint.
	resp = tb.httpDo(t, "PATCH", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/checkpoint",
		map[string]any{
			"version": 3,
			"deployment": map[string]any{
				"manifest": map[string]any{"time": "2024-01-01T00:00:00Z", "magic": "test", "version": "v3.0.0"},
				"resources": []map[string]any{
					{
						"urn":  "urn:pulumi:dev::test-project::pulumi:pulumi:Stack::test-project-dev",
						"type": "pulumi:pulumi:Stack",
					},
				},
			},
		})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for checkpoint, got %d", resp.StatusCode)
	}

	// Complete the update.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/complete",
		map[string]any{"status": "succeeded", "result": map[string]any{}})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for complete, got %d", resp.StatusCode)
	}

	// Get update status — should be succeeded, no continuationToken.
	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID, nil)
	var finalStatus struct {
		Status            string  `json:"status"`
		ContinuationToken *string `json:"continuationToken"`
	}
	httpJSON(t, resp, &finalStatus)
	if finalStatus.Status != "succeeded" {
		t.Fatalf("expected succeeded, got %s", finalStatus.Status)
	}
	if finalStatus.ContinuationToken != nil {
		t.Fatal("expected nil continuationToken for completed update")
	}

	// Get events after completion — no continuationToken.
	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/events", nil)
	var finalEvents struct {
		ContinuationToken *string `json:"continuationToken"`
		Events            []any   `json:"events"`
	}
	httpJSON(t, resp, &finalEvents)
	if finalEvents.ContinuationToken != nil {
		t.Fatal("expected nil continuationToken after completion")
	}
}

func TestGetNonExistentUpdate(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/update/nonexistent-uuid", nil)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for non-existent update, got %d", resp.StatusCode)
	}
}

func TestStartUpdateNonExistentStackFails(t *testing.T) {
	tb := startBackend(t)

	// Create update succeeds (just a record), but start fails because stack doesn't exist.
	resp := tb.httpDo(t, "POST", "/api/stacks/organization/no-project/no-stack/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &createResp)

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/no-project/no-stack/update/"+createResp.UpdateID,
		map[string]any{})
	resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Fatal("expected error starting update for non-existent stack")
	}
}

func TestGetStackActiveUpdate(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project", map[string]string{"stackName": "dev"})
	resp.Body.Close()

	// No active update initially.
	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev", nil)
	var stackResp map[string]any
	httpJSON(t, resp, &stackResp)
	if stackResp["activeUpdate"] != nil {
		t.Fatal("expected no activeUpdate initially")
	}

	// Create and start an update.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &createResp)

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID,
		map[string]any{})
	resp.Body.Close()

	// Now getStack should show activeUpdate.
	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev", nil)
	httpJSON(t, resp, &stackResp)
	if stackResp["activeUpdate"] == nil {
		t.Fatal("expected activeUpdate to be set after starting an update")
	}
	if stackResp["activeUpdate"] != createResp.UpdateID {
		t.Fatalf("expected activeUpdate=%s, got %v", createResp.UpdateID, stackResp["activeUpdate"])
	}
}

func TestDuplicateUpdateLockingHTTP(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project", map[string]string{"stackName": "dev"})
	resp.Body.Close()

	// Create and start an update.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &createResp)

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID,
		map[string]any{})
	resp.Body.Close()

	// Second create should fail with 409 (conflict — stack locked).
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Fatalf("expected 409 for locked stack, got %d", resp.StatusCode)
	}
}

func TestCompleteUpdateWithFailedStatus(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "dev"})
	resp.Body.Close()

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &createResp)

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID,
		map[string]any{})
	resp.Body.Close()

	// Complete with failed status.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/complete",
		map[string]any{"status": "failed", "result": map[string]any{}})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for failed complete, got %d", resp.StatusCode)
	}

	// History should show failed result.
	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/updates", nil)
	var histResp struct {
		Updates []struct {
			Result string `json:"result"`
		} `json:"updates"`
	}
	httpJSON(t, resp, &histResp)

	if len(histResp.Updates) == 0 {
		t.Fatal("expected at least 1 history entry")
	}
	if histResp.Updates[0].Result != "failed" {
		t.Fatalf("expected result=failed, got %s", histResp.Updates[0].Result)
	}

	// Stack should be unlocked after failed update.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	if resp.StatusCode != 200 {
		resp.Body.Close()
		t.Fatalf("expected 200 for new update after failed, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestCancelUpdateHTTP(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "dev"})
	resp.Body.Close()

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &createResp)

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID,
		map[string]any{})
	resp.Body.Close()

	// Cancel.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/cancel",
		map[string]any{})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for cancel, got %d", resp.StatusCode)
	}

	// Stack should be unlocked.
	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev", nil)
	var stackResp map[string]any
	httpJSON(t, resp, &stackResp)
	if stackResp["activeUpdate"] != nil {
		t.Fatal("expected no activeUpdate after cancel")
	}
}

func TestLeaseRenewalHTTP(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "dev"})
	resp.Body.Close()

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &createResp)

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID,
		map[string]any{})
	var startResp struct {
		Token           string `json:"token"`
		TokenExpiration int64  `json:"tokenExpiration"`
	}
	httpJSON(t, resp, &startResp)

	originalToken := startResp.Token
	originalExpiry := startResp.TokenExpiration

	// Renew lease.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/renew_lease",
		map[string]any{"duration": 600})
	var renewResp struct {
		Token           string `json:"token"`
		TokenExpiration int64  `json:"tokenExpiration"`
	}
	httpJSON(t, resp, &renewResp)

	if renewResp.Token == originalToken {
		t.Fatal("expected new token after renewal")
	}
	if renewResp.TokenExpiration <= originalExpiry {
		t.Fatal("expected later expiry after renewal")
	}
}

func TestConcurrentUpdatesOnDifferentStacks(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "stack-a"})
	resp.Body.Close()
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "stack-b"})
	resp.Body.Close()

	var wg sync.WaitGroup
	errors := make([]error, 2)
	updateIDs := make([]string, 2)

	for i, stack := range []string{"stack-a", "stack-b"} {
		wg.Add(1)
		go func(idx int, stackName string) {
			defer wg.Done()

			resp := tb.httpDo(t, "POST",
				"/api/stacks/organization/test-project/"+stackName+"/update",
				map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
			var createResp struct {
				UpdateID string `json:"updateID"`
			}
			httpJSON(t, resp, &createResp)
			if createResp.UpdateID == "" {
				errors[idx] = fmt.Errorf("empty updateID for %s", stackName)
				return
			}
			updateIDs[idx] = createResp.UpdateID

			resp = tb.httpDo(t, "POST",
				"/api/stacks/organization/test-project/"+stackName+"/update/"+createResp.UpdateID,
				map[string]any{})
			if resp.StatusCode != 200 {
				errors[idx] = fmt.Errorf("start update for %s returned %d", stackName, resp.StatusCode)
			}
			resp.Body.Close()
		}(i, stack)
	}
	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("stack %d: %v", i, err)
		}
	}

	for i, stack := range []string{"stack-a", "stack-b"} {
		resp := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/"+stack, nil)
		var stackResp map[string]any
		httpJSON(t, resp, &stackResp)
		if stackResp["activeUpdate"] != updateIDs[i] {
			t.Fatalf("%s: expected activeUpdate=%s, got %v", stack, updateIDs[i], stackResp["activeUpdate"])
		}
	}
}

// ===== Events =====

func TestEventPagination(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "dev"})
	resp.Body.Close()

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &createResp)

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID,
		map[string]any{})
	resp.Body.Close()

	// Post 5 events.
	for i := 1; i <= 5; i++ {
		resp = tb.httpDo(t, "POST",
			"/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/events",
			map[string]any{"sequence": i, "timestamp": 12345 + i, "type": "testEvent"})
		resp.Body.Close()
	}

	// Get events from offset 0.
	resp = tb.httpDo(t, "GET",
		"/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/events", nil)
	var evResp struct {
		Events            []json.RawMessage `json:"events"`
		ContinuationToken *string           `json:"continuationToken"`
	}
	httpJSON(t, resp, &evResp)

	if len(evResp.Events) != 5 {
		t.Fatalf("expected 5 events, got %d", len(evResp.Events))
	}
	if evResp.ContinuationToken == nil {
		t.Fatal("expected continuationToken for in-progress update")
	}

	// Get events from offset 3.
	resp = tb.httpDo(t, "GET",
		"/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/events?continuationToken=3", nil)
	var evResp2 struct {
		Events []json.RawMessage `json:"events"`
	}
	httpJSON(t, resp, &evResp2)

	if len(evResp2.Events) != 2 {
		t.Fatalf("expected 2 events from offset 3, got %d", len(evResp2.Events))
	}
}

// ===== Checkpoint / Journal =====

func TestCheckpointVerbatimHTTP(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project", map[string]string{"stackName": "dev"})
	resp.Body.Close()

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &createResp)

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID,
		map[string]any{})
	resp.Body.Close()

	deployment := `{
  "version": 3,
  "deployment": {
    "manifest": {
      "time": "2024-01-01T00:00:00Z"
    },
    "resources": []
  }
}`
	resp = tb.httpDo(t, "PATCH", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/checkpointverbatim",
		map[string]any{
			"version":           3,
			"untypedDeployment": json.RawMessage(deployment),
			"sequenceNumber":    1,
		})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for verbatim checkpoint, got %d", resp.StatusCode)
	}

	// Complete.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/complete",
		map[string]any{"status": "succeeded", "result": map[string]any{}})
	resp.Body.Close()

	// Verify state was saved.
	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/export", nil)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "deployment") {
		t.Fatalf("expected deployment in export, got: %s", body)
	}
}

func TestJournalEntriesHTTP(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "dev"})
	resp.Body.Close()

	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update",
		map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &createResp)

	// Start update with journal version 1.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID,
		map[string]any{"tags": map[string]string{}, "journalVersion": 1})
	var startResp struct {
		JournalVersion int `json:"journalVersion"`
	}
	httpJSON(t, resp, &startResp)
	if startResp.JournalVersion != 1 {
		t.Fatalf("expected journalVersion=1, got %d", startResp.JournalVersion)
	}

	// Save journal entries.
	resp = tb.httpDo(t, "PATCH", "/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID+"/journalentries",
		map[string]any{
			"entries": []map[string]any{
				{"sequenceID": 1, "kind": "begin"},
				{"sequenceID": 2, "kind": "save"},
			},
		})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for journal entries, got %d", resp.StatusCode)
	}
}

// ===== Secrets via HTTP =====

func TestEncryptDecryptHTTP(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project", map[string]string{"stackName": "dev"})
	resp.Body.Close()

	plaintext := []byte("hello-secret-world")
	b64Plaintext := base64.StdEncoding.EncodeToString(plaintext)

	// Encrypt.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/encrypt",
		map[string]string{"plaintext": b64Plaintext})
	var encResp struct {
		Ciphertext string `json:"ciphertext"`
	}
	httpJSON(t, resp, &encResp)
	if encResp.Ciphertext == "" {
		t.Fatal("expected ciphertext in encrypt response")
	}

	// Decrypt.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/decrypt",
		map[string]string{"ciphertext": encResp.Ciphertext})
	var decResp struct {
		Plaintext string `json:"plaintext"`
	}
	httpJSON(t, resp, &decResp)

	decoded, err := base64.StdEncoding.DecodeString(decResp.Plaintext)
	if err != nil {
		t.Fatalf("failed to decode plaintext: %v", err)
	}
	if string(decoded) != string(plaintext) {
		t.Fatalf("expected %q, got %q", string(plaintext), string(decoded))
	}
}

func TestBatchEncryptDecryptHTTP(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project", map[string]string{"stackName": "dev"})
	resp.Body.Close()

	pt1 := base64.StdEncoding.EncodeToString([]byte("secret-one"))
	pt2 := base64.StdEncoding.EncodeToString([]byte("secret-two"))

	// Batch encrypt.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/batch-encrypt",
		map[string]any{"plaintexts": []string{pt1, pt2}})
	var batchEncResp struct {
		Ciphertexts []string `json:"ciphertexts"`
	}
	httpJSON(t, resp, &batchEncResp)
	if len(batchEncResp.Ciphertexts) != 2 {
		t.Fatalf("expected 2 ciphertexts, got %d", len(batchEncResp.Ciphertexts))
	}

	// Batch decrypt.
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/batch-decrypt",
		map[string]any{"ciphertexts": batchEncResp.Ciphertexts})
	var batchDecResp struct {
		Plaintexts map[string]string `json:"plaintexts"`
	}
	httpJSON(t, resp, &batchDecResp)
	if len(batchDecResp.Plaintexts) != 2 {
		t.Fatalf("expected 2 plaintexts in map, got %d", len(batchDecResp.Plaintexts))
	}
}

func TestMultipleSecretsOperationsReuseKey(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "dev"})
	resp.Body.Close()

	secrets := []string{"secret-one", "secret-two", "secret-three"}
	ciphertexts := make([]string, len(secrets))

	for i, s := range secrets {
		b64 := base64.StdEncoding.EncodeToString([]byte(s))
		resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/encrypt",
			map[string]string{"plaintext": b64})
		var encResp struct {
			Ciphertext string `json:"ciphertext"`
		}
		httpJSON(t, resp, &encResp)
		ciphertexts[i] = encResp.Ciphertext
	}

	for i, ct := range ciphertexts {
		resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project/dev/decrypt",
			map[string]string{"ciphertext": ct})
		var decResp struct {
			Plaintext string `json:"plaintext"`
		}
		httpJSON(t, resp, &decResp)

		decoded, err := base64.StdEncoding.DecodeString(decResp.Plaintext)
		if err != nil {
			t.Fatalf("failed to decode plaintext[%d]: %v", i, err)
		}
		if string(decoded) != secrets[i] {
			t.Fatalf("secret[%d]: expected %q, got %q", i, secrets[i], string(decoded))
		}
	}
}

func TestSecretsIsolationBetweenStacks(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "stack-a"})
	resp.Body.Close()
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "stack-b"})
	resp.Body.Close()

	// Encrypt with stack-a.
	plaintext := base64.StdEncoding.EncodeToString([]byte("cross-stack-secret"))
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/stack-a/encrypt",
		map[string]string{"plaintext": plaintext})
	var encResp struct {
		Ciphertext string `json:"ciphertext"`
	}
	httpJSON(t, resp, &encResp)

	// Decrypt with stack-b should fail (different stack key).
	resp = tb.httpDo(t, "POST", "/api/stacks/organization/test-project/stack-b/decrypt",
		map[string]string{"ciphertext": encResp.Ciphertext})
	if resp.StatusCode == 200 {
		var decResp struct {
			Plaintext string `json:"plaintext"`
		}
		httpJSON(t, resp, &decResp)
		decoded, _ := base64.StdEncoding.DecodeString(decResp.Plaintext)
		if string(decoded) == "cross-stack-secret" {
			t.Fatal("cross-stack decryption should fail — secrets should be isolated per stack")
		}
	} else {
		resp.Body.Close()
	}
}

// ===== Config =====

func TestUpdateStackConfigPUT(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "POST", "/api/stacks/organization/test-project",
		map[string]string{"stackName": "dev"})
	resp.Body.Close()

	resp = tb.httpDo(t, "PUT", "/api/stacks/organization/test-project/dev/config",
		map[string]any{"key": "value"})
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for config PUT, got %d", resp.StatusCode)
	}
}

// ===== Wrong Method =====

func TestWrongMethodReturnsError(t *testing.T) {
	tb := startBackend(t)

	resp := tb.httpDo(t, "PUT", "/api/capabilities", nil)
	resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Fatal("expected error for PUT on GET-only endpoint")
	}
}
