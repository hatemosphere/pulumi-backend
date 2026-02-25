package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ===== Login & User =====

func TestLoginAndUserInfo(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
`)

	out := tb.pulumi(t, dir, "login", tb.URL)
	if !strings.Contains(out, "Logged in") {
		t.Fatalf("expected 'Logged in' in output, got: %s", out)
	}

	out = tb.pulumi(t, dir, "whoami")
	if !strings.Contains(out, "test-user") {
		t.Fatalf("expected 'test-user' in output, got: %s", out)
	}
}

// ===== Stack Lifecycle =====

func TestStackLifecycle(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
`)

	tb.pulumi(t, dir, "login", tb.URL)

	// Create stack.
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	// List stacks.
	out := tb.pulumi(t, dir, "stack", "ls")
	if !strings.Contains(out, "dev") {
		t.Fatalf("expected 'dev' in stack list, got: %s", out)
	}

	// Create another stack.
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/staging")

	// List should show both.
	out = tb.pulumi(t, dir, "stack", "ls")
	if !strings.Contains(out, "dev") || !strings.Contains(out, "staging") {
		t.Fatalf("expected both stacks in list, got: %s", out)
	}

	// Select a stack.
	tb.pulumi(t, dir, "stack", "select", "organization/test-project/dev")

	// Delete a stack.
	tb.pulumi(t, dir, "stack", "rm", "--yes", "-s", "organization/test-project/staging")

	// Verify staging is gone.
	out = tb.pulumi(t, dir, "stack", "ls")
	if strings.Contains(out, "staging") {
		t.Fatalf("expected staging to be removed, got: %s", out)
	}
}

func TestStackSelect(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/staging")

	// Select dev.
	tb.pulumi(t, dir, "stack", "select", "organization/test-project/dev")

	// Verify current stack is dev.
	out := tb.pulumi(t, dir, "stack", "ls")
	lines := strings.SplitSeq(out, "\n")
	for line := range lines {
		if strings.Contains(line, "dev") && strings.Contains(line, "*") {
			return
		}
	}
	t.Fatalf("expected dev to be selected (marked with *), got: %s", out)
}

func TestListStacks(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/staging")
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/prod")

	out := tb.pulumi(t, dir, "stack", "ls", "--all")
	if !strings.Contains(out, "dev") || !strings.Contains(out, "staging") || !strings.Contains(out, "prod") {
		t.Fatalf("expected all 3 stacks in list, got: %s", out)
	}
}

func TestDeleteEmptyStack(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/to-delete")
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/keeper")

	tb.pulumi(t, dir, "stack", "rm", "--yes", "-s", "organization/test-project/to-delete")

	out := tb.pulumi(t, dir, "stack", "ls")
	if strings.Contains(out, "to-delete") {
		t.Fatalf("expected to-delete to be removed, got: %s", out)
	}
	if !strings.Contains(out, "keeper") {
		t.Fatalf("expected keeper to still exist, got: %s", out)
	}
}

func TestDeleteNonEmptyStackRequiresForce(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "non-empty"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	// Delete without force should fail.
	out := tb.pulumiExpectFailure(t, dir, "stack", "rm", "--yes", "-s", "organization/test-project/dev")
	if !strings.Contains(out, "resources") && !strings.Contains(out, "force") {
		t.Logf("Warning: expected 'resources' or 'force' in error, got: %s", out)
	}

	// Delete with force should succeed.
	tb.pulumi(t, dir, "stack", "rm", "--yes", "--force", "-s", "organization/test-project/dev")
}

func TestDuplicateStackCreationFails(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	out := tb.pulumiExpectFailure(t, dir, "stack", "init", "organization/test-project/dev")
	if !strings.Contains(out, "409") && !strings.Contains(out, "already exists") && !strings.Contains(out, "UNIQUE") {
		t.Fatalf("expected conflict error, got: %s", out)
	}
}

// ===== Stack Tags =====

func TestStackTagsCRUD(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumi(t, dir, "stack", "tag", "set", "env", "production", "--stack", "organization/test-project/dev")

	out := tb.pulumi(t, dir, "stack", "tag", "get", "env", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "production") {
		t.Fatalf("expected tag value 'production', got: %s", out)
	}

	out = tb.pulumi(t, dir, "stack", "tag", "ls", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "env") {
		t.Fatalf("expected 'env' in tag list, got: %s", out)
	}

	tb.pulumi(t, dir, "stack", "tag", "rm", "env", "--stack", "organization/test-project/dev")

	_, err := tb.pulumiMayFail(t, dir, nil,
		"stack", "tag", "get", "env", "--stack", "organization/test-project/dev",
	)
	if err == nil {
		t.Fatal("expected error getting removed tag")
	}
}

func TestStackTagsSetByUpdate(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: my-project
runtime: yaml
outputs:
  value: "tags-test"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/my-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/my-project/dev",
	)

	resp := tb.httpDo(t, "GET", "/api/stacks/organization/my-project/dev", nil)
	var stackResp struct {
		Tags map[string]string `json:"tags"`
	}
	httpJSON(t, resp, &stackResp)

	if stackResp.Tags == nil {
		t.Fatal("expected tags to be set after update")
	}
}

// ===== Stack Rename =====

func TestRenameStack(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "rename-test"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/old-name")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/old-name",
	)

	tb.pulumi(t, dir, "stack", "rename", "new-name", "--stack", "organization/test-project/old-name")

	out := tb.pulumi(t, dir, "stack", "ls")
	if strings.Contains(out, "old-name") {
		t.Fatalf("old stack name should be gone, got: %s", out)
	}
	if !strings.Contains(out, "new-name") {
		t.Fatalf("expected new-name in stack list, got: %s", out)
	}

	exported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/new-name")
	if !strings.Contains(exported, "pulumi:pulumi:Stack") {
		t.Fatalf("expected stack resource in export after rename, got: %s", exported)
	}
}

func TestStackRenamePreservesHistory(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "rename-test"
`)

	journalEnv := []string{"PULUMI_ENABLE_JOURNALING=true"}

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/before-rename")

	tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/before-rename")

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  value: "rename-test-v2"
`), 0o644)
	tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/before-rename")

	resp := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/before-rename/updates", nil)
	var histBefore struct {
		Updates []struct {
			Version int `json:"version"`
		} `json:"updates"`
	}
	httpJSON(t, resp, &histBefore)
	beforeCount := len(histBefore.Updates)

	tb.pulumi(t, dir, "stack", "rename", "after-rename", "--stack", "organization/test-project/before-rename")

	exported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/after-rename")
	if !strings.Contains(exported, "pulumi:pulumi:Stack") {
		t.Fatal("state lost after rename")
	}

	tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/after-rename")

	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/after-rename/updates", nil)
	var histAfter struct {
		Updates []struct {
			Version int `json:"version"`
		} `json:"updates"`
	}
	httpJSON(t, resp, &histAfter)

	if len(histAfter.Updates) <= beforeCount {
		t.Fatalf("expected history to grow after rename: before=%d, after=%d", beforeCount, len(histAfter.Updates))
	}
}

// ===== Preview =====

func TestPreviewAndUp(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  greeting: "hello world"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	out := tb.pulumi(t, dir, "preview", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "create") {
		t.Fatalf("expected 'create' in preview output, got: %s", out)
	}

	out = tb.pulumi(t, dir, "up", "--yes", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "1 created") {
		t.Fatalf("expected '1 created' in up output, got: %s", out)
	}

	out = tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "pulumi:pulumi:Stack") {
		t.Fatalf("expected Stack resource in export, got: %s", out)
	}
}

func TestPreviewOnlyDoesNotSaveCheckpoint(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  greeting: "hello"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	out := tb.pulumi(t, dir, "preview", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "create") {
		t.Fatalf("expected 'create' in preview output, got: %s", out)
	}

	resp := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/export", nil)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), "pulumi:pulumi:Stack") {
		t.Fatal("preview should not save state — export should not contain Stack resource")
	}

	resp2 := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/updates", nil)
	var histResp struct {
		Updates []struct {
			Kind   string `json:"kind"`
			Result string `json:"result"`
		} `json:"updates"`
	}
	httpJSON(t, resp2, &histResp)

	if len(histResp.Updates) != 1 {
		t.Fatalf("expected 1 history entry for preview, got %d", len(histResp.Updates))
	}
	if histResp.Updates[0].Kind != "preview" {
		t.Fatalf("expected kind=preview, got %s", histResp.Updates[0].Kind)
	}
}

// ===== Up (Update) =====

func TestUpWithJournaling(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "journaling-test"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	out := tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)
	if !strings.Contains(out, "1 created") {
		t.Fatalf("expected '1 created' in up output, got: %s", out)
	}

	out = tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "pulumi:pulumi:Stack") {
		t.Fatalf("expected Stack resource in export after journaling, got: %s", out)
	}
}

func TestWithoutJournaling(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  mode: "no-journaling"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	out := tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=false"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)
	if !strings.Contains(out, "1 created") {
		t.Fatalf("expected '1 created', got: %s", out)
	}

	out = tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "pulumi:pulumi:Stack") {
		t.Fatalf("expected Stack resource in export, got: %s", out)
	}

	out = tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=false"},
		"destroy", "--yes", "--stack", "organization/test-project/dev",
	)
	if !strings.Contains(out, "1 deleted") {
		t.Fatalf("expected '1 deleted', got: %s", out)
	}
}

func TestMultipleUpdates(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  version: "v1"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  version: "v2"
  newOutput: "added"
`), 0o644)

	out := tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)
	if !strings.Contains(out, "1 unchanged") {
		t.Fatalf("expected '1 unchanged' in second update, got: %s", out)
	}

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  version: "v3"
`), 0o644)

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)
}

func TestStackVersionIncrementsOnUpdates(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "v1"
`)

	journalEnv := []string{"PULUMI_ENABLE_JOURNALING=true"}

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	resp := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev", nil)
	var stackResp struct {
		Version int `json:"version"`
	}
	httpJSON(t, resp, &stackResp)
	if stackResp.Version != 0 {
		t.Fatalf("expected initial version=0, got %d", stackResp.Version)
	}

	tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/dev")

	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev", nil)
	httpJSON(t, resp, &stackResp)
	if stackResp.Version < 1 {
		t.Fatalf("expected version >= 1 after first up, got %d", stackResp.Version)
	}
	firstVersion := stackResp.Version

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  value: "v2"
`), 0o644)
	tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/dev")

	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev", nil)
	httpJSON(t, resp, &stackResp)
	if stackResp.Version <= firstVersion {
		t.Fatalf("expected version > %d after second up, got %d", firstVersion, stackResp.Version)
	}
}

func TestStackOutput(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  greeting: "hello-from-output"
  number: "42"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	out := tb.pulumi(t, dir, "stack", "output", "greeting", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "hello-from-output") {
		t.Fatalf("expected 'hello-from-output' in stack output, got: %s", out)
	}

	out = tb.pulumi(t, dir, "stack", "output", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "greeting") || !strings.Contains(out, "number") {
		t.Fatalf("expected both outputs in stack output, got: %s", out)
	}
}

func TestStackShowURNs(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "urn-test"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")
	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	out := tb.pulumi(t, dir, "stack", "--show-urns", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "urn:pulumi") {
		t.Fatalf("expected URN in stack output, got: %s", out)
	}
}

func TestResourceCountInStackListing(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "resource-count-test"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	resp := tb.httpDo(t, "GET", "/api/user/stacks?organization=organization", nil)
	var listResp struct {
		Stacks []struct {
			StackName     string `json:"stackName"`
			ResourceCount int    `json:"resourceCount"`
		} `json:"stacks"`
	}
	httpJSON(t, resp, &listResp)

	for _, s := range listResp.Stacks {
		if s.StackName == "dev" && s.ResourceCount != 0 {
			t.Fatalf("expected resourceCount=0 before deploy, got %d", s.ResourceCount)
		}
	}

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	resp = tb.httpDo(t, "GET", "/api/user/stacks?organization=organization", nil)
	var listResp2 struct {
		Stacks []struct {
			StackName     string `json:"stackName"`
			ResourceCount int    `json:"resourceCount"`
		} `json:"stacks"`
	}
	httpJSON(t, resp, &listResp2)

	found := false
	for _, s := range listResp2.Stacks {
		if s.StackName == "dev" {
			found = true
			if s.ResourceCount != 1 {
				t.Fatalf("expected resourceCount=1 after deploy, got %d", s.ResourceCount)
			}
		}
	}
	if !found {
		t.Fatal("dev stack not found in listing")
	}
}

// ===== Destroy =====

func TestUpdateThenDestroy(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  hello: "world"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	out := tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"destroy", "--yes", "--stack", "organization/test-project/dev",
	)
	if !strings.Contains(out, "1 deleted") {
		t.Fatalf("expected '1 deleted' in destroy output, got: %s", out)
	}

	out = tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")
	var export map[string]any
	_ = json.Unmarshal([]byte(out), &export)
	deployment := export["deployment"].(map[string]any)
	resources := deployment["resources"]
	if resources != nil {
		resSlice, ok := resources.([]any)
		if ok && len(resSlice) > 0 {
			t.Fatalf("expected empty resources after destroy, got: %v", resources)
		}
	}
}

func TestDestroyThenRedeploy(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "phase-1"
`)

	journalEnv := []string{"PULUMI_ENABLE_JOURNALING=true"}

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/dev")
	tb.pulumiEnv(t, dir, journalEnv, "destroy", "--yes", "--stack", "organization/test-project/dev")

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  value: "phase-2"
  new_output: "after-destroy"
`), 0o644)
	out := tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "1 created") {
		t.Fatalf("expected '1 created' after redeploy, got: %s", out)
	}

	exported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")
	if !strings.Contains(exported, "after-destroy") {
		t.Fatalf("expected 'after-destroy' in export after redeploy, got: %s", exported)
	}
}

// ===== Refresh =====

func TestRefresh(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "refresh-test"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	out := tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"refresh", "--yes", "--stack", "organization/test-project/dev",
	)
	if !strings.Contains(out, "unchanged") {
		t.Fatalf("expected 'unchanged' in refresh output, got: %s", out)
	}
}

func TestRefreshAfterUpdateWithChanges(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "v1"
`)

	journalEnv := []string{"PULUMI_ENABLE_JOURNALING=true"}

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/dev")

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  value: "v2"
  extra: "added"
`), 0o644)
	tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/dev")

	out := tb.pulumiEnv(t, dir, journalEnv, "refresh", "--yes", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "unchanged") {
		t.Fatalf("expected 'unchanged' in refresh after update, got: %s", out)
	}

	resp := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/updates", nil)
	var histResp struct {
		Updates []struct {
			Kind string `json:"kind"`
		} `json:"updates"`
	}
	httpJSON(t, resp, &histResp)

	if len(histResp.Updates) < 3 {
		t.Fatalf("expected at least 3 history entries, got %d", len(histResp.Updates))
	}
	if histResp.Updates[0].Kind != "refresh" {
		t.Fatalf("expected latest entry to be refresh, got %s", histResp.Updates[0].Kind)
	}
}

func TestRefreshOnEmptyStack(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "test"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)
	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"destroy", "--yes", "--stack", "organization/test-project/dev",
	)

	out := tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"refresh", "--yes", "--stack", "organization/test-project/dev",
	)
	if strings.Contains(out, "error") || strings.Contains(out, "failed") {
		t.Fatalf("refresh on empty stack should succeed, got: %s", out)
	}
}

// ===== Export / Import =====

func TestExportImportRoundTrip(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "export-test"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	exported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")

	exportFile := filepath.Join(dir, "state.json")
	_ = os.WriteFile(exportFile, []byte(exported), 0o644)

	tb.pulumi(t, dir, "stack", "init", "organization/test-project/staging")
	tb.pulumi(t, dir, "stack", "import", "--file", exportFile, "--stack", "organization/test-project/staging", "--force")

	reExported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/staging")

	var orig, reimp map[string]any
	if err := json.Unmarshal([]byte(exported), &orig); err != nil {
		t.Fatalf("unmarshal exported: %v", err)
	}
	if err := json.Unmarshal([]byte(reExported), &reimp); err != nil {
		t.Fatalf("unmarshal re-exported: %v", err)
	}

	origRes := orig["deployment"].(map[string]any)["resources"]
	reimpRes := reimp["deployment"].(map[string]any)["resources"]

	origJSON, _ := json.Marshal(origRes)
	reimpJSON, _ := json.Marshal(reimpRes)

	if string(origJSON) != string(reimpJSON) {
		t.Fatalf("export/import round-trip mismatch:\nOriginal:  %s\nReimport: %s", origJSON, reimpJSON)
	}
}

func TestExportSpecificVersion(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  version: "v1"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  version: "v2"
`), 0o644)
	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	resp := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/export/1", nil)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for versioned export, got %d: %s", resp.StatusCode, body)
	}

	var export map[string]any
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if err := json.Unmarshal(b, &export); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}

	if export["deployment"] == nil {
		t.Fatal("expected deployment in versioned export")
	}

	resp2 := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/export/abc", nil)
	resp2.Body.Close()
	if resp2.StatusCode != 400 && resp2.StatusCode != 422 {
		t.Fatalf("expected 400 or 422 for invalid version, got %d", resp2.StatusCode)
	}

	resp3 := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/export/999", nil)
	resp3.Body.Close()
	if resp3.StatusCode != 404 {
		t.Fatalf("expected 404 for non-existent version, got %d", resp3.StatusCode)
	}
}

func TestExportImportCrossProject(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: project-source
runtime: yaml
outputs:
  value: "cross-project"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/project-source/dev")
	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/project-source/dev",
	)

	exported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/project-source/dev")

	dir2 := makeYAMLProject(t, `name: project-target
runtime: yaml
outputs:
  value: "cross-project"
`)

	tb.pulumi(t, dir2, "login", tb.URL)
	tb.pulumi(t, dir2, "stack", "init", "organization/project-target/dev")

	exportFile := filepath.Join(dir2, "state.json")
	_ = os.WriteFile(exportFile, []byte(exported), 0o644)
	tb.pulumi(t, dir2, "stack", "import", "--file", exportFile, "--stack", "organization/project-target/dev", "--force")

	reimported := tb.pulumi(t, dir2, "stack", "export", "--stack", "organization/project-target/dev")
	if !strings.Contains(reimported, "pulumi:pulumi:Stack") {
		t.Fatal("expected Stack resource in cross-project import")
	}
}

func TestImportOnFreshStack(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	stateFile := filepath.Join(dir, "state.json")
	_ = os.WriteFile(stateFile, []byte(`{
		"version": 3,
		"deployment": {
			"manifest": {"time": "2024-01-01T00:00:00Z", "magic": "test", "version": "v3.0.0"},
			"resources": [{
				"urn": "urn:pulumi:dev::test-project::pulumi:pulumi:Stack::test-project-dev",
				"type": "pulumi:pulumi:Stack",
				"outputs": {"imported": "yes"}
			}]
		}
	}`), 0o644)

	tb.pulumi(t, dir, "stack", "import", "--file", stateFile, "--stack", "organization/test-project/dev", "--force")

	out := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "imported") {
		t.Fatalf("expected imported data in export, got: %s", out)
	}
}

func TestImportThenUpdate(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "imported"
`)

	journalEnv := []string{"PULUMI_ENABLE_JOURNALING=true"}

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/dev")

	exported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")

	stateFile := filepath.Join(dir, "state.json")
	_ = os.WriteFile(stateFile, []byte(exported), 0o644)
	tb.pulumi(t, dir, "stack", "import", "--file", stateFile, "--stack", "organization/test-project/dev")

	out := tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "1 unchanged") {
		t.Fatalf("expected '1 unchanged' after update on imported state, got: %s", out)
	}
}

// ===== Checkpoint / Journaling Modes =====

func TestCheckpointDeltaProtocol(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "delta-test"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=false"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	out := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "pulumi:pulumi:Stack") {
		t.Fatalf("expected Stack resource in export, got: %s", out)
	}

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  value: "delta-test-v2"
`), 0o644)

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=false"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	out = tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "delta-test-v2") {
		t.Fatalf("expected 'delta-test-v2' in export after delta update, got: %s", out)
	}

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  value: "delta-test-v3"
  extra: "more-data"
`), 0o644)

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=false"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	out = tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "delta-test-v3") || !strings.Contains(out, "more-data") {
		t.Fatalf("expected 'delta-test-v3' and 'more-data' in export, got: %s", out)
	}
}

func TestJournalingToCheckpointSwitch(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "v1"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  value: "v2"
`), 0o644)
	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=false"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  value: "v3"
`), 0o644)
	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	out := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "pulumi:pulumi:Stack") {
		t.Fatal("expected stack resource in final state")
	}
}

func TestCheckpointThenJournalingMode(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "v1"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=false"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	out := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "pulumi:pulumi:Stack") {
		t.Fatal("expected stack resource after checkpoint update")
	}

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  value: "v2"
`), 0o644)
	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  value: "v3"
`), 0o644)
	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=false"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	out = tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"destroy", "--yes", "--stack", "organization/test-project/dev",
	)
	if !strings.Contains(out, "1 deleted") {
		t.Fatalf("expected '1 deleted' in destroy, got: %s", out)
	}
}

// ===== Config & Secrets =====

func TestConfigSecretsRoundTrip(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
config:
  greeting:
    type: string
  secret-val:
    type: string
    secret: true
outputs:
  greeting: ${greeting}
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumi(t, dir, "config", "set", "greeting", "hello-world", "--stack", "organization/test-project/dev")
	tb.pulumi(t, dir, "config", "set", "--secret", "secret-val", "super-secret-123", "--stack", "organization/test-project/dev")

	out := tb.pulumi(t, dir, "config", "get", "greeting", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "hello-world") {
		t.Fatalf("expected 'hello-world' in config get, got: %s", out)
	}

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	exported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")
	if strings.Contains(exported, "super-secret-123") {
		t.Fatal("exported state should NOT contain plaintext secret")
	}
	if !strings.Contains(exported, "hello-world") {
		t.Fatalf("expected 'hello-world' in export outputs, got: %s", exported)
	}
}

func TestStackConfigEndpoint(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
config:
  mykey:
    type: string
outputs:
  value: ${mykey}
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")
	tb.pulumi(t, dir, "config", "set", "mykey", "myvalue", "--stack", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	resp := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/config", nil)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for config endpoint, got %d", resp.StatusCode)
	}

	resp2 := tb.httpDo(t, "POST", "/api/stacks/organization/test-project", map[string]string{"stackName": "empty"})
	resp2.Body.Close()
	resp2 = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/empty/config", nil)
	var emptyConfig map[string]any
	httpJSON(t, resp2, &emptyConfig)
	if emptyConfig == nil {
		t.Fatal("expected non-nil response for empty config")
	}
}

// ===== Cancel =====

func TestCancelUpdate(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "cancel-test"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	client := &http.Client{}
	createReq, _ := http.NewRequest("POST",
		tb.URL+"/api/stacks/organization/test-project/dev/update",
		strings.NewReader(`{"config":{},"metadata":{}}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "token test-token")
	resp, err := client.Do(createReq)
	if err != nil {
		t.Fatalf("failed to create update: %v", err)
	}
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&createResp)
	resp.Body.Close()

	startReq, _ := http.NewRequest("POST",
		tb.URL+"/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID,
		strings.NewReader(`{}`))
	startReq.Header.Set("Content-Type", "application/json")
	startReq.Header.Set("Authorization", "token test-token")
	resp, err = client.Do(startReq)
	if err != nil {
		t.Fatalf("failed to start update: %v", err)
	}
	resp.Body.Close()

	tb.pulumi(t, dir, "cancel", "--yes", "--stack", "organization/test-project/dev")

	out := tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)
	if !strings.Contains(out, "1 unchanged") {
		t.Fatalf("expected '1 unchanged' after cancel, got: %s", out)
	}
}

func TestCancelNoActiveUpdate(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	out := tb.pulumiExpectFailure(t, dir, "cancel", "--yes", "--stack", "organization/test-project/dev")
	if !strings.Contains(out, "no active update") && !strings.Contains(out, "never been updated") {
		t.Logf("cancel error output: %s", out)
	}
}

// ===== Concurrent Update Locking =====

func TestConcurrentUpdateLocking(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "lock-test"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	client := &http.Client{}
	createReq, _ := http.NewRequest("POST",
		tb.URL+"/api/stacks/organization/test-project/dev/update",
		strings.NewReader(`{"config":{},"metadata":{}}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "token test-token")
	resp, err := client.Do(createReq)
	if err != nil {
		t.Fatalf("failed to create update: %v", err)
	}
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&createResp)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	startReq, _ := http.NewRequest("POST",
		tb.URL+"/api/stacks/organization/test-project/dev/update/"+createResp.UpdateID,
		strings.NewReader(`{}`))
	startReq.Header.Set("Content-Type", "application/json")
	startReq.Header.Set("Authorization", "token test-token")
	resp, err = client.Do(startReq)
	if err != nil {
		t.Fatalf("failed to start update: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for start, got %d", resp.StatusCode)
	}

	_, err = tb.pulumiMayFail(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)
	if err == nil {
		t.Fatal("expected second update to fail due to lock, but it succeeded")
	}

	tb.pulumi(t, dir, "cancel", "--yes", "--stack", "organization/test-project/dev")

	out := tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)
	if !strings.Contains(out, "1 unchanged") {
		t.Fatalf("expected '1 unchanged' after cancel, got: %s", out)
	}
}

// ===== History =====

func TestStackHistory(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "v1"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	journalEnv := []string{"PULUMI_ENABLE_JOURNALING=true"}

	tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/dev")

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
outputs:
  value: "v2"
`), 0o644)
	tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/dev")

	tb.pulumiEnv(t, dir, journalEnv, "destroy", "--yes", "--stack", "organization/test-project/dev")

	out := tb.pulumi(t, dir, "stack", "history", "--stack", "organization/test-project/dev")

	if !strings.Contains(out, "update") && !strings.Contains(out, "Update") {
		t.Fatalf("expected 'update' in history output, got: %s", out)
	}
}

func TestUpdateRefreshDestroyKindsInHistory(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "v1"
`)

	journalEnv := []string{"PULUMI_ENABLE_JOURNALING=true"}

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/dev")
	tb.pulumiEnv(t, dir, journalEnv, "refresh", "--yes", "--stack", "organization/test-project/dev")
	tb.pulumiEnv(t, dir, journalEnv, "destroy", "--yes", "--stack", "organization/test-project/dev")

	resp := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/updates", nil)
	var histResp struct {
		Updates []struct {
			Kind    string `json:"kind"`
			Result  string `json:"result"`
			Version int    `json:"version"`
		} `json:"updates"`
	}
	httpJSON(t, resp, &histResp)

	if len(histResp.Updates) < 3 {
		t.Fatalf("expected at least 3 history entries, got %d", len(histResp.Updates))
	}

	kindSet := make(map[string]bool)
	for _, u := range histResp.Updates {
		kindSet[u.Kind] = true
		if u.Result != "succeeded" {
			t.Fatalf("entry kind=%s: expected result=succeeded, got %s", u.Kind, u.Result)
		}
	}

	for _, expected := range []string{"update", "refresh", "destroy"} {
		if !kindSet[expected] {
			t.Fatalf("expected kind=%s in history, found kinds: %v", expected, kindSet)
		}
	}
}

func TestHistoryPagination(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "v1"
`)

	journalEnv := []string{"PULUMI_ENABLE_JOURNALING=true"}

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	for i := 1; i <= 5; i++ {
		_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), fmt.Appendf(nil, `name: test-project
runtime: yaml
outputs:
  value: "v%d"
`, i), 0o644)
		tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/dev")
	}

	resp := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/updates?pageSize=2&page=0", nil)
	var page1 struct {
		Updates []struct {
			Version int `json:"version"`
		} `json:"updates"`
	}
	httpJSON(t, resp, &page1)

	if len(page1.Updates) != 2 {
		t.Fatalf("page 1: expected 2 entries, got %d", len(page1.Updates))
	}

	resp = tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/updates?pageSize=2&page=1", nil)
	var page2 struct {
		Updates []struct {
			Version int `json:"version"`
		} `json:"updates"`
	}
	httpJSON(t, resp, &page2)

	if len(page2.Updates) != 2 {
		t.Fatalf("page 2: expected 2 entries, got %d", len(page2.Updates))
	}

	for _, p1 := range page1.Updates {
		for _, p2 := range page2.Updates {
			if p1.Version == p2.Version {
				t.Fatalf("pages overlap: version %d appears on both pages", p1.Version)
			}
		}
	}
}

func TestHistoryManyEntriesGetByVersion(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "v1"
`)

	journalEnv := []string{"PULUMI_ENABLE_JOURNALING=true"}

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	for i := 1; i <= 12; i++ {
		_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), fmt.Appendf(nil, `name: test-project
runtime: yaml
outputs:
  value: "v%d"
`, i), 0o644)
		tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/test-project/dev")
	}

	// Default page size is 10, so request more.
	resp := tb.httpDo(t, "GET", "/api/stacks/organization/test-project/dev/updates?pageSize=50", nil)
	var histResp struct {
		Updates []struct {
			Version int `json:"version"`
		} `json:"updates"`
	}
	httpJSON(t, resp, &histResp)

	if len(histResp.Updates) < 12 {
		t.Fatalf("expected at least 12 history entries, got %d", len(histResp.Updates))
	}

	// Regression test: getUpdateByVersion for versions > 10 used to return 404.
	for _, u := range histResp.Updates {
		resp := tb.httpDo(t, "GET", fmt.Sprintf("/api/stacks/organization/test-project/dev/updates/%d", u.Version), nil)
		if resp.StatusCode != 200 {
			resp.Body.Close()
			t.Fatalf("getUpdateByVersion for version %d returned %d (expected 200)", u.Version, resp.StatusCode)
		}
		var versionResp struct {
			Version int    `json:"version"`
			Kind    string `json:"kind"`
		}
		httpJSON(t, resp, &versionResp)
		if versionResp.Version != u.Version {
			t.Fatalf("expected version %d, got %d", u.Version, versionResp.Version)
		}
	}
}

// ===== Large State =====

func TestLargeState(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	var outputs strings.Builder
	outputs.WriteString("name: large-project\nruntime: yaml\noutputs:\n")
	for i := range 50 {
		fmt.Fprintf(&outputs, "  key%03d: \"%s\"\n", i, strings.Repeat("x", 200))
	}

	dir := makeYAMLProject(t, outputs.String())

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/large-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/large-project/dev",
	)

	exported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/large-project/dev")

	if len(exported) < 5000 {
		t.Fatalf("expected large state (>5KB), got %d bytes", len(exported))
	}

	for i := range 50 {
		key := fmt.Sprintf("key%03d", i)
		if !strings.Contains(exported, key) {
			t.Fatalf("expected %s in export, not found", key)
		}
	}

	exportFile := filepath.Join(dir, "state.json")
	_ = os.WriteFile(exportFile, []byte(exported), 0o644)
	tb.pulumi(t, dir, "stack", "import", "--file", exportFile, "--stack", "organization/large-project/dev")

	reExported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/large-project/dev")
	if len(reExported) < 5000 {
		t.Fatalf("expected large state after import, got %d bytes", len(reExported))
	}
}

// ===== Failed Update =====

func TestFailedUpdateDoesNotCorruptState(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "before-failure"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/test-project/dev")

	tb.pulumiEnv(t, dir,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	goodState := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: test-project
runtime: yaml
resources:
  bucket:
    type: pulumi:pulumi:StackReference
    properties:
      name: "nonexistent/stack/reference"
`), 0o644)

	tb.pulumiExpectFailure(t, dir,
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	afterState := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/test-project/dev")

	var good, after map[string]any
	if err := json.Unmarshal([]byte(goodState), &good); err != nil {
		t.Fatalf("failed to unmarshal goodState: %v", err)
	}
	if err := json.Unmarshal([]byte(afterState), &after); err != nil {
		t.Fatalf("failed to unmarshal afterState: %v", err)
	}

	goodRes, _ := json.Marshal(good["deployment"].(map[string]any)["resources"])
	afterRes, _ := json.Marshal(after["deployment"].(map[string]any)["resources"])

	if string(goodRes) != string(afterRes) {
		t.Fatal("state was corrupted after failed update")
	}
}

// ===== Full Lifecycle =====

func TestFullLifecycleWithJournaling(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: lifecycle-test
runtime: yaml
outputs:
  phase: "create"
`)

	journalEnv := []string{"PULUMI_ENABLE_JOURNALING=true"}

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/lifecycle-test/dev")

	out := tb.pulumiEnv(t, dir, journalEnv, "preview", "--stack", "organization/lifecycle-test/dev")
	if !strings.Contains(out, "create") {
		t.Fatalf("preview should show create, got: %s", out)
	}

	out = tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/lifecycle-test/dev")
	if !strings.Contains(out, "1 created") {
		t.Fatalf("first up should create 1 resource, got: %s", out)
	}

	tb.pulumiEnv(t, dir, journalEnv, "preview", "--stack", "organization/lifecycle-test/dev")

	out = tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/lifecycle-test/dev")
	if !strings.Contains(out, "1 unchanged") {
		t.Fatalf("no-op up should show 1 unchanged, got: %s", out)
	}

	_ = os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(`name: lifecycle-test
runtime: yaml
outputs:
  phase: "update"
  extra: "value"
`), 0o644)

	out = tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/lifecycle-test/dev")
	if !strings.Contains(out, "1 unchanged") {
		t.Fatalf("update should show 1 unchanged (stack resource), got: %s", out)
	}

	out = tb.pulumiEnv(t, dir, journalEnv, "refresh", "--yes", "--stack", "organization/lifecycle-test/dev")
	if !strings.Contains(out, "unchanged") {
		t.Fatalf("refresh should show unchanged, got: %s", out)
	}

	exported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/lifecycle-test/dev")
	exportFile := filepath.Join(dir, "state.json")
	_ = os.WriteFile(exportFile, []byte(exported), 0o644)
	tb.pulumi(t, dir, "stack", "import", "--file", exportFile, "--stack", "organization/lifecycle-test/dev")

	out = tb.pulumiEnv(t, dir, journalEnv, "up", "--yes", "--stack", "organization/lifecycle-test/dev")
	if !strings.Contains(out, "unchanged") {
		t.Fatalf("up after import should be no-op, got: %s", out)
	}

	out = tb.pulumiEnv(t, dir, journalEnv, "destroy", "--yes", "--stack", "organization/lifecycle-test/dev")
	if !strings.Contains(out, "1 deleted") {
		t.Fatalf("destroy should delete 1 resource, got: %s", out)
	}

	exported = tb.pulumi(t, dir, "stack", "export", "--stack", "organization/lifecycle-test/dev")
	var state map[string]any
	if err := json.Unmarshal([]byte(exported), &state); err != nil {
		t.Fatalf("failed to unmarshal exported state: %v", err)
	}
	dep := state["deployment"].(map[string]any)
	if res, ok := dep["resources"]; ok && res != nil {
		resSlice, ok := res.([]any)
		if ok && len(resSlice) > 0 {
			t.Fatalf("expected empty resources after destroy, got: %v", res)
		}
	}

	tb.pulumi(t, dir, "stack", "rm", "--yes", "-s", "organization/lifecycle-test/dev")

	out = tb.pulumi(t, dir, "stack", "ls")
	if strings.Contains(out, "dev") {
		t.Fatalf("expected stack to be removed from list, got: %s", out)
	}
}

// ===== Multiple Projects =====

func TestMultipleProjectsInOrg(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir1 := makeYAMLProject(t, `name: project-alpha
runtime: yaml
outputs:
  from: "alpha"
`)
	dir2 := makeYAMLProject(t, `name: project-beta
runtime: yaml
outputs:
  from: "beta"
`)

	tb.pulumi(t, dir1, "login", tb.URL)
	tb.pulumi(t, dir2, "login", tb.URL)

	tb.pulumi(t, dir1, "stack", "init", "organization/project-alpha/dev")
	tb.pulumi(t, dir2, "stack", "init", "organization/project-beta/dev")
	tb.pulumi(t, dir2, "stack", "init", "organization/project-beta/prod")

	tb.pulumiEnv(t, dir1,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/project-alpha/dev",
	)
	tb.pulumiEnv(t, dir2,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/project-beta/dev",
	)

	resp := tb.httpDo(t, "GET", "/api/stacks/organization", nil)
	var listResp struct {
		Stacks []struct {
			OrgName     string `json:"orgName"`
			ProjectName string `json:"projectName"`
			StackName   string `json:"stackName"`
		} `json:"stacks"`
	}
	httpJSON(t, resp, &listResp)

	if len(listResp.Stacks) < 3 {
		t.Fatalf("expected at least 3 stacks across projects, got %d", len(listResp.Stacks))
	}

	projects := make(map[string]bool)
	for _, s := range listResp.Stacks {
		projects[s.ProjectName] = true
	}
	if !projects["project-alpha"] || !projects["project-beta"] {
		t.Fatalf("expected both projects in list, got: %v", projects)
	}

	exportAlpha := tb.pulumi(t, dir1, "stack", "export", "--stack", "organization/project-alpha/dev")
	exportBeta := tb.pulumi(t, dir2, "stack", "export", "--stack", "organization/project-beta/dev")

	if !strings.Contains(exportAlpha, "project-alpha") {
		t.Fatal("alpha export should reference project-alpha")
	}
	if !strings.Contains(exportBeta, "project-beta") {
		t.Fatal("beta export should reference project-beta")
	}
}

func TestMultipleStacksResourceCounts(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir1 := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "from-dev"
`)
	dir2 := makeYAMLProject(t, `name: test-project
runtime: yaml
outputs:
  value: "from-staging"
`)

	tb.pulumi(t, dir1, "login", tb.URL)
	tb.pulumi(t, dir2, "login", tb.URL)
	tb.pulumi(t, dir1, "stack", "init", "organization/test-project/dev")
	tb.pulumi(t, dir2, "stack", "init", "organization/test-project/staging")

	// Deploy only dev.
	tb.pulumiEnv(t, dir1,
		[]string{"PULUMI_ENABLE_JOURNALING=true"},
		"up", "--yes", "--stack", "organization/test-project/dev",
	)

	resp := tb.httpDo(t, "GET", "/api/stacks/organization", nil)
	var listResp struct {
		Stacks []struct {
			StackName     string `json:"stackName"`
			ResourceCount int    `json:"resourceCount"`
		} `json:"stacks"`
	}
	httpJSON(t, resp, &listResp)

	for _, s := range listResp.Stacks {
		switch s.StackName {
		case "dev":
			if s.ResourceCount != 1 {
				t.Fatalf("dev: expected resourceCount=1, got %d", s.ResourceCount)
			}
		case "staging":
			if s.ResourceCount != 0 {
				t.Fatalf("staging: expected resourceCount=0, got %d", s.ResourceCount)
			}
		}
	}
}
