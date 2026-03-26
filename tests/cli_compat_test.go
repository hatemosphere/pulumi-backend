package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Smoke/compat CLI tests.
// Keep these intentionally small and version-agnostic so they can run across a
// Pulumi CLI compatibility matrix without accumulating workflow-specific noise.

func TestCLICompat_CoreWorkflow(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: compat-project
runtime: yaml
config:
  message:
    type: string
outputs:
  value: ${message}
`)

	t.Logf("pulumi version: %s", pulumiVersion(t))

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/compat-project/dev")
	tb.pulumi(t, dir, "config", "set", "message", "compat-v1", "--stack", "organization/compat-project/dev")

	out := tb.pulumi(t, dir, "up", "--yes", "--stack", "organization/compat-project/dev")
	if !strings.Contains(out, "1 changed") && !strings.Contains(out, "1 created") {
		t.Fatalf("expected update output, got: %s", out)
	}

	output := tb.pulumi(t, dir, "stack", "output", "value", "--stack", "organization/compat-project/dev")
	if !strings.Contains(output, "compat-v1") {
		t.Fatalf("expected stack output to contain compat-v1, got: %s", output)
	}

	exported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/compat-project/dev")
	if !strings.Contains(exported, "pulumi:pulumi:Stack") {
		t.Fatalf("expected stack export to contain stack resource, got: %s", exported)
	}

	tb.pulumi(t, dir, "stack", "rename", "dev-renamed", "--stack", "organization/compat-project/dev")
	lsOut := tb.pulumi(t, dir, "stack", "ls")
	if !strings.Contains(lsOut, "dev-renamed") {
		t.Fatalf("expected renamed stack in stack ls, got: %s", lsOut)
	}

	destroy := tb.pulumi(t, dir, "destroy", "--yes", "--stack", "organization/compat-project/dev-renamed")
	if !strings.Contains(destroy, "deleted") && !strings.Contains(destroy, "unchanged") {
		t.Fatalf("expected destroy output, got: %s", destroy)
	}
}

func TestCLICompat_ImportExportRoundTrip(t *testing.T) {
	requireCLI(t)
	tb := startBackend(t)

	dir := makeYAMLProject(t, `name: import-compat
runtime: yaml
outputs:
  value: "import-compat"
`)

	tb.pulumi(t, dir, "login", tb.URL)
	tb.pulumi(t, dir, "stack", "init", "organization/import-compat/dev")

	exportPath := filepath.Join(t.TempDir(), "state.json")
	tb.pulumi(t, dir, "up", "--yes", "--stack", "organization/import-compat/dev")
	exported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/import-compat/dev")
	if err := os.WriteFile(exportPath, []byte(exported), 0o644); err != nil {
		t.Fatalf("write export: %v", err)
	}

	tb.pulumi(t, dir, "stack", "import", "--file", exportPath, "--force", "--stack", "organization/import-compat/dev")

	reexported := tb.pulumi(t, dir, "stack", "export", "--stack", "organization/import-compat/dev")
	if !strings.Contains(reexported, "pulumi:pulumi:Stack") {
		t.Fatalf("expected imported stack export to contain stack resource, got: %s", reexported)
	}
}
