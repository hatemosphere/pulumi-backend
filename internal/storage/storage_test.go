package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestCompression(t *testing.T) {
	// Setup temporary DB.
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewSQLiteStore(dbPath, SQLiteStoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()

	// Create prerequisite objects.
	err = store.CreateStack(ctx, &Stack{
		OrgName:     "org",
		ProjectName: "proj",
		StackName:   "stack",
		Tags:        map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Test SaveState (should compress).
	data := []byte(`{"foo":"bar"}`)
	state := &StackState{
		OrgName:     "org",
		ProjectName: "proj",
		StackName:   "stack",
		Version:     1,
		Deployment:  data,
		Hash:        "hash",
	}
	if err := store.SaveState(ctx, state); err != nil {
		t.Fatal(err)
	}

	// Verify it's compressed in the DB.
	var rawDeployment []byte
	err = store.db.QueryRow(`SELECT deployment FROM stack_state WHERE version=1`).Scan(&rawDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if !isGzipped(rawDeployment) {
		t.Fatal("expected data to be gzipped in DB")
	}

	// 2. Test GetStateVersion (should decompress).
	loaded, err := store.GetStateVersion(ctx, "org", "proj", "stack", 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.Deployment) != string(data) {
		t.Fatalf("expected output %s, got %s", data, loaded.Deployment)
	}

	// 3. Test Legacy Compatibility (insert uncompressed, read back).
	legacyData := []byte(`{"legacy":"true"}`)
	_, err = store.db.Exec(`INSERT INTO stack_state (org_name, project_name, stack_name, version, deployment, deployment_hash, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"org", "proj", "stack", 2, legacyData, "legacy-hash", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}

	legacyLoaded, err := store.GetStateVersion(ctx, "org", "proj", "stack", 2)
	if err != nil {
		t.Fatal(err)
	}
	if string(legacyLoaded.Deployment) != string(legacyData) {
		t.Fatalf("expected legacy output %s, got %s", legacyData, legacyLoaded.Deployment)
	}
}

func isGzipped(data []byte) bool {
	return len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b
}
