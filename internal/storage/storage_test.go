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

func TestStackLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewSQLiteStore(dbPath, SQLiteStoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()

	// 1. Create stack
	err = store.CreateStack(ctx, &Stack{
		OrgName:     "org1",
		ProjectName: "proj1",
		StackName:   "stack1",
		Tags:        map[string]string{"env": "dev"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Get stack
	st, err := store.GetStack(ctx, "org1", "proj1", "stack1")
	if err != nil {
		t.Fatal(err)
	}
	if st.Tags["env"] != "dev" {
		t.Fatalf("expected tag dev, got %v", st.Tags["env"])
	}

	// 3. Update tags
	err = store.UpdateStackTags(ctx, "org1", "proj1", "stack1", map[string]string{"env": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	st, _ = store.GetStack(ctx, "org1", "proj1", "stack1")
	if st.Tags["env"] != "prod" {
		t.Fatalf("expected tag prod, got %v", st.Tags["env"])
	}

	// 4. List stacks
	stacks, _, err := store.ListStacks(ctx, "org1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(stacks) != 1 {
		t.Fatalf("expected 1 stack, got %d", len(stacks))
	}

	// 5. Rename stack
	err = store.RenameStack(ctx, "org1", "proj1", "stack1", "proj2", "stack2")
	if err != nil {
		t.Fatal(err)
	}

	// Ensure old is gone
	st, err = store.GetStack(ctx, "org1", "proj1", "stack1")
	if err != nil {
		t.Fatal(err)
	}
	if st != nil {
		t.Fatal("expected old stack to be gone")
	}

	// Ensure new is present
	st, err = store.GetStack(ctx, "org1", "proj2", "stack2")
	if err != nil {
		t.Fatal(err)
	}
	if st == nil {
		t.Fatal("expected new stack to be present")
	}

	// 6. Delete stack
	err = store.DeleteStack(ctx, "org1", "proj2", "stack2")
	if err != nil {
		t.Fatal(err)
	}
	st, _ = store.GetStack(ctx, "org1", "proj2", "stack2")
	if st != nil {
		t.Fatal("expected stack to be deleted")
	}
}

func TestUpdateLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(tmpDir, "test.db"), SQLiteStoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	store.CreateStack(ctx, &Stack{OrgName: "org", ProjectName: "proj", StackName: "stack"}) //nolint:errcheck // test setup

	u := &Update{
		ID:          "upd1",
		OrgName:     "org",
		ProjectName: "proj",
		StackName:   "stack",
		Kind:        "update",
		Config:      []byte("{}"),
	}

	// 1. Create Update
	if err := store.CreateUpdate(ctx, u); err != nil {
		t.Fatal(err)
	}

	// 2. Get Active Update
	active, err := store.GetActiveUpdate(ctx, "org", "proj", "stack")
	if err != nil {
		t.Fatal(err)
	}
	if active != nil {
		t.Fatal("expected no active update initially since it is not-started")
	}

	// 3. Start Update
	expires := time.Now().Add(time.Hour)
	if err := store.StartUpdate(ctx, "upd1", 1, "token123", expires, 1); err != nil {
		t.Fatal(err)
	}

	active, err = store.GetActiveUpdate(ctx, "org", "proj", "stack")
	if err != nil || active == nil {
		t.Fatalf("expected active update, got %v", active)
	}
	if active.Status != "in-progress" {
		t.Fatalf("expected status form active: %s", active.Status)
	}

	// 4. Renew Lease
	newExpires := time.Now().Add(2 * time.Hour)
	if err := store.RenewLease(ctx, "upd1", "token456", newExpires); err != nil {
		t.Fatal(err)
	}
	upd, _ := store.GetUpdate(ctx, "upd1")
	if upd.Token != "token456" || upd.TokenExpiresAt.Unix() != newExpires.Unix() {
		t.Fatal("lease not renewed properly")
	}

	// 5. Complete Update
	if err := store.CompleteUpdate(ctx, "upd1", "succeeded", []byte(`{"res":"ok"}`)); err != nil {
		t.Fatal(err)
	}

	upd, _ = store.GetUpdate(ctx, "upd1")
	if upd.Status != "succeeded" {
		t.Fatal("expected succeeded")
	}

	active, _ = store.GetActiveUpdate(ctx, "org", "proj", "stack")
	if active != nil {
		t.Fatal("expected no active update after completion")
	}
}

func TestTokenManagement(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(tmpDir, "test.db"), SQLiteStoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	tok := &Token{
		TokenHash:   "hash1",
		UserName:    "user1",
		Description: "desc1",
		ExpiresAt:   &exp,
	}

	// Create
	if err := store.CreateToken(ctx, tok); err != nil {
		t.Fatal(err)
	}

	// Get
	fetched, err := store.GetToken(ctx, "hash1")
	if err != nil || fetched == nil {
		t.Fatal("expected token")
	}
	if fetched.UserName != "user1" {
		t.Fatal("username mismatch")
	}

	// Touch
	if err := store.TouchToken(ctx, "hash1"); err != nil {
		t.Fatal(err)
	}
	fetched, _ = store.GetToken(ctx, "hash1")
	if fetched.LastUsedAt == nil {
		t.Fatal("expected last used at to be set")
	}

	// List
	tokens, err := store.ListTokensByUser(ctx, "user1")
	if err != nil || len(tokens) != 1 {
		t.Fatal("expected 1 token")
	}

	// Delete by hash
	if err := store.DeleteToken(ctx, "hash1"); err != nil {
		t.Fatal(err)
	}
	fetched, _ = store.GetToken(ctx, "hash1")
	if fetched != nil {
		t.Fatal("expected token to be deleted")
	}

	// Test Delete by user
	store.CreateToken(ctx, &Token{TokenHash: "hash2", UserName: "user2"}) //nolint:errcheck // test setup
	store.CreateToken(ctx, &Token{TokenHash: "hash3", UserName: "user2"}) //nolint:errcheck // test setup
	deletedCount, err := store.DeleteTokensByUser(ctx, "user2")
	if err != nil || deletedCount != 2 {
		t.Fatalf("expected to delete 2 tokens, got %d", deletedCount)
	}
}

func TestJournalAndEngineEvents(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(tmpDir, "test.db"), SQLiteStoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()

	store.CreateStack(ctx, &Stack{OrgName: "org", ProjectName: "proj", StackName: "stack"})                               //nolint:errcheck // test setup
	store.CreateUpdate(ctx, &Update{ID: "upd1", OrgName: "org", ProjectName: "proj", StackName: "stack", Kind: "update"}) //nolint:errcheck // test setup //nolint:errcheck // test setup

	err = store.SaveJournalEntries(ctx, []JournalEntry{
		{UpdateID: "upd1", SequenceID: 1, Entry: []byte("entry1")},
		{UpdateID: "upd1", SequenceID: 2, Entry: []byte("entry2")},
	})
	if err != nil {
		t.Fatal(err)
	}

	maxSeq, err := store.GetMaxJournalSequence(ctx, "upd1")
	if err != nil || maxSeq != 2 {
		t.Fatalf("expected max sequence 2, got %d", maxSeq)
	}

	err = store.SaveEngineEvents(ctx, []EngineEvent{
		{UpdateID: "upd1", Sequence: 1, Event: []byte("ev1")},
	})
	if err != nil {
		t.Fatal(err)
	}

	events, err := store.GetEngineEvents(ctx, "upd1", 0, 10)
	if err != nil || len(events) != 1 {
		t.Fatal("expected 1 event")
	}
}
