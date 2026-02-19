package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/hatemosphere/pulumi-backend/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockStore for testing Manager
type MockStore struct {
	mock.Mock
	storage.Store // Embed interface to skip implementing everything
}

func (m *MockStore) GetUpdate(ctx context.Context, id string) (*storage.Update, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Update), args.Error(1)
}

func (m *MockStore) GetCurrentState(ctx context.Context, org, project, stack string) (*storage.StackState, error) {
	args := m.Called(ctx, org, project, stack)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.StackState), args.Error(1)
}

func (m *MockStore) GetStateVersionRaw(ctx context.Context, org, project, stack string, version int) ([]byte, bool, error) {
	args := m.Called(ctx, org, project, stack, version)
	return args.Get(0).([]byte), args.Bool(1), args.Error(2)
}

func (m *MockStore) SaveState(ctx context.Context, state *storage.StackState) error {
	args := m.Called(ctx, state)
	return args.Error(0)
}

func TestSaveCheckpointDelta(t *testing.T) {
	store := new(MockStore)
	mgr, err := NewManager(store, nil)
	require.NoError(t, err)

	ctx := context.Background()
	updateID := "update-1"

	// Initial state: {"foo":"bar"}
	initialJSON := `{"foo":"bar"}`
	// initialHash := sha256.Sum256([]byte(initialJSON))
	// initialHashStr := hex.EncodeToString(initialHash[:])

	// Mock GetUpdate
	store.On("GetUpdate", ctx, updateID).Return(&storage.Update{
		ID:          updateID,
		OrgName:     "org",
		ProjectName: "proj",
		StackName:   "stack",
		Version:     1,
	}, nil)

	// Mock GetCurrentState (Sequence 0 -> Version 1)
	// Note: GetCurrentState returns *storage.StackState, which has Deployment []byte
	store.On("GetCurrentState", ctx, "org", "proj", "stack").Return(&storage.StackState{
		Version:    1,
		Deployment: []byte(initialJSON),
	}, nil)

	// New state: {"foo":"baz"}
	// Delta from bar -> baz
	// We'll use a dummy delta since applyDelta logic is tested elsewhere,
	// but Manager integration needs to be verified.

	baseText := "abc"
	// baseHash := sha256.Sum256([]byte(baseText))
	// baseHashStr := hex.EncodeToString(baseHash[:])

	// newText := "abcd"
	// Delta: Append "d" at offset 3.
	// applyDelta expects a JSON array of TextEdit.
	delta := `[{"Span":{"start":{"offset":3,"line":1,"column":4},"end":{"offset":3,"line":1,"column":4}},"NewText":"d"}]`

	// Calculate expected hash of the RESULT (abc + "d" = "abcd")
	expectedText := "abcd"
	expectedHash := sha256.Sum256([]byte(expectedText))
	expectedHashStr := hex.EncodeToString(expectedHash[:])

	// Mock again with real text
	store.ExpectedCalls = nil // Clear previous
	store.On("GetUpdate", ctx, updateID).Return(&storage.Update{
		ID:          updateID,
		OrgName:     "org",
		ProjectName: "proj",
		StackName:   "stack",
		Version:     1,
	}, nil)
	store.On("GetCurrentState", ctx, "org", "proj", "stack").Return(&storage.StackState{
		Version:    1,
		Deployment: []byte(baseText),
	}, nil)

	// Expect SaveState with new content
	store.On("SaveState", ctx, mock.MatchedBy(func(s *storage.StackState) bool {
		return s.Version == 1 && s.OrgName == "org"
	})).Return(nil)

	err = mgr.SaveCheckpointDelta(ctx, updateID, expectedHashStr, delta, 1)
	require.NoError(t, err)

	store.AssertExpectations(t)
}

func TestSaveCheckpointDelta_HashMismatch(t *testing.T) {
	store := new(MockStore)
	mgr, _ := NewManager(store, nil)
	ctx := context.Background()

	// Mock GetUpdate
	store.On("GetUpdate", ctx, "up-1").Return(&storage.Update{
		OrgName: "org", ProjectName: "proj", StackName: "stack", Version: 1,
	}, nil)

	// Mock GetState containing "abc"
	store.On("GetCurrentState", ctx, "org", "proj", "stack").Return(&storage.StackState{
		Version:    1,
		Deployment: []byte("abc"),
	}, nil)

	// Client sends hash for "xyz" -> Mismatch!
	// But we must provide a VALID delta so applyDelta succeeds.
	// Empty delta -> result is "abc". Hash of "abc" != Hash of "xyz".
	validDelta := `[]`
	wrongHash := sha256.Sum256([]byte("xyz"))
	wrongHashStr := hex.EncodeToString(wrongHash[:])

	err := mgr.SaveCheckpointDelta(ctx, "up-1", wrongHashStr, validDelta, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hash mismatch after applying delta")
}
