package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// MockStore is a testify mock for storage.Store, implementing only the methods needed by tests.
type MockStore struct {
	mock.Mock
	storage.Store
}

func (m *MockStore) GetUpdate(ctx context.Context, id string) (*storage.Update, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Update), args.Error(1)
}

func (m *MockStore) ProjectExists(ctx context.Context, org, proj string) (bool, error) {
	args := m.Called(ctx, org, proj)
	return args.Bool(0), args.Error(1)
}

func (m *MockStore) StartUpdate(ctx context.Context, id string, version int, token string, expires time.Time, journalVer int) error {
	args := m.Called(ctx, id, version, token, expires, journalVer)
	return args.Error(0)
}

func (m *MockStore) GetActiveUpdate(ctx context.Context, org, proj, stack string) (*storage.Update, error) {
	args := m.Called(ctx, org, proj, stack)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Update), args.Error(1)
}

func (m *MockStore) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockStore) RenewLease(ctx context.Context, id string, token string, expiry time.Time) error {
	args := m.Called(ctx, id, token, expiry)
	return args.Error(0)
}

// newSQLiteTestServer creates a Server backed by a real SQLite database in a temp dir.
func newSQLiteTestServer(t *testing.T) *Server {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := storage.NewSQLiteStore(dbPath, storage.SQLiteStoreConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	provider, err := engine.NewLocalSecretsProvider(make([]byte, 32))
	require.NoError(t, err)

	mgr, err := engine.NewManager(store, engine.NewSecretsEngine(provider))
	require.NoError(t, err)
	t.Cleanup(mgr.Shutdown)

	return NewServer(mgr, "organization", "test-user")
}

// testAPI wraps a Server router for compact HTTP handler tests.
type testAPI struct {
	t      *testing.T
	router http.Handler
}

func newTestAPI(t *testing.T) *testAPI {
	t.Helper()
	srv := newSQLiteTestServer(t)
	return &testAPI{t: t, router: srv.Router()}
}

// do issues an HTTP request through the router and returns the recorder.
func (a *testAPI) do(method, path string, body any) *httptest.ResponseRecorder {
	a.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(a.t, err)
		reader = bytes.NewReader(data)
	}
	var req *http.Request
	if reader != nil {
		req = httptest.NewRequest(method, path, reader)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("Authorization", "token test-token")
	rec := httptest.NewRecorder()
	a.router.ServeHTTP(rec, req)
	return rec
}

// jsonBody unmarshals the recorder body into v.
func (a *testAPI) jsonBody(rec *httptest.ResponseRecorder, v any) {
	a.t.Helper()
	require.NoError(a.t, json.Unmarshal(rec.Body.Bytes(), v))
}
