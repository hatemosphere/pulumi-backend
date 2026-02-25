package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

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

func (m *MockStore) RenewLease(ctx context.Context, id string, token string, expiry time.Time) error {
	args := m.Called(ctx, id, token, expiry)
	return args.Error(0)
}

func TestGetUpdateStatusAPI(t *testing.T) {
	store := new(MockStore)
	mgr, _ := engine.NewManager(store, nil)
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
