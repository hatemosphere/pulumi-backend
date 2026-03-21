package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

func newTestServer(t *testing.T) (*Server, *MockStore) {
	t.Helper()

	store := new(MockStore)
	mgr, err := engine.NewManager(store, nil)
	require.NoError(t, err)
	t.Cleanup(mgr.Shutdown)

	return NewServer(mgr, "organization", "test-user"), store
}

func TestAuthMiddlewareRejectsMissingHeader(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/user", nil)
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "missing Authorization header")
}

func TestAuthMiddlewareRejectsInvalidHeaderFormat(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/user", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid Authorization header format")
}

func TestAuthMiddlewareRejectsUpdateTokenOnNonUpdateRoute(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/user", nil)
	req.Header.Set("Authorization", "update-token some-token")
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "update-token requires an update-scoped endpoint")
}

func TestSingleTenantAnyTokenUsesConfiguredAdminIdentity(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/user", nil)
	req.Header.Set("Authorization", "token anything-goes")
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		GitHubLogin string `json:"githubLogin"`
		SiteAdmin   bool   `json:"siteAdmin"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "test-user", body.GitHubLogin)
	assert.True(t, body.SiteAdmin)
}

func TestAuthMiddlewareAcceptsValidUpdateTokenOnUpdateRoute(t *testing.T) {
	srv, store := newTestServer(t)
	store.On("GetUpdate", mock.Anything, "up-1").Return(&storage.Update{
		ID:             "up-1",
		Token:          "valid-token",
		TokenExpiresAt: time.Now().Add(time.Minute),
	}, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/stacks/org/proj/stack/update/up-1", nil)
	req.Header.Set("Authorization", "update-token valid-token")
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"status"`)
	store.AssertExpectations(t)
}

func TestReadinessHandlerUsesStorePing(t *testing.T) {
	tests := []struct {
		name       string
		pingErr    error
		statusCode int
	}{
		{name: "ready", statusCode: http.StatusOK},
		{name: "not ready", pingErr: errors.New("db unavailable"), statusCode: http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, store := newTestServer(t)
			store.On("Ping", mock.Anything).Return(tt.pingErr)
			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			rec := httptest.NewRecorder()

			srv.Router().ServeHTTP(rec, req)

			assert.Equal(t, tt.statusCode, rec.Code)
			store.AssertExpectations(t)
		})
	}
}

func TestHealthCheckReturnsJSON(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestWrongMethodReturnsError(t *testing.T) {
	api := newTestAPI(t)
	rec := api.do(http.MethodPut, "/api/capabilities", nil)
	assert.NotEqual(t, http.StatusOK, rec.Code)
}

func TestPublicHealthAndCapabilitiesHandlers(t *testing.T) {
	srv, _ := newTestServer(t)

	t.Run("root health", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		srv.Router().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
	})

	t.Run("liveness", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()

		srv.Router().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
	})

	t.Run("capabilities", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/capabilities", nil)
		req.Header.Set("Authorization", "token test-token")
		rec := httptest.NewRecorder()

		srv.Router().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Capabilities []Capability `json:"capabilities"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

		assert.Contains(t, body.Capabilities, Capability{
			Capability: "batch-encrypt",
		})

		foundDelta := false
		for _, capability := range body.Capabilities {
			if capability.Capability == "delta-checkpoint-uploads-v2" {
				foundDelta = true
				assert.Equal(t, 2, capability.Version)
			}
		}
		assert.True(t, foundDelta)
	})

	t.Run("cli version", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/cli/version", nil)
		req.Header.Set("Authorization", "token test-token")
		rec := httptest.NewRecorder()

		srv.Router().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			LatestVersion        string `json:"latestVersion"`
			OldestWithoutWarning string `json:"oldestWithoutWarning"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.NotEmpty(t, body.LatestVersion)
		assert.NotEmpty(t, body.OldestWithoutWarning)
	})
}
