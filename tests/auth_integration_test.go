package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// startBackendWithOpts starts a backend server with custom ServerOptions.
func startBackendWithOpts(t *testing.T, opts ...api.ServerOption) *testBackend {
	t.Helper()

	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "test.db")

	store, err := storage.NewSQLiteStore(dbPath, storage.SQLiteStoreConfig{})
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	masterKey := make([]byte, 32)
	provider, err := engine.NewLocalSecretsProvider(masterKey)
	if err != nil {
		t.Fatalf("failed to create secrets provider: %v", err)
	}
	secrets := engine.NewSecretsEngine(provider)

	mgr, err := engine.NewManager(store, secrets, engine.ManagerConfig{})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	srv := api.NewServer(mgr, "organization", "test-user", opts...)
	router := srv.Router()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	httpServer := &http.Server{Handler: router, ReadHeaderTimeout: 10 * time.Second} //nolint:gosec // test server
	go func() { _ = httpServer.Serve(listener) }()

	tb := &testBackend{
		URL:     fmt.Sprintf("http://127.0.0.1:%d", port),
		server:  httpServer,
		store:   store,
		dataDir: dataDir,
	}

	t.Cleanup(func() {
		_ = httpServer.Shutdown(context.Background())
		store.Close()
	})

	for i := 0; i < 50; i++ {
		resp, err := http.Get(tb.URL + "/")
		if err == nil {
			resp.Body.Close()
			return tb
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("backend server failed to start")
	return nil
}

const jwtTestSecret = "integration-test-secret-key-1234567890"

// signTestJWT creates a JWT for integration testing.
func signTestJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = jwt.NewNumericDate(time.Now().Add(time.Hour))
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString([]byte(jwtTestSecret))
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return s
}

// httpDoWithToken makes an HTTP request with a custom auth token.
func (tb *testBackend) httpDoWithToken(t *testing.T, method, path, token string, body any) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, tb.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "token "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

func newJWTBackend(t *testing.T, rbacConfig *auth.RBACConfig) *testBackend {
	t.Helper()
	jwtAuth, err := auth.NewJWTAuthenticator(auth.JWTConfig{
		SigningKey: jwtTestSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := []api.ServerOption{
		api.WithAuthMode("jwt"),
		api.WithJWTAuth(jwtAuth),
	}
	if rbacConfig != nil {
		opts = append(opts, api.WithRBAC(auth.NewRBACResolver(rbacConfig)))
	}
	return startBackendWithOpts(t, opts...)
}

// createTestStack creates a stack via the API for permission testing.
func createTestStack(t *testing.T, tb *testBackend, token, org, project, stack string) {
	t.Helper()
	resp := tb.httpDoWithToken(t, "POST",
		fmt.Sprintf("/api/stacks/%s/%s", org, project),
		token, map[string]string{"stackName": stack})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create stack: status %d, body: %s", resp.StatusCode, body)
	}
}

// --- JWT Integration Tests ---

func TestJWT_ValidToken_200(t *testing.T) {
	tb := newJWTBackend(t, nil) // no RBAC = all users admin

	tok := signTestJWT(t, jwt.MapClaims{"sub": "alice@example.com"})
	resp := tb.httpDoWithToken(t, "GET", "/api/user", tok, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
}

func TestJWT_ExpiredToken_401(t *testing.T) {
	tb := newJWTBackend(t, nil)

	tok := signTestJWT(t, jwt.MapClaims{
		"sub": "alice@example.com",
		"exp": jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	})
	resp := tb.httpDoWithToken(t, "GET", "/api/user", tok, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestJWT_BadSignature_401(t *testing.T) {
	tb := newJWTBackend(t, nil)

	// Sign with a different key.
	claims := jwt.MapClaims{
		"sub": "alice@example.com",
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok, _ := token.SignedString([]byte("wrong-secret-key"))

	resp := tb.httpDoWithToken(t, "GET", "/api/user", tok, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestJWT_RBAC_ReadOnlyUser(t *testing.T) {
	rbacConfig := &auth.RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []auth.GroupRole{
			{Group: "readers", Permission: "read"},
			{Group: "admins", Permission: "admin"},
		},
	}
	tb := newJWTBackend(t, rbacConfig)

	// Create stack with an admin token first.
	adminTok := signTestJWT(t, jwt.MapClaims{
		"sub":    "admin@example.com",
		"groups": []any{"admins"},
	})
	createTestStack(t, tb, adminTok, "organization", "test-project", "dev")

	// Now test read-only user.
	readerTok := signTestJWT(t, jwt.MapClaims{
		"sub":    "reader@example.com",
		"groups": []any{"readers"},
	})

	// GET should succeed (read permission).
	resp := tb.httpDoWithToken(t, "GET",
		"/api/stacks/organization/test-project/dev",
		readerTok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d", resp.StatusCode)
	}

	// DELETE should be forbidden (requires admin).
	resp = tb.httpDoWithToken(t, "DELETE",
		"/api/stacks/organization/test-project/dev",
		readerTok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("DELETE: expected 403, got %d", resp.StatusCode)
	}
}

func TestJWT_RBAC_WriteUser(t *testing.T) {
	rbacConfig := &auth.RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []auth.GroupRole{
			{Group: "writers", Permission: "write"},
			{Group: "admins", Permission: "admin"},
		},
	}
	tb := newJWTBackend(t, rbacConfig)

	// Create stack with admin.
	adminTok := signTestJWT(t, jwt.MapClaims{
		"sub":    "admin@example.com",
		"groups": []any{"admins"},
	})
	createTestStack(t, tb, adminTok, "organization", "test-project", "dev")

	writerTok := signTestJWT(t, jwt.MapClaims{
		"sub":    "writer@example.com",
		"groups": []any{"writers"},
	})

	// GET should succeed.
	resp := tb.httpDoWithToken(t, "GET",
		"/api/stacks/organization/test-project/dev",
		writerTok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d", resp.StatusCode)
	}

	// DELETE should be forbidden (requires admin).
	resp = tb.httpDoWithToken(t, "DELETE",
		"/api/stacks/organization/test-project/dev",
		writerTok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("DELETE: expected 403, got %d", resp.StatusCode)
	}
}

func TestJWT_RBAC_AdminUser(t *testing.T) {
	rbacConfig := &auth.RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []auth.GroupRole{
			{Group: "admins", Permission: "admin"},
		},
	}
	tb := newJWTBackend(t, rbacConfig)

	adminTok := signTestJWT(t, jwt.MapClaims{
		"sub":    "admin@example.com",
		"groups": []any{"admins"},
	})

	// Create stack.
	createTestStack(t, tb, adminTok, "organization", "test-project", "dev")

	// GET should succeed.
	resp := tb.httpDoWithToken(t, "GET",
		"/api/stacks/organization/test-project/dev",
		adminTok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d", resp.StatusCode)
	}

	// DELETE should also succeed (admin).
	resp = tb.httpDoWithToken(t, "DELETE",
		"/api/stacks/organization/test-project/dev",
		adminTok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE: expected 204, got %d", resp.StatusCode)
	}
}

func TestJWT_NonStackRoutes_SkipRBAC(t *testing.T) {
	rbacConfig := &auth.RBACConfig{
		DefaultPermission: "read",
	}
	tb := newJWTBackend(t, rbacConfig)

	// User with no groups — only "read" default.
	tok := signTestJWT(t, jwt.MapClaims{"sub": "user@example.com"})

	// Non-stack-scoped routes (no orgName param) should skip RBAC.
	resp := tb.httpDoWithToken(t, "GET", "/api/user", tok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/user: expected 200, got %d", resp.StatusCode)
	}
}

func TestSingleTenant_AnyToken(t *testing.T) {
	// Default mode (no auth options) = single-tenant.
	tb := startBackendWithOpts(t)

	resp := tb.httpDoWithToken(t, "GET", "/api/user", "any-random-token", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAuth_MissingHeader_401(t *testing.T) {
	tb := startBackendWithOpts(t)

	req, _ := http.NewRequest("GET", tb.URL+"/api/user", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAuth_InvalidFormat_401(t *testing.T) {
	tb := startBackendWithOpts(t)

	req, _ := http.NewRequest("GET", tb.URL+"/api/user", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestJWT_MissingSub_401(t *testing.T) {
	tb := newJWTBackend(t, nil)

	tok := signTestJWT(t, jwt.MapClaims{"name": "alice"})
	resp := tb.httpDoWithToken(t, "GET", "/api/user", tok, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// TestJWT_RBAC_StackPolicyOverride tests that stack-level policies can grant
// higher permissions than the group role for specific stacks.
func TestJWT_RBAC_StackPolicyOverride(t *testing.T) {
	rbacConfig := &auth.RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []auth.GroupRole{
			{Group: "devs", Permission: "read"},
			{Group: "admins", Permission: "admin"},
		},
		StackPolicies: []auth.StackPolicy{
			{Group: "devs", StackPattern: "organization/test-project/dev", Permission: "admin"},
		},
	}
	tb := newJWTBackend(t, rbacConfig)

	adminTok := signTestJWT(t, jwt.MapClaims{
		"sub":    "admin@example.com",
		"groups": []any{"admins"},
	})
	createTestStack(t, tb, adminTok, "organization", "test-project", "dev")
	createTestStack(t, tb, adminTok, "organization", "test-project", "prod")

	devTok := signTestJWT(t, jwt.MapClaims{
		"sub":    "dev@example.com",
		"groups": []any{"devs"},
	})

	// Dev has admin on dev stack (stack policy).
	resp := tb.httpDoWithToken(t, "DELETE",
		"/api/stacks/organization/test-project/dev",
		devTok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE dev: expected 204, got %d", resp.StatusCode)
	}

	// Dev has only read on prod stack (group role).
	resp = tb.httpDoWithToken(t, "DELETE",
		"/api/stacks/organization/test-project/prod",
		devTok, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("DELETE prod: expected 403, got %d", resp.StatusCode)
	}
}

// Verify public routes work without auth.
func TestPublicRoutes_NoAuth(t *testing.T) {
	tb := newJWTBackend(t, nil)

	// Health check.
	resp, err := http.Get(tb.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: expected 200, got %d", resp.StatusCode)
	}

	// Metrics.
	resp, err = http.Get(tb.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics: expected 200, got %d", resp.StatusCode)
	}

	// OpenAPI spec.
	resp, err = http.Get(tb.URL + "/api/openapi")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("openapi: expected 200, got %d", resp.StatusCode)
	}
}
