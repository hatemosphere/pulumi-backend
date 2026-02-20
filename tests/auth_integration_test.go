package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
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

// --- OIDC Auth Mock Infrastructure ---

const testOIDCClientID = "test-client-id.apps.googleusercontent.com"

// testOIDCValidator is a mock TestOIDCValidator that verifies RS256 JWTs
// signed with a test RSA key and returns claims as map[string]any.
type testOIDCValidator struct {
	publicKey *rsa.PublicKey
	audience  string
}

func (v *testOIDCValidator) Verify(_ context.Context, rawToken string) (map[string]any, error) {
	token, err := jwt.Parse(rawToken, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Check audience like the real OIDC verifier does.
	aud, _ := claims["aud"].(string)
	if aud != v.audience {
		return nil, fmt.Errorf("audience mismatch: got %q, want %q", aud, v.audience)
	}

	// Convert to map[string]any.
	result := make(map[string]any, len(claims))
	for k, val := range claims {
		result[k] = val
	}
	return result, nil
}

// testGroupsResolver is a mock GroupsResolverIface that returns pre-configured
// group memberships per email.
type testGroupsResolver struct {
	groups map[string][]string // email -> groups
}

func (r *testGroupsResolver) ResolveGroups(_ context.Context, email string) ([]string, error) {
	if groups, ok := r.groups[email]; ok {
		return groups, nil
	}
	return nil, nil
}

// oidcTestSetup holds the test RSA key pair and backend for OIDC auth tests.
type oidcTestSetup struct {
	tb         *testBackend
	privateKey *rsa.PrivateKey
}

// newOIDCBackend creates a backend in OIDC auth mode (Google flavor) with a mock
// ID token validator and optional groups/RBAC configuration.
func newOIDCBackend(t *testing.T, rbacConfig *auth.RBACConfig, groups map[string][]string, tokenTTL time.Duration, extraOpts ...api.ServerOption) *oidcTestSetup {
	t.Helper()

	// Generate test RSA key pair.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	validator := &testOIDCValidator{publicKey: &privateKey.PublicKey, audience: testOIDCClientID}

	if tokenTTL == 0 {
		tokenTTL = time.Hour
	}

	oidcConfig := auth.OIDCConfig{
		ClientID:       testOIDCClientID,
		AllowedDomains: []string{"example.com"},
		TokenTTL:       tokenTTL,
		ProviderName:   "Google",
	}

	// Set up groups cache if groups are configured.
	var groupsCache *auth.GroupsCache
	if groups != nil {
		resolver := &testGroupsResolver{groups: groups}
		groupsCache = auth.NewGroupsCache(resolver, 5*time.Minute)
	}

	oidcAuth := auth.NewTestOIDCAuthenticator(oidcConfig, groupsCache, validator, nil)

	// Build the backend manually (similar to startBackendWithOpts) so we can
	// pass the same store as both the engine's store and the token store.
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

	opts := []api.ServerOption{
		api.WithAuthMode("google"),
		api.WithOIDCAuth(oidcAuth),
		api.WithTokenStore(store),
	}
	if groupsCache != nil {
		opts = append(opts, api.WithGroupsCache(groupsCache))
	}
	if rbacConfig != nil {
		opts = append(opts, api.WithRBAC(auth.NewRBACResolver(rbacConfig)))
	}
	opts = append(opts, extraOpts...)

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
			return &oidcTestSetup{tb: tb, privateKey: privateKey}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("backend server failed to start")
	return nil
}

// newOIDCBackendWithRefresher is like newOIDCBackend but also injects a
// custom TestOIDCRefresher so that refresh re-validation is active in the
// auth middleware.
func newOIDCBackendWithRefresher(t *testing.T, rbacConfig *auth.RBACConfig, groups map[string][]string, tokenTTL time.Duration, refresher auth.TestOIDCRefresher) *oidcTestSetup {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	validator := &testOIDCValidator{publicKey: &privateKey.PublicKey, audience: testOIDCClientID}
	if tokenTTL == 0 {
		tokenTTL = time.Hour
	}

	oidcConfig := auth.OIDCConfig{
		ClientID:       testOIDCClientID,
		AllowedDomains: []string{"example.com"},
		TokenTTL:       tokenTTL,
		ProviderName:   "Google",
	}

	var groupsCache *auth.GroupsCache
	if groups != nil {
		resolver := &testGroupsResolver{groups: groups}
		groupsCache = auth.NewGroupsCache(resolver, 5*time.Minute)
	}

	oidcAuth := auth.NewTestOIDCAuthenticator(oidcConfig, groupsCache, validator, refresher)

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

	opts := []api.ServerOption{
		api.WithAuthMode("google"),
		api.WithOIDCAuth(oidcAuth),
		api.WithTokenStore(store),
	}
	if groupsCache != nil {
		opts = append(opts, api.WithGroupsCache(groupsCache))
	}
	if rbacConfig != nil {
		opts = append(opts, api.WithRBAC(auth.NewRBACResolver(rbacConfig)))
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
			return &oidcTestSetup{tb: tb, privateKey: privateKey}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("backend server failed to start")
	return nil
}

// mintIDToken creates a signed RS256 JWT that mimics an OIDC ID token.
func mintIDToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = testOIDCClientID
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = jwt.NewNumericDate(time.Now().Add(time.Hour))
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = jwt.NewNumericDate(time.Now())
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign ID token: %v", err)
	}
	return s
}

// exchangeToken calls POST /api/auth/token-exchange to exchange an ID token for
// a backend access token.
func exchangeToken(t *testing.T, tb *testBackend, idToken string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"idToken": idToken})
	resp, err := http.Post(tb.URL+"/api/auth/token-exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("exchange request failed: %v", err)
	}
	defer resp.Body.Close()
	var result map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &result)
	return resp.StatusCode, result
}

// --- OIDC Auth Integration Tests ---

func TestOIDCAuth_TokenExchange_200(t *testing.T) {
	gs := newOIDCBackend(t, nil, nil, 0)

	idToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub":            "alice@example.com",
		"email":          "alice@example.com",
		"email_verified": true,
		"hd":             "example.com",
	})

	status, result := exchangeToken(t, gs.tb, idToken)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, result)
	}
	if result["accessToken"] == nil || result["accessToken"] == "" {
		t.Fatal("expected accessToken in response")
	}
	if result["userName"] != "alice@example.com" {
		t.Fatalf("expected userName alice@example.com, got %v", result["userName"])
	}
}

func TestOIDCAuth_InvalidToken_401(t *testing.T) {
	gs := newOIDCBackend(t, nil, nil, 0)

	status, _ := exchangeToken(t, gs.tb, "not-a-valid-jwt")
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
}

func TestOIDCAuth_WrongAudience_401(t *testing.T) {
	gs := newOIDCBackend(t, nil, nil, 0)

	idToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub":            "alice@example.com",
		"email":          "alice@example.com",
		"email_verified": true,
		"hd":             "example.com",
		"aud":            "wrong-client-id",
	})

	status, _ := exchangeToken(t, gs.tb, idToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
}

func TestOIDCAuth_WrongDomain_401(t *testing.T) {
	gs := newOIDCBackend(t, nil, nil, 0)

	idToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub":            "alice@evil.com",
		"email":          "alice@evil.com",
		"email_verified": true,
		"hd":             "evil.com",
	})

	status, _ := exchangeToken(t, gs.tb, idToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
}

func TestOIDCAuth_MissingEmail_401(t *testing.T) {
	gs := newOIDCBackend(t, nil, nil, 0)

	idToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub":            "no-email-user",
		"email_verified": true,
		"hd":             "example.com",
	})

	status, _ := exchangeToken(t, gs.tb, idToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
}

func TestOIDCAuth_EmailNotVerified_401(t *testing.T) {
	gs := newOIDCBackend(t, nil, nil, 0)

	idToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub":            "alice@example.com",
		"email":          "alice@example.com",
		"email_verified": false,
		"hd":             "example.com",
	})

	status, _ := exchangeToken(t, gs.tb, idToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
}

func TestOIDCAuth_ExpiredBackendToken_401(t *testing.T) {
	// Use a short TTL so the backend token expires quickly.
	gs := newOIDCBackend(t, nil, nil, 1*time.Second)

	idToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub":            "alice@example.com",
		"email":          "alice@example.com",
		"email_verified": true,
		"hd":             "example.com",
	})

	// Exchange should succeed.
	status, result := exchangeToken(t, gs.tb, idToken)
	if status != http.StatusOK {
		t.Fatalf("exchange: expected 200, got %d", status)
	}

	backendToken, _ := result["accessToken"].(string)

	// Immediately should work.
	resp := gs.tb.httpDoWithToken(t, "GET", "/api/user", backendToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("immediate use: expected 200, got %d", resp.StatusCode)
	}

	// Wait for token to expire.
	time.Sleep(1100 * time.Millisecond)

	resp = gs.tb.httpDoWithToken(t, "GET", "/api/user", backendToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after expiry: expected 401, got %d", resp.StatusCode)
	}
}

func TestOIDCAuth_AuthenticatedRequest_200(t *testing.T) {
	gs := newOIDCBackend(t, nil, nil, 0)

	idToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub":            "alice@example.com",
		"email":          "alice@example.com",
		"email_verified": true,
		"hd":             "example.com",
	})

	status, result := exchangeToken(t, gs.tb, idToken)
	if status != http.StatusOK {
		t.Fatalf("exchange: expected 200, got %d", status)
	}

	backendToken, _ := result["accessToken"].(string)

	// Use the backend token to access a protected endpoint.
	resp := gs.tb.httpDoWithToken(t, "GET", "/api/user", backendToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
}

func TestOIDCAuth_RBAC_GroupPermissions(t *testing.T) {
	rbacConfig := &auth.RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []auth.GroupRole{
			{Group: "admins@example.com", Permission: "admin"},
			{Group: "readers@example.com", Permission: "read"},
		},
	}
	groups := map[string][]string{
		"admin@example.com":  {"admins@example.com"},
		"reader@example.com": {"readers@example.com"},
	}
	gs := newOIDCBackend(t, rbacConfig, groups, 0)

	// Exchange admin token.
	adminIDToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub":            "admin@example.com",
		"email":          "admin@example.com",
		"email_verified": true,
		"hd":             "example.com",
	})
	status, adminResult := exchangeToken(t, gs.tb, adminIDToken)
	if status != http.StatusOK {
		t.Fatalf("admin exchange: expected 200, got %d", status)
	}
	adminToken, _ := adminResult["accessToken"].(string)

	// Create a stack with the admin token.
	createTestStack(t, gs.tb, adminToken, "organization", "test-project", "dev")

	// Exchange reader token.
	readerIDToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub":            "reader@example.com",
		"email":          "reader@example.com",
		"email_verified": true,
		"hd":             "example.com",
	})
	status, readerResult := exchangeToken(t, gs.tb, readerIDToken)
	if status != http.StatusOK {
		t.Fatalf("reader exchange: expected 200, got %d", status)
	}
	readerToken, _ := readerResult["accessToken"].(string)

	// Reader should be able to GET.
	resp := gs.tb.httpDoWithToken(t, "GET",
		"/api/stacks/organization/test-project/dev",
		readerToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reader GET: expected 200, got %d", resp.StatusCode)
	}

	// Reader should NOT be able to DELETE (requires admin).
	resp = gs.tb.httpDoWithToken(t, "DELETE",
		"/api/stacks/organization/test-project/dev",
		readerToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("reader DELETE: expected 403, got %d", resp.StatusCode)
	}

	// Admin should be able to DELETE.
	resp = gs.tb.httpDoWithToken(t, "DELETE",
		"/api/stacks/organization/test-project/dev",
		adminToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("admin DELETE: expected 204, got %d", resp.StatusCode)
	}
}

func TestOIDCAuth_NoGroupsCache_NoGroups(t *testing.T) {
	// When no groups cache is configured, RBAC should still work with
	// just the default permission (no groups to match against).
	rbacConfig := &auth.RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []auth.GroupRole{
			{Group: "admins@example.com", Permission: "admin"},
		},
	}
	// Pass nil groups = no groups cache.
	gs := newOIDCBackend(t, rbacConfig, nil, 0)

	idToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub":            "alice@example.com",
		"email":          "alice@example.com",
		"email_verified": true,
		"hd":             "example.com",
	})
	status, result := exchangeToken(t, gs.tb, idToken)
	if status != http.StatusOK {
		t.Fatalf("exchange: expected 200, got %d", status)
	}
	backendToken, _ := result["accessToken"].(string)

	// User has only "read" default permission (no groups resolved).
	// Non-stack routes should work.
	resp := gs.tb.httpDoWithToken(t, "GET", "/api/user", backendToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/user: expected 200, got %d", resp.StatusCode)
	}
}

// --- Browser/CLI Login Page Tests ---

func TestOIDCAuth_LoginPage_Available(t *testing.T) {
	gs := newOIDCBackend(t, nil, nil, 0)

	// GET /login should return the login page HTML.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(gs.tb.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login: expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Should be HTML with SSO sign-in, not JSON health check.
	if !strings.Contains(bodyStr, "Sign in with Google") {
		t.Fatalf("GET /login: expected login page HTML with 'Sign in with Google', got: %s", bodyStr[:min(200, len(bodyStr))])
	}
	if strings.Contains(bodyStr, `"status":"ok"`) {
		t.Fatal("GET /login: got health check JSON instead of login page")
	}
}

func TestOIDCAuth_CLILogin_Redirects(t *testing.T) {
	gs := newOIDCBackend(t, nil, nil, 0)

	// GET /cli-login with proper params should redirect to OIDC provider.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(gs.tb.URL + "/cli-login?cliSessionPort=12345&cliSessionNonce=testnonce")
	if err != nil {
		t.Fatalf("GET /cli-login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTemporaryRedirect {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /cli-login: expected 307 redirect, got %d: %s", resp.StatusCode, string(body)[:min(200, len(body))])
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "accounts.google.com") {
		t.Fatalf("GET /cli-login: expected redirect to Google OAuth, got: %s", location)
	}
	if !strings.Contains(location, "redirect_uri=") {
		t.Fatal("GET /cli-login: redirect URL missing redirect_uri")
	}
}

func TestAuth_LoginPage_NotAvailableInJWTMode(t *testing.T) {
	// In JWT mode (no OIDC auth), /login should not return a login page.
	tb := newJWTBackend(t, nil)

	resp, err := http.Get(tb.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Should NOT be the login page.
	if strings.Contains(bodyStr, "Sign in with") {
		t.Fatal("GET /login: login page should not be available in JWT mode")
	}
}

// --- Admin Token Management Tests ---

func TestOIDCAuth_AdminListTokens(t *testing.T) {
	rbacConfig := &auth.RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []auth.GroupRole{
			{Group: "admins@example.com", Permission: "admin"},
		},
	}
	groups := map[string][]string{
		"admin@example.com": {"admins@example.com"},
		"user@example.com":  {},
	}
	gs := newOIDCBackend(t, rbacConfig, groups, 0)

	// Exchange admin token.
	adminIDToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub": "admin@example.com", "email": "admin@example.com",
		"email_verified": true, "hd": "example.com",
	})
	status, adminResult := exchangeToken(t, gs.tb, adminIDToken)
	if status != http.StatusOK {
		t.Fatalf("admin exchange: expected 200, got %d", status)
	}
	adminToken, _ := adminResult["accessToken"].(string)

	// Exchange user token.
	userIDToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub": "user@example.com", "email": "user@example.com",
		"email_verified": true, "hd": "example.com",
	})
	status, _ = exchangeToken(t, gs.tb, userIDToken)
	if status != http.StatusOK {
		t.Fatalf("user exchange: expected 200, got %d", status)
	}

	// Admin lists user's tokens.
	resp := gs.tb.httpDoWithToken(t, "GET", "/api/admin/tokens/user@example.com", adminToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin list tokens: expected 200, got %d: %s", resp.StatusCode, body)
	}

	var listResp struct {
		Tokens []struct {
			TokenHashPrefix string `json:"tokenHashPrefix"`
			Description     string `json:"description"`
		} `json:"tokens"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listResp.Tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(listResp.Tokens))
	}
	if listResp.Tokens[0].Description != "oidc-token-exchange" {
		t.Fatalf("expected description 'oidc-token-exchange', got %q", listResp.Tokens[0].Description)
	}
}

func TestOIDCAuth_AdminRevokeTokens(t *testing.T) {
	rbacConfig := &auth.RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []auth.GroupRole{
			{Group: "admins@example.com", Permission: "admin"},
		},
	}
	groups := map[string][]string{
		"admin@example.com": {"admins@example.com"},
		"user@example.com":  {},
	}
	gs := newOIDCBackend(t, rbacConfig, groups, 0)

	// Exchange admin + user tokens.
	adminIDToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub": "admin@example.com", "email": "admin@example.com",
		"email_verified": true, "hd": "example.com",
	})
	status, adminResult := exchangeToken(t, gs.tb, adminIDToken)
	if status != http.StatusOK {
		t.Fatalf("admin exchange: expected 200, got %d", status)
	}
	adminToken, _ := adminResult["accessToken"].(string)

	userIDToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub": "user@example.com", "email": "user@example.com",
		"email_verified": true, "hd": "example.com",
	})
	status, userResult := exchangeToken(t, gs.tb, userIDToken)
	if status != http.StatusOK {
		t.Fatalf("user exchange: expected 200, got %d", status)
	}
	userToken, _ := userResult["accessToken"].(string)

	// Verify user token works.
	resp := gs.tb.httpDoWithToken(t, "GET", "/api/user", userToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("user token should work: expected 200, got %d", resp.StatusCode)
	}

	// Admin revokes user's tokens.
	resp = gs.tb.httpDoWithToken(t, "DELETE", "/api/admin/tokens/user@example.com", adminToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin revoke: expected 200, got %d: %s", resp.StatusCode, body)
	}

	var revokeResp struct {
		Revoked int64 `json:"revoked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&revokeResp); err != nil {
		t.Fatalf("decode revoke response: %v", err)
	}
	if revokeResp.Revoked != 1 {
		t.Fatalf("expected 1 revoked, got %d", revokeResp.Revoked)
	}

	// Verify user token no longer works.
	resp2 := gs.tb.httpDoWithToken(t, "GET", "/api/user", userToken, nil)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token should fail: expected 401, got %d", resp2.StatusCode)
	}

	// Admin token should still work.
	resp3 := gs.tb.httpDoWithToken(t, "GET", "/api/user", adminToken, nil)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("admin token should still work: expected 200, got %d", resp3.StatusCode)
	}
}

func TestOIDCAuth_AdminForbiddenForNonAdmin(t *testing.T) {
	rbacConfig := &auth.RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []auth.GroupRole{
			{Group: "admins@example.com", Permission: "admin"},
		},
	}
	groups := map[string][]string{
		"user@example.com": {},
	}
	gs := newOIDCBackend(t, rbacConfig, groups, 0)

	userIDToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub": "user@example.com", "email": "user@example.com",
		"email_verified": true, "hd": "example.com",
	})
	status, userResult := exchangeToken(t, gs.tb, userIDToken)
	if status != http.StatusOK {
		t.Fatalf("user exchange: expected 200, got %d", status)
	}
	userToken, _ := userResult["accessToken"].(string)

	// Non-admin cannot list tokens.
	resp := gs.tb.httpDoWithToken(t, "GET", "/api/admin/tokens/user@example.com", userToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin list: expected 403, got %d", resp.StatusCode)
	}

	// Non-admin cannot revoke tokens.
	resp = gs.tb.httpDoWithToken(t, "DELETE", "/api/admin/tokens/user@example.com", userToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin revoke: expected 403, got %d", resp.StatusCode)
	}
}

// --- Refresh Token Re-validation Tests ---

// testOIDCRefresher is a mock TestOIDCRefresher for testing re-validation behavior.
type testOIDCRefresher struct {
	shouldFail bool
	failErr    error
	// signKey is used to mint a valid JWT when refresh succeeds (so the validator accepts it).
	signKey *rsa.PrivateKey
}

func (r *testOIDCRefresher) Refresh(_ context.Context, _ string) (string, error) {
	if r.shouldFail {
		if r.failErr != nil {
			return "", r.failErr
		}
		return "", errors.New("OIDC provider rejected refresh token: user deactivated")
	}
	// Return a signed JWT that the test validator will accept.
	claims := jwt.MapClaims{
		"sub":            "alice@example.com",
		"email":          "alice@example.com",
		"email_verified": true,
		"hd":             "example.com",
		"aud":            testOIDCClientID,
		"exp":            jwt.NewNumericDate(time.Now().Add(time.Hour)),
		"iat":            jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := token.SignedString(r.signKey)
	if err != nil {
		return "", fmt.Errorf("sign mock ID token: %w", err)
	}
	return s, nil
}

func TestOIDCAuth_RefreshTokenRevalidation_Revokes(t *testing.T) {
	// Create a backend where the refresh token re-validation will fail,
	// simulating a deactivated user.
	// Use 6s TTL — long enough that the token doesn't expire naturally during the test,
	// but the revocation happens due to failed re-validation.
	refresher := &testOIDCRefresher{shouldFail: true}

	gs := newOIDCBackendWithRefresher(t, nil, nil, 6*time.Second, refresher)
	refresher.signKey = gs.privateKey

	idToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub": "alice@example.com", "email": "alice@example.com",
		"email_verified": true, "hd": "example.com",
	})

	status, result := exchangeToken(t, gs.tb, idToken)
	if status != http.StatusOK {
		t.Fatalf("exchange: expected 200, got %d", status)
	}
	backendToken, _ := result["accessToken"].(string)

	// Manually insert a refresh token into the token record.
	tokenHash := auth.HashToken(backendToken)
	_, err := gs.tb.store.DB().ExecContext(context.Background(),
		`UPDATE tokens SET refresh_token='fake-refresh-token' WHERE token_hash=?`, tokenHash)
	if err != nil {
		t.Fatalf("update refresh token: %v", err)
	}

	// Wait until token is past half its TTL (3s) so re-validation triggers.
	time.Sleep(3100 * time.Millisecond)

	// Make a request — this will trigger async re-validation which should fail
	// and revoke the token.
	resp := gs.tb.httpDoWithToken(t, "GET", "/api/user", backendToken, nil)
	resp.Body.Close()
	// The request itself succeeds (re-validation is async).
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request during revalidation: expected 200, got %d", resp.StatusCode)
	}

	// Wait for async re-validation to complete and revoke the token.
	time.Sleep(500 * time.Millisecond)

	// Next request should fail because the token was revoked.
	resp2 := gs.tb.httpDoWithToken(t, "GET", "/api/user", backendToken, nil)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after revalidation failure: expected 401, got %d", resp2.StatusCode)
	}
}

func TestOIDCAuth_RefreshTokenRevalidation_Passes(t *testing.T) {
	// Create a backend where refresh token re-validation succeeds.
	// Use a longer TTL (6s) so the token doesn't expire during the test.
	refresher := &testOIDCRefresher{shouldFail: false}

	gs := newOIDCBackendWithRefresher(t, nil, nil, 6*time.Second, refresher)
	refresher.signKey = gs.privateKey

	idToken := mintIDToken(t, gs.privateKey, jwt.MapClaims{
		"sub": "alice@example.com", "email": "alice@example.com",
		"email_verified": true, "hd": "example.com",
	})

	status, result := exchangeToken(t, gs.tb, idToken)
	if status != http.StatusOK {
		t.Fatalf("exchange: expected 200, got %d", status)
	}
	backendToken, _ := result["accessToken"].(string)

	// Insert a refresh token.
	tokenHash := auth.HashToken(backendToken)
	_, err := gs.tb.store.DB().ExecContext(context.Background(),
		`UPDATE tokens SET refresh_token='fake-refresh-token' WHERE token_hash=?`, tokenHash)
	if err != nil {
		t.Fatalf("update refresh token: %v", err)
	}

	// Wait past half TTL (3s) so re-validation triggers.
	time.Sleep(3100 * time.Millisecond)

	// Make a request — triggers revalidation which should succeed.
	resp := gs.tb.httpDoWithToken(t, "GET", "/api/user", backendToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request during revalidation: expected 200, got %d", resp.StatusCode)
	}

	// Wait for async work.
	time.Sleep(500 * time.Millisecond)

	// Token should still work since revalidation passed.
	resp2 := gs.tb.httpDoWithToken(t, "GET", "/api/user", backendToken, nil)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("after successful revalidation: expected 200, got %d", resp2.StatusCode)
	}
}
