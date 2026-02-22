package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// TestGoogleAuthE2E tests the full Google OIDC auth flow end-to-end:
//
//  1. Starts the backend in google auth mode with RBAC + keyless DWD groups
//  2. Opens browser for Google OAuth2 login to get an ID token
//  3. Exchanges the Google ID token for a backend token
//  4. Tests authenticated + unauthenticated requests
//
// Required env vars:
//
//	GOOGLE_CLIENT_ID        — OAuth2 client ID
//	GOOGLE_CLIENT_SECRET    — OAuth2 client secret
//	GOOGLE_SA_EMAIL         — DWD service account email
//	GOOGLE_ADMIN_EMAIL      — Workspace super-admin email
//	GOOGLE_ALLOWED_DOMAIN   — Allowed hosted domain (e.g. "example.com")
//	GOOGLE_ADMIN_GROUP      — Admin group email (e.g. "admins@example.com")
//	GOOGLE_WRITE_GROUP      — Write group email (e.g. "developers@example.com")
func TestGoogleAuthE2E(t *testing.T) {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	saEmail := os.Getenv("GOOGLE_SA_EMAIL")
	adminEmail := os.Getenv("GOOGLE_ADMIN_EMAIL")

	if clientID == "" || clientSecret == "" || saEmail == "" || adminEmail == "" {
		t.Skip("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_SA_EMAIL, or GOOGLE_ADMIN_EMAIL not set")
	}

	allowedDomain := os.Getenv("GOOGLE_ALLOWED_DOMAIN")
	if allowedDomain == "" {
		// Derive domain from admin email.
		parts := strings.SplitN(adminEmail, "@", 2)
		if len(parts) == 2 {
			allowedDomain = parts[1]
		}
	}

	adminGroup := os.Getenv("GOOGLE_ADMIN_GROUP")
	writeGroup := os.Getenv("GOOGLE_WRITE_GROUP")

	ctx := context.Background()

	// --- Groups resolver (keyless DWD via IAM impersonation) ---
	resolver, err := auth.NewGroupsResolver(ctx, "", saEmail, adminEmail, false)
	if err != nil {
		t.Fatalf("NewGroupsResolver: %v", err)
	}
	groupsCache := auth.NewGroupsCache(resolver, 5*time.Minute)

	// --- Google OIDC authenticator ---
	var allowedDomains []string
	if allowedDomain != "" {
		allowedDomains = []string{allowedDomain}
	}
	oidcAuth, err := auth.NewGoogleOIDCAuthenticator(ctx, auth.OIDCConfig{
		ClientID:       clientID,
		AllowedDomains: allowedDomains,
		TokenTTL:       1 * time.Hour,
	}, clientSecret, groupsCache)
	if err != nil {
		t.Fatalf("NewGoogleOIDCAuthenticator: %v", err)
	}

	// --- RBAC ---
	var groupRoles []auth.GroupRole
	if adminGroup != "" {
		groupRoles = append(groupRoles, auth.GroupRole{Group: adminGroup, Permission: "admin"})
	}
	if writeGroup != "" {
		groupRoles = append(groupRoles, auth.GroupRole{Group: writeGroup, Permission: "write"})
	}
	rbacConfig := &auth.RBACConfig{DefaultPermission: "read", GroupRoles: groupRoles}
	rbacResolver, err := auth.NewRBACResolver(rbacConfig)
	if err != nil {
		t.Fatalf("NewRBACResolver: %v", err)
	}

	// --- Build backend server ---
	dataDir := t.TempDir()
	store, err := storage.NewSQLiteStore(filepath.Join(dataDir, "test.db"), storage.SQLiteStoreConfig{})
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	masterKey := make([]byte, 32)
	provider, err := engine.NewLocalSecretsProvider(masterKey)
	if err != nil {
		t.Fatalf("NewLocalSecretsProvider: %v", err)
	}

	mgr, err := engine.NewManager(store, engine.NewSecretsEngine(provider), engine.ManagerConfig{})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	orgName := "testorg"
	srv := api.NewServer(mgr, orgName, "",
		api.WithAuthMode("google"),
		api.WithTokenStore(store),
		api.WithOIDCAuth(oidcAuth),
		api.WithGroupsCache(groupsCache),
		api.WithRBAC(rbacResolver),
	)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	httpServer := &http.Server{Handler: srv.Router(), ReadHeaderTimeout: 10 * time.Second} //nolint:gosec // test server
	go func() { _ = httpServer.Serve(listener) }()
	t.Cleanup(func() {
		_ = httpServer.Shutdown(ctx)
		store.Close()
	})

	// Wait for server to be ready.
	for range 50 {
		if resp, err := http.Get(baseURL + "/"); err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("Backend running at %s", baseURL)

	// --- Step 1: Get Google ID token via OAuth2 flow ---
	idToken := getGoogleIDToken(t, clientID, clientSecret)
	t.Logf("Got Google ID token (length=%d)", len(idToken))

	// --- Step 2: Exchange ID token for backend token ---
	resp := doReq(t, baseURL, "POST", "/api/auth/token-exchange", "", map[string]string{"idToken": idToken})
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("token exchange: status %d, body: %s", resp.StatusCode, body)
	}
	var exchangeResp struct {
		Token     string `json:"accessToken"` //nolint:gosec // JSON API field, not a credential
		UserName  string `json:"userName"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&exchangeResp); err != nil {
		t.Fatalf("decode exchange response: %v", err)
	}
	resp.Body.Close()

	token := exchangeResp.Token
	t.Logf("Backend token issued for user=%s groups resolved via DWD", exchangeResp.UserName)

	// --- Step 3: Authenticated requests ---
	stackPath := fmt.Sprintf("/api/stacks/%s/myproject", orgName)
	assertHTTP(t, baseURL, "GET", "/api/user", token, nil, 200, "authenticated user info")
	assertHTTP(t, baseURL, "POST", stackPath, token,
		map[string]string{"stackName": "dev-us"}, 200, "create stack (write)")
	assertHTTP(t, baseURL, "GET", stackPath+"/dev-us", token, nil, 200, "get stack (read)")

	// --- Step 4: Auth failures ---
	assertHTTP(t, baseURL, "GET", stackPath+"/dev-us", "", nil, 401, "no auth")
	assertHTTP(t, baseURL, "GET", stackPath+"/dev-us", "bogus", nil, 401, "bad token")

	t.Log("All Google auth E2E checks passed!")
}

func assertHTTP(t *testing.T, base, method, path, token string, body any, wantStatus int, desc string) {
	t.Helper()
	resp := doReq(t, base, method, path, token, body)
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Errorf("%s: %s %s: want %d, got %d, body: %s", desc, method, path, wantStatus, resp.StatusCode, respBody)
	} else {
		t.Logf("%s: %s %s -> %d OK", desc, method, path, resp.StatusCode)
	}
}

func doReq(t *testing.T, base, method, path, token string, body any) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, base+path, bodyReader)
	if token != "" {
		req.Header.Set("Authorization", "token "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, path, err)
	}
	return resp
}

// getGoogleIDToken does the OAuth2 authorization code flow: opens browser, waits
// for callback with auth code, exchanges code for ID token.
func getGoogleIDToken(t *testing.T, clientID, clientSecret string) string {
	t.Helper()

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			errCh <- fmt.Errorf("OAuth error: %s", errMsg)
			http.Error(w, "OAuth error", http.StatusBadRequest)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			return // favicon etc
		}
		codeCh <- code
		fmt.Fprint(w, "<h2>OK — you can close this tab</h2>")
	})

	callbackSrv := &http.Server{Addr: "127.0.0.1:8085", Handler: mux, ReadHeaderTimeout: 10 * time.Second} //nolint:gosec // test server
	go func() { _ = callbackSrv.ListenAndServe() }()
	defer callbackSrv.Close()

	authURL := "https://accounts.google.com/o/oauth2/v2/auth?" + url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {"http://localhost:8085"},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"access_type":   {"offline"},
		"prompt":        {"consent"},
	}.Encode()

	t.Log(">>> Opening browser for Google login. Complete sign-in to continue the test.")
	openBrowser(authURL)

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		t.Fatalf("OAuth error: %v", err)
	case <-time.After(90 * time.Second):
		t.Fatal("Timed out waiting for Google OAuth callback (90s)")
	}

	// Exchange code for tokens.
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {"http://localhost:8085"},
		"grant_type":    {"authorization_code"},
	})
	if err != nil {
		t.Fatalf("Google token exchange: %v", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		ErrDesc string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	if tokenResp.Error != "" {
		t.Fatalf("Google token exchange: %s: %s", tokenResp.Error, tokenResp.ErrDesc)
	}
	if tokenResp.IDToken == "" {
		t.Fatal("no id_token in Google token response")
	}
	return tokenResp.IDToken
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("open", url).Start()
	case "linux":
		_ = exec.Command("xdg-open", url).Start()
	}
}
