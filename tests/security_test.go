package tests

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/auth"
)

// --- Security Headers ---

func TestSecurityHeaders(t *testing.T) {
	tb := startBackend(t)

	resp, err := http.Get(tb.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	tests := []struct {
		header string
		want   string
	}{
		{"X-Frame-Options", "DENY"},
		{"X-Content-Type-Options", "nosniff"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
	}
	for _, tc := range tests {
		got := resp.Header.Get(tc.header)
		if got != tc.want {
			t.Errorf("header %s: got %q, want %q", tc.header, got, tc.want)
		}
	}
}

// --- Update Token Bypass ---

func TestUpdateTokenBypass(t *testing.T) {
	// Use JWT mode so that update-token validation is active
	// (in single-tenant mode, all tokens are accepted).
	tb := newJWTBackend(t, nil)

	// Try to access a non-update-scoped endpoint with an update-token.
	// This should be rejected because update-token requires an update-scoped endpoint.
	req, err := http.NewRequest("GET", tb.URL+"/api/user/stacks", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "update-token fake-token-value")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401, got %d: %s", resp.StatusCode, string(body))
	}

	// Verify the error message mentions update-scoped endpoint.
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "update-token requires an update-scoped endpoint") {
		t.Fatalf("expected 'update-token requires an update-scoped endpoint' in body, got: %s", string(body))
	}
}

func TestUpdateTokenBypass_InvalidToken(t *testing.T) {
	// Use JWT mode so that update-token validation is active.
	tb := newJWTBackend(t, nil)

	// Create a stack and start an update so we have a valid updateID.
	adminTok := signTestJWT(t, jwt.MapClaims{"sub": "admin@example.com"})
	createTestStack(t, tb, adminTok, "organization", "sec-proj", "sec-stack")

	// Create and start update using JWT auth.
	resp := tb.httpDoWithToken(t, "POST",
		fmt.Sprintf("/api/stacks/%s/sec-proj/sec-stack/update", rOrg),
		adminTok, map[string]any{"config": map[string]any{}, "metadata": map[string]any{}})
	var createResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &createResp)
	if createResp.UpdateID == "" {
		t.Fatal("empty updateID")
	}

	resp = tb.httpDoWithToken(t, "POST",
		fmt.Sprintf("/api/stacks/%s/sec-proj/sec-stack/update/%s", rOrg, createResp.UpdateID),
		adminTok, map[string]any{"tags": map[string]string{}})
	resp.Body.Close()

	// Try to access the update-scoped endpoint with a bogus update-token.
	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/api/stacks/%s/sec-proj/sec-stack/update/%s/events", tb.URL, rOrg, createResp.UpdateID), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "update-token totally-wrong-token")

	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("expected 401, got %d: %s", resp2.StatusCode, string(body))
	}
}

// --- Continuation Token Validation ---

func TestContinuationTokenValidation(t *testing.T) {
	tb := startBackend(t)

	// Create a stack and run a full update so events endpoint is reachable.
	rCreateStack(t, tb, "ct-proj", "ct-stack")
	deployment := rMakeDeployment("ct-marker")
	rRunFullUpdate(t, tb, "ct-proj", "ct-stack", deployment)

	// Get the latest update to find the updateID.
	resp := tb.httpDo(t, "GET",
		fmt.Sprintf("/api/stacks/%s/ct-proj/ct-stack/updates/latest", rOrg), nil)
	var latestResp struct {
		UpdateID string `json:"updateID"`
	}
	httpJSON(t, resp, &latestResp)
	if latestResp.UpdateID == "" {
		t.Fatal("no updateID from latest update")
	}

	tests := []struct {
		name  string
		token string
	}{
		{"non-numeric", "not-a-number"},
		{"negative", "-1"},
		{"float", "1.5"},
		{"special-chars", "abc!@#"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := tb.httpDo(t, "GET",
				fmt.Sprintf("/api/stacks/%s/ct-proj/ct-stack/update/%s/events?continuationToken=%s",
					rOrg, latestResp.UpdateID, tc.token), nil)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected 400 for token %q, got %d: %s", tc.token, resp.StatusCode, string(body))
			}
		})
	}
}

// --- RBAC Default Permission Invalid ---

func TestRBACDefaultPermissionInvalid(t *testing.T) {
	cfg := &auth.RBACConfig{DefaultPermission: "bogus"}
	_, err := auth.NewRBACResolver(cfg)
	if err == nil {
		t.Fatal("expected error for invalid default permission")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("error should mention the invalid value, got: %v", err)
	}
}

func TestRBACDefaultPermission_ValidValues(t *testing.T) {
	for _, perm := range []string{"none", "read", "write", "admin"} {
		t.Run(perm, func(t *testing.T) {
			cfg := &auth.RBACConfig{DefaultPermission: perm}
			resolver, err := auth.NewRBACResolver(cfg)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", perm, err)
			}
			if resolver == nil {
				t.Fatal("resolver should not be nil")
			}
		})
	}
}

// --- RBAC Stack List Filtering ---

func TestRBACStackListFiltering(t *testing.T) {
	// defaultPermission=none means users with no matching group/stack policy
	// get "none" (no access). The "devs" group has no global group role, only
	// a stack policy granting read on a specific stack. This ensures devs
	// can see only that stack, not all stacks.
	rbacConfig := &auth.RBACConfig{
		DefaultPermission: "none",
		GroupRoles: []auth.GroupRole{
			{Group: "admins", Permission: "admin"},
			// No group role for "devs" — they only get stack-level policies.
		},
		StackPolicies: []auth.StackPolicy{
			{Group: "devs", StackPattern: "organization/allowed-proj/dev", Permission: "read"},
		},
	}
	tb := newJWTBackend(t, rbacConfig)

	// Create stacks with admin.
	adminTok := signTestJWT(t, jwt.MapClaims{
		"sub":    "admin@example.com",
		"groups": []any{"admins"},
	})
	createTestStack(t, tb, adminTok, "organization", "allowed-proj", "dev")
	createTestStack(t, tb, adminTok, "organization", "secret-proj", "prod")

	// Dev user should only see the allowed stack.
	devTok := signTestJWT(t, jwt.MapClaims{
		"sub":    "dev@example.com",
		"groups": []any{"devs"},
	})
	resp := tb.httpDoWithToken(t, "GET", "/api/user/stacks", devTok, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	var stacksResp struct {
		Stacks []struct {
			ProjectName string `json:"projectName"`
			StackName   string `json:"stackName"`
		} `json:"stacks"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &stacksResp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Should only see allowed-proj/dev, not secret-proj/prod.
	for _, s := range stacksResp.Stacks {
		if s.ProjectName == "secret-proj" && s.StackName == "prod" {
			t.Fatal("dev user should NOT see secret-proj/prod stack")
		}
	}

	found := false
	for _, s := range stacksResp.Stacks {
		if s.ProjectName == "allowed-proj" && s.StackName == "dev" {
			found = true
		}
	}
	if !found {
		t.Fatal("dev user should see allowed-proj/dev stack")
	}
}

// --- Team Enumeration Filtered ---

func TestTeamEnumerationFiltered(t *testing.T) {
	rbacConfig := &auth.RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []auth.GroupRole{
			{Group: "dev-group", Permission: "write"},
			{Group: "admin-group", Permission: "admin"},
		},
	}
	tb := newJWTBackend(t, rbacConfig)

	// User in dev-group only.
	devTok := signTestJWT(t, jwt.MapClaims{
		"sub":    "dev@example.com",
		"groups": []any{"dev-group"},
	})

	resp := tb.httpDoWithToken(t, "GET", "/api/orgs/organization/teams", devTok, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	var teamsResp struct {
		Teams []struct {
			Name string `json:"name"`
		} `json:"teams"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &teamsResp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, team := range teamsResp.Teams {
		if team.Name == "admin-group" {
			t.Fatal("non-admin user should NOT see admin-group team")
		}
	}

	found := false
	for _, team := range teamsResp.Teams {
		if team.Name == "dev-group" {
			found = true
		}
	}
	if !found {
		t.Fatal("dev user should see dev-group team")
	}
}

func TestTeamEnumeration_AdminSeesAll(t *testing.T) {
	rbacConfig := &auth.RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []auth.GroupRole{
			{Group: "dev-group", Permission: "write"},
			{Group: "admin-group", Permission: "admin"},
		},
	}
	tb := newJWTBackend(t, rbacConfig)

	// Admin user should see all teams.
	adminTok := signTestJWT(t, jwt.MapClaims{
		"sub":    "admin@example.com",
		"groups": []any{"admin-group"},
	})

	resp := tb.httpDoWithToken(t, "GET", "/api/orgs/organization/teams", adminTok, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	var teamsResp struct {
		Teams []struct {
			Name string `json:"name"`
		} `json:"teams"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &teamsResp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	teamNames := make(map[string]bool)
	for _, team := range teamsResp.Teams {
		teamNames[team.Name] = true
	}
	if !teamNames["dev-group"] {
		t.Fatal("admin should see dev-group")
	}
	if !teamNames["admin-group"] {
		t.Fatal("admin should see admin-group")
	}
}

// --- Gzip Bomb Rejection ---

func TestGzipBombRejection(t *testing.T) {
	tb := startBackend(t)

	// Create a gzip payload that decompresses to >256MB.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	zeros := make([]byte, 1<<20) // 1MB of zeros
	for range 300 {              // 300MB decompressed
		if _, err := gz.Write(zeros); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	req, err := http.NewRequest("POST", tb.URL+"/api/stacks/organization/bomb-proj", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "token test-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 413, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestGzipBomb_ValidPayloadPasses(t *testing.T) {
	tb := startBackend(t)

	// Create a small valid gzip payload.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	payload, _ := json.Marshal(map[string]string{"stackName": "test-stack"})
	if _, err := gz.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	req, err := http.NewRequest("POST", tb.URL+"/api/stacks/organization/gzip-proj", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "token test-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Should succeed (200 for stack creation), not be blocked as a bomb.
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Fatal("valid small gzip payload should not be rejected as a bomb")
	}
}

// --- Trusted Proxies ---

func TestTrustedProxies_ParseValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		count int
	}{
		{"single CIDR", "10.0.0.0/8", 1},
		{"multiple CIDRs", "10.0.0.0/8, 172.16.0.0/12", 2},
		{"plain IP gets /32", "10.0.0.1", 1},
		{"IPv6 plain gets /128", "::1", 1},
		{"mixed", "10.0.0.0/8, 192.168.1.1", 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nets, err := api.ParseTrustedProxies(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(nets) != tc.count {
				t.Fatalf("expected %d nets, got %d", tc.count, len(nets))
			}
		})
	}
}

func TestTrustedProxies_ParseEmpty(t *testing.T) {
	nets, err := api.ParseTrustedProxies("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nets != nil {
		t.Fatalf("expected nil for empty input, got %v", nets)
	}
}

func TestTrustedProxies_ParseInvalid(t *testing.T) {
	_, err := api.ParseTrustedProxies("not-a-cidr")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestTrustedProxies_PlainIPAuto32(t *testing.T) {
	nets, err := api.ParseTrustedProxies("10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 1 {
		t.Fatalf("expected 1 net, got %d", len(nets))
	}
	// The parsed CIDR should be 10.0.0.1/32.
	expected := "10.0.0.1/32"
	if nets[0].String() != expected {
		t.Fatalf("expected %s, got %s", expected, nets[0].String())
	}
}

func TestTrustedProxies_RealIPMiddleware(t *testing.T) {
	// When trusted proxies are configured and the request comes from an untrusted IP,
	// X-Forwarded-For should NOT be honoured.
	tb := startBackendWithOpts(t, api.WithTrustedProxies([]*net.IPNet{
		{IP: net.ParseIP("192.168.1.0"), Mask: net.CIDRMask(24, 32)},
	}))

	req, err := http.NewRequest("GET", tb.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// The request should succeed (health check) — we're testing that the
	// middleware doesn't crash, and that the proxy filtering path is exercised.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// --- MaxBodyBytes for createUpdate ---

func TestMaxBodyBytes_CreateUpdate(t *testing.T) {
	tb := startBackend(t)
	rCreateStack(t, tb, "maxbody-proj", "maxbody-stack")

	// Create a body larger than 1MB (the MaxBodyBytes for createUpdate).
	largeBody := make([]byte, (1<<20)+1024) // ~1MB + 1KB
	for i := range largeBody {
		largeBody[i] = 'a'
	}

	req, err := http.NewRequest("POST",
		fmt.Sprintf("%s/api/stacks/%s/maxbody-proj/maxbody-stack/update", tb.URL, rOrg),
		bytes.NewReader(largeBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "token test-token")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// huma returns 413 when MaxBodyBytes is exceeded.
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 413, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestMaxBodyBytes_CompleteUpdate(t *testing.T) {
	tb := startBackend(t)
	rCreateStack(t, tb, "maxcomplete-proj", "maxcomplete-stack")
	updateID, _ := rCreateAndStartUpdate(t, tb, "maxcomplete-proj", "maxcomplete-stack", 0)

	// Create a body larger than 1MB for complete update.
	largeBody := make([]byte, (1<<20)+1024)
	for i := range largeBody {
		largeBody[i] = 'a'
	}

	req, err := http.NewRequest("POST",
		fmt.Sprintf("%s/api/stacks/%s/maxcomplete-proj/maxcomplete-stack/update/%s/complete",
			tb.URL, rOrg, updateID),
		bytes.NewReader(largeBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "token test-token")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 413, got %d: %s", resp.StatusCode, string(body))
	}
}

// --- Org Name Validation ---

func TestOrgNameValidation(t *testing.T) {
	tb := startBackend(t)

	// Attempt to create a stack with an invalid org name containing special characters.
	tests := []struct {
		name    string
		orgName string
	}{
		{"path-traversal", "../etc"},
		{"slash", "org/name"},
		{"spaces", "org name"},
		{"too-long", strings.Repeat("a", 101)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := tb.httpDo(t, "POST",
				fmt.Sprintf("/api/stacks/%s/test-proj", tc.orgName),
				map[string]string{"stackName": "test-stack"})
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
				t.Fatalf("expected rejection for org name %q, got %d", tc.orgName, resp.StatusCode)
			}
		})
	}
}

// --- Security Headers on Error Responses ---

func TestSecurityHeaders_OnErrors(t *testing.T) {
	tb := startBackend(t)

	// Make a request that triggers a 401 error and verify security headers are still set.
	req, err := http.NewRequest("GET", tb.URL+"/api/user", nil)
	if err != nil {
		t.Fatal(err)
	}
	// No Authorization header = 401.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}

	// Security headers should be present even on error responses.
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options on 401: got %q, want DENY", got)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options on 401: got %q, want nosniff", got)
	}
}

// --- Invalid Gzip Body ---

func TestInvalidGzipBody(t *testing.T) {
	tb := startBackend(t)

	// Send garbage with Content-Encoding: gzip.
	req, err := http.NewRequest("POST", tb.URL+"/api/stacks/organization/gzip-proj",
		bytes.NewReader([]byte("this is not gzip")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "token test-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 for invalid gzip, got %d: %s", resp.StatusCode, string(body))
	}
}
