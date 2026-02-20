package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/api/idtoken"
)

// IDTokenValidator abstracts Google ID token verification for testing.
// The production implementation delegates to idtoken.Validate; tests can
// inject a mock that verifies JWTs signed with a test key.
type IDTokenValidator interface {
	Validate(ctx context.Context, idToken string, audience string) (*idtoken.Payload, error)
}

// googleValidator wraps the package-level idtoken.Validate function.
type googleValidator struct{}

func (googleValidator) Validate(ctx context.Context, idToken, audience string) (*idtoken.Payload, error) {
	return idtoken.Validate(ctx, idToken, audience)
}

// GoogleAuthConfig holds configuration for Google OIDC authentication.
type GoogleAuthConfig struct {
	ClientID       string   // Google OAuth2 client ID for JWT audience verification
	AllowedDomains []string // Allowed hosted domains (empty = allow all)
	TokenTTL       time.Duration
}

// GoogleAuthResult is returned after successful token exchange.
type GoogleAuthResult struct {
	Token     string //nolint:gosec // not a credential, it's the field name
	TokenHash string
	UserName  string   // email from the ID token
	Groups    []string // resolved group memberships
	ExpiresAt time.Time
}

// TokenRefresher abstracts Google OAuth2 refresh token exchange for testing.
// The production implementation calls Google's token endpoint; tests can inject
// a mock that simulates token refresh success/failure.
type TokenRefresher interface {
	// RefreshToken exchanges a Google refresh token for a new ID token.
	// Returns the new ID token string, or an error if the refresh was rejected
	// (e.g. user deactivated, consent revoked).
	RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret string) (idToken string, err error)
}

// googleTokenRefresher is the production implementation that calls Google's token endpoint.
type googleTokenRefresher struct{}

func (googleTokenRefresher) RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret string) (string, error) {
	data := url.Values{
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"grant_type":    {"refresh_token"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://oauth2.googleapis.com/token",
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // URL is constant Google endpoint
	if err != nil {
		return "", fmt.Errorf("refresh request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("google rejected refresh token (status %d): %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		IDToken string `json:"id_token"` //nolint:tagliatelle // Google API naming
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parse refresh response: %w", err)
	}
	if tokenResp.IDToken == "" {
		return "", errors.New("no id_token in refresh response")
	}
	return tokenResp.IDToken, nil
}

// GoogleAuthenticator verifies Google ID tokens and resolves group memberships.
type GoogleAuthenticator struct {
	config      GoogleAuthConfig
	groupsCache *GroupsCache     // nil if groups resolution is not configured
	validator   IDTokenValidator // production: googleValidator; tests: mock
	refresher   TokenRefresher   // production: googleTokenRefresher; tests: mock
}

// NewGoogleAuthenticator creates an authenticator for Google ID token exchange.
// Uses the real Google JWKS for token verification and Google's token endpoint for refresh.
func NewGoogleAuthenticator(config GoogleAuthConfig, groupsCache *GroupsCache) *GoogleAuthenticator {
	return &GoogleAuthenticator{
		config:      config,
		groupsCache: groupsCache,
		validator:   googleValidator{},
		refresher:   googleTokenRefresher{},
	}
}

// NewGoogleAuthenticatorWithValidator creates an authenticator with custom
// token validator and refresher. Used in tests to inject mocks.
func NewGoogleAuthenticatorWithValidator(config GoogleAuthConfig, groupsCache *GroupsCache, validator IDTokenValidator, refresher TokenRefresher) *GoogleAuthenticator {
	a := &GoogleAuthenticator{
		config:      config,
		groupsCache: groupsCache,
		validator:   validator,
		refresher:   googleTokenRefresher{},
	}
	if refresher != nil {
		a.refresher = refresher
	}
	return a
}

// Exchange verifies a Google ID token and returns an auth result with a
// backend-issued access token. The caller is responsible for persisting the
// token in the database.
func (a *GoogleAuthenticator) Exchange(ctx context.Context, rawIDToken string) (*GoogleAuthResult, error) {
	// Verify the ID token signature and claims against the configured client ID.
	payload, err := a.validator.Validate(ctx, rawIDToken, a.config.ClientID)
	if err != nil {
		return nil, fmt.Errorf("invalid ID token: %w", err)
	}

	// Extract email claim.
	email, ok := payload.Claims["email"].(string)
	if !ok || email == "" {
		return nil, errors.New("ID token missing email claim")
	}

	emailVerified, _ := payload.Claims["email_verified"].(bool)
	if !emailVerified {
		slog.Warn("Login rejected: email not verified", "email", email)
		return nil, errors.New("email not verified")
	}

	// Validate hosted domain if configured.
	if len(a.config.AllowedDomains) > 0 {
		hd, _ := payload.Claims["hd"].(string)
		if !a.isDomainAllowed(hd) {
			slog.Warn("Login rejected: domain not allowed", "email", email, "domain", hd, "allowed_domains", a.config.AllowedDomains)
			return nil, fmt.Errorf("domain %q not in allowed domains", hd)
		}
	}

	slog.Debug("Google ID token validated successfully", "email", email)

	// Resolve group memberships.
	var groups []string
	if a.groupsCache != nil {
		groups, err = a.groupsCache.ResolveGroups(ctx, email)
		if err != nil {
			return nil, fmt.Errorf("resolve groups for %s: %w", email, err)
		}
	}

	// Generate backend access token.
	token, err := GenerateToken()
	if err != nil {
		return nil, err
	}

	return &GoogleAuthResult{
		Token:     token,
		TokenHash: HashToken(token),
		UserName:  email,
		Groups:    groups,
		ExpiresAt: time.Now().Add(a.config.TokenTTL),
	}, nil
}

// Revalidate uses a stored Google refresh token to verify the user is still
// active in Google Workspace. It exchanges the refresh token for a new ID token
// and validates it. Returns nil if the user is still valid, or an error if the
// user has been deactivated or their consent was revoked.
//
// This follows the same pattern as Dex's Google connector: on each token use,
// attempt to refresh against Google to verify the account is still active.
func (a *GoogleAuthenticator) Revalidate(ctx context.Context, refreshToken, clientSecret string) error {
	if refreshToken == "" {
		return errors.New("no refresh token available")
	}

	// Exchange the refresh token for a new ID token via Google's token endpoint.
	newIDToken, err := a.refresher.RefreshToken(ctx, refreshToken, a.config.ClientID, clientSecret)
	if err != nil {
		return fmt.Errorf("google rejected refresh: %w", err)
	}

	// Validate the new ID token to confirm the account is still active.
	_, err = a.validator.Validate(ctx, newIDToken, a.config.ClientID)
	if err != nil {
		return fmt.Errorf("refreshed ID token invalid: %w", err)
	}

	return nil
}

// Config returns the authenticator's configuration.
func (a *GoogleAuthenticator) Config() GoogleAuthConfig {
	return a.config
}

func (a *GoogleAuthenticator) isDomainAllowed(hd string) bool {
	for _, d := range a.config.AllowedDomains {
		if strings.EqualFold(d, hd) {
			return true
		}
	}
	return false
}
