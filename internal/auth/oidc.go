package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig holds configuration for OIDC authentication.
type OIDCConfig struct {
	ClientID       string
	AllowedDomains []string
	TokenTTL       time.Duration
	ProviderName   string   // display name for login UI (e.g. "Google", "Okta", "SSO")
	Scopes         []string // additional scopes beyond "openid" (default: ["profile", "email"])
	UsernameClaim  string   // claim key for username (default: "email")
	GroupsClaim    string   // claim key for groups (default: "groups")
}

func (c OIDCConfig) scopes() []string {
	scopes := []string{oidc.ScopeOpenID}
	if len(c.Scopes) > 0 {
		scopes = append(scopes, c.Scopes...)
	} else {
		scopes = append(scopes, "profile", "email")
	}
	return scopes
}

func (c OIDCConfig) usernameClaim() string {
	if c.UsernameClaim != "" {
		return c.UsernameClaim
	}
	return "email"
}

func (c OIDCConfig) groupsClaim() string {
	if c.GroupsClaim != "" {
		return c.GroupsClaim
	}
	return "groups"
}

// OIDCAuthResult is returned after successful token exchange.
type OIDCAuthResult struct {
	Token     string //nolint:gosec // not a credential, it's the field name
	TokenHash string
	UserName  string
	Groups    []string
	ExpiresAt time.Time
}

// CodeExchangeResult contains tokens from an authorization code exchange.
type CodeExchangeResult struct {
	IDToken      string
	RefreshToken string //nolint:gosec // field name, not a credential
}

// OIDCAuthenticator abstracts OIDC authentication flows.
type OIDCAuthenticator interface {
	// Exchange validates a raw ID token and returns a backend auth result.
	Exchange(ctx context.Context, rawIDToken string) (*OIDCAuthResult, error)
	// Revalidate uses a stored refresh token to verify the user is still active.
	Revalidate(ctx context.Context, refreshToken string) error
	// AuthCodeURL builds the provider's authorization URL for browser/CLI login.
	// Returns the URL and a crypto-random nonce that must be stored and validated
	// in ExchangeCode to prevent ID token replay attacks.
	AuthCodeURL(redirectURI, state string) (authURL, nonce string)
	// ExchangeCode exchanges an authorization code for tokens.
	// expectedNonce is the nonce returned by AuthCodeURL; it is verified against
	// the "nonce" claim in the ID token.
	ExchangeCode(ctx context.Context, code, redirectURI, expectedNonce string) (*CodeExchangeResult, error)
	// Config returns the authenticator's configuration.
	Config() OIDCConfig
}

// domainCheckFunc validates the user's domain from claims and email.
type domainCheckFunc func(claims map[string]any, email string) error

// oidcAuthenticator is the production implementation using go-oidc/v3 + oauth2.
type oidcAuthenticator struct {
	config        OIDCConfig
	verifier      oidcVerifier
	oauth2Config  oauth2.Config
	groupsCache   *GroupsCache
	domainCheck   domainCheckFunc
	testRefresher TestOIDCRefresher // non-nil only in tests
}

// oidcVerifier abstracts ID token verification for both production and tests.
type oidcVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (claims map[string]any, err error)
}

// goOIDCVerifier wraps go-oidc's IDTokenVerifier.
type goOIDCVerifier struct {
	verifier *oidc.IDTokenVerifier
}

func (v *goOIDCVerifier) Verify(ctx context.Context, rawIDToken string) (map[string]any, error) {
	token, err := v.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extract claims: %w", err)
	}
	return claims, nil
}

// NewOIDCAuthenticator creates a generic OIDC authenticator using go-oidc discovery.
func NewOIDCAuthenticator(ctx context.Context, config OIDCConfig, issuer, clientSecret string, groupsCache *GroupsCache) (OIDCAuthenticator, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", issuer, err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	oauth2Cfg := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.scopes(),
	}

	goVerifier := &goOIDCVerifier{verifier: verifier}

	a := &oidcAuthenticator{
		config:       config,
		verifier:     goVerifier,
		oauth2Config: oauth2Cfg,
		groupsCache:  groupsCache,
		domainCheck:  emailDomainCheck(config.AllowedDomains),
	}

	return a, nil
}

// NewGoogleOIDCAuthenticator creates a Google-flavored OIDC authenticator.
// Issuer is hardcoded to accounts.google.com; domain check uses the "hd" claim.
func NewGoogleOIDCAuthenticator(ctx context.Context, config OIDCConfig, clientSecret string, groupsCache *GroupsCache) (OIDCAuthenticator, error) {
	if config.ProviderName == "" {
		config.ProviderName = "Google"
	}
	a, err := NewOIDCAuthenticator(ctx, config, "https://accounts.google.com", clientSecret, groupsCache)
	if err != nil {
		return nil, err
	}
	// Override domain check to use Google's "hd" claim.
	a.(*oidcAuthenticator).domainCheck = googleHDDomainCheck(config.AllowedDomains)
	return a, nil
}

// TestOIDCValidator abstracts ID token verification for tests.
type TestOIDCValidator interface {
	Verify(ctx context.Context, rawIDToken string) (claims map[string]any, err error)
}

// TestOIDCRefresher abstracts token refresh for tests.
type TestOIDCRefresher interface {
	Refresh(ctx context.Context, refreshToken string) (newIDToken string, err error)
}

// NewTestOIDCAuthenticator creates an authenticator with injected mocks for testing.
// Uses Google endpoints by default so login page/CLI redirect tests work.
func NewTestOIDCAuthenticator(config OIDCConfig, groupsCache *GroupsCache, validator TestOIDCValidator, refresher TestOIDCRefresher) OIDCAuthenticator {
	a := &oidcAuthenticator{
		config:      config,
		verifier:    validator,
		groupsCache: groupsCache,
		domainCheck: googleHDDomainCheck(config.AllowedDomains),
		oauth2Config: oauth2.Config{
			ClientID: config.ClientID,
			Endpoint: oauth2.Endpoint{ //nolint:gosec // test-only Google endpoints, not credentials
				AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
			Scopes: config.scopes(),
		},
	}
	if refresher != nil {
		a.testRefresher = refresher
	}
	return a
}

// Exchange validates a raw ID token and returns an auth result with a
// backend-issued access token.
func (a *oidcAuthenticator) Exchange(ctx context.Context, rawIDToken string) (*OIDCAuthResult, error) {
	claims, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("invalid ID token: %w", err)
	}

	// Extract username (default: email).
	username, _ := claims[a.config.usernameClaim()].(string)
	if username == "" {
		return nil, fmt.Errorf("ID token missing %s claim", a.config.usernameClaim())
	}

	// Check email_verified if present.
	if emailVerified, ok := claims["email_verified"]; ok {
		if verified, isBool := emailVerified.(bool); isBool && !verified {
			slog.Warn("Login rejected: email not verified", "email", username)
			return nil, errors.New("email not verified")
		}
	}

	// Validate domain.
	if a.domainCheck != nil {
		if err := a.domainCheck(claims, username); err != nil {
			slog.Warn("Login rejected: domain check failed", "email", username, "error", err)
			return nil, err
		}
	}

	slog.Debug("OIDC ID token validated", "email", username, "provider", a.config.ProviderName)

	// Resolve groups: prefer external resolver (e.g. Google Admin SDK), fall back to token claims.
	var groups []string
	if a.groupsCache != nil {
		groups, err = a.groupsCache.ResolveGroups(ctx, username)
		if err != nil {
			return nil, fmt.Errorf("resolve groups for %s: %w", username, err)
		}
	} else {
		groups = extractGroupsFromClaims(claims, a.config.groupsClaim())
	}

	// Generate backend access token.
	token, err := GenerateToken()
	if err != nil {
		return nil, err
	}

	return &OIDCAuthResult{
		Token:     token,
		TokenHash: HashToken(token),
		UserName:  username,
		Groups:    groups,
		ExpiresAt: time.Now().Add(a.config.TokenTTL),
	}, nil
}

// Revalidate uses a stored refresh token to verify the user is still active.
func (a *oidcAuthenticator) Revalidate(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return errors.New("no refresh token available")
	}

	var newIDToken string
	var err error

	if a.testRefresher != nil {
		// Test path: use injected refresher.
		newIDToken, err = a.testRefresher.Refresh(ctx, refreshToken)
	} else {
		// Production path: use oauth2 token source.
		t := &oauth2.Token{
			RefreshToken: refreshToken,
			Expiry:       time.Now().Add(-time.Hour),
		}
		newToken, tokenErr := a.oauth2Config.TokenSource(ctx, t).Token()
		if tokenErr != nil {
			return fmt.Errorf("refresh rejected: %w", tokenErr)
		}
		idTokenRaw, ok := newToken.Extra("id_token").(string)
		if !ok || idTokenRaw == "" {
			return errors.New("no id_token in refresh response")
		}
		newIDToken = idTokenRaw
		err = nil
	}

	if err != nil {
		return fmt.Errorf("refresh rejected: %w", err)
	}

	// Validate the new ID token to confirm the account is still active.
	_, err = a.verifier.Verify(ctx, newIDToken)
	if err != nil {
		return fmt.Errorf("refreshed ID token invalid: %w", err)
	}

	return nil
}

// AuthCodeURL builds the provider's authorization URL for browser/CLI login.
// Generates a crypto-random nonce and includes it in the auth request. The
// caller must store the nonce and pass it to ExchangeCode for validation.
func (a *oidcAuthenticator) AuthCodeURL(redirectURI, state string) (string, string) {
	nonce := generateOIDCNonce()
	cfg := a.oauth2Config
	cfg.RedirectURL = redirectURI
	url := cfg.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "select_account"),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
	return url, nonce
}

// generateOIDCNonce generates a 32-byte crypto-random hex nonce.
func generateOIDCNonce() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// This should never fail; if it does, the auth flow will fail at nonce validation.
		return ""
	}
	return hex.EncodeToString(b)
}

// ExchangeCode exchanges an authorization code for tokens and validates the
// OIDC nonce claim against the expected value to prevent ID token replay.
func (a *oidcAuthenticator) ExchangeCode(ctx context.Context, code, redirectURI, expectedNonce string) (*CodeExchangeResult, error) {
	cfg := a.oauth2Config
	cfg.RedirectURL = redirectURI

	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		return nil, errors.New("no id_token in code exchange response")
	}

	// Validate nonce in the ID token to prevent replay attacks.
	if expectedNonce != "" {
		claims, err := a.verifier.Verify(ctx, idToken)
		if err != nil {
			return nil, fmt.Errorf("nonce verification: ID token invalid: %w", err)
		}
		tokenNonce, _ := claims["nonce"].(string)
		if tokenNonce == "" {
			return nil, errors.New("ID token missing nonce claim")
		}
		if subtle.ConstantTimeCompare([]byte(expectedNonce), []byte(tokenNonce)) != 1 {
			return nil, errors.New("ID token nonce mismatch")
		}
	}

	return &CodeExchangeResult{
		IDToken:      idToken,
		RefreshToken: token.RefreshToken,
	}, nil
}

// Config returns the authenticator's configuration.
func (a *oidcAuthenticator) Config() OIDCConfig {
	return a.config
}

// --- Domain check strategies ---

// emailDomainCheck validates the email domain suffix against allowed domains.
// Used for generic OIDC providers.
func emailDomainCheck(allowedDomains []string) domainCheckFunc {
	if len(allowedDomains) == 0 {
		return nil
	}
	return func(_ map[string]any, email string) error {
		parts := strings.SplitN(email, "@", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid email format: %s", email)
		}
		domain := parts[1]
		for _, d := range allowedDomains {
			if strings.EqualFold(d, domain) {
				return nil
			}
		}
		return fmt.Errorf("domain %q not in allowed domains", domain)
	}
}

// googleHDDomainCheck validates the Google "hd" (hosted domain) claim.
func googleHDDomainCheck(allowedDomains []string) domainCheckFunc {
	if len(allowedDomains) == 0 {
		return nil
	}
	return func(claims map[string]any, _ string) error {
		hd, _ := claims["hd"].(string)
		for _, d := range allowedDomains {
			if strings.EqualFold(d, hd) {
				return nil
			}
		}
		return fmt.Errorf("domain %q not in allowed domains", hd)
	}
}

// --- Claim extraction ---

// extractGroupsFromClaims extracts group names from a claims map.
// Handles []interface{} (standard), []string, and string (single group).
func extractGroupsFromClaims(claims map[string]any, claimKey string) []string {
	raw, ok := claims[claimKey]
	if !ok {
		return nil
	}

	switch v := raw.(type) {
	case []any:
		groups := make([]string, 0, len(v))
		for _, item := range v {
			switch g := item.(type) {
			case string:
				groups = append(groups, g)
			case map[string]any:
				// Keycloak-style: {"name": "group-name"}
				if name, ok := g["name"].(string); ok {
					groups = append(groups, name)
				}
			}
		}
		return groups
	case []string:
		return v
	case string:
		return []string{v}
	default:
		return nil
	}
}
