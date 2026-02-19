package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/idtoken"
)

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

// GoogleAuthenticator verifies Google ID tokens and resolves group memberships.
type GoogleAuthenticator struct {
	config      GoogleAuthConfig
	groupsCache *GroupsCache // nil if groups resolution is not configured
}

// NewGoogleAuthenticator creates an authenticator for Google ID token exchange.
func NewGoogleAuthenticator(config GoogleAuthConfig, groupsCache *GroupsCache) *GoogleAuthenticator {
	return &GoogleAuthenticator{
		config:      config,
		groupsCache: groupsCache,
	}
}

// Exchange verifies a Google ID token and returns an auth result with a
// backend-issued access token. The caller is responsible for persisting the
// token in the database.
func (a *GoogleAuthenticator) Exchange(ctx context.Context, rawIDToken string) (*GoogleAuthResult, error) {
	// Verify the ID token signature and claims against the configured client ID.
	payload, err := idtoken.Validate(ctx, rawIDToken, a.config.ClientID)
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
		return nil, errors.New("email not verified")
	}

	// Validate hosted domain if configured.
	if len(a.config.AllowedDomains) > 0 {
		hd, _ := payload.Claims["hd"].(string)
		if !a.isDomainAllowed(hd) {
			return nil, fmt.Errorf("domain %q not in allowed domains", hd)
		}
	}

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

func (a *GoogleAuthenticator) isDomainAllowed(hd string) bool {
	for _, d := range a.config.AllowedDomains {
		if strings.EqualFold(d, hd) {
			return true
		}
	}
	return false
}
