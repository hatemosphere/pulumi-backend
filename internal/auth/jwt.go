package auth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// JWTConfig holds configuration for JWT authentication.
type JWTConfig struct {
	SigningKey    string // raw HMAC secret string OR path to PEM public key file
	Issuer        string // expected "iss" claim (empty = don't verify)
	Audience      string // expected "aud" claim (empty = don't verify)
	GroupsClaim   string // JWT claim name for groups (default: "groups")
	UsernameClaim string // JWT claim for username: "sub" or "email" (default: "sub")
}

// JWTAuthenticator validates JWT tokens and extracts user identity.
type JWTAuthenticator struct {
	config     JWTConfig
	parserOpts []jwt.ParserOption
	keyFunc    jwt.Keyfunc
}

// NewJWTAuthenticator creates a JWT authenticator with auto-detected key type.
// If signingKey is a path to a PEM file, RSA or ECDSA public key is used.
// Otherwise, the raw string is treated as an HMAC-SHA256 secret.
func NewJWTAuthenticator(config JWTConfig) (*JWTAuthenticator, error) {
	if config.SigningKey == "" {
		return nil, errors.New("jwt signing key is required")
	}
	if config.GroupsClaim == "" {
		config.GroupsClaim = "groups"
	}
	if config.UsernameClaim == "" {
		config.UsernameClaim = "sub"
	}

	signingKey, validMethods, err := parseSigningKey(config.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}

	keyFunc := func(token *jwt.Token) (any, error) {
		method := token.Method.Alg()
		for _, m := range validMethods {
			if method == m {
				return signingKey, nil
			}
		}
		return nil, fmt.Errorf("unexpected signing method: %s", method)
	}

	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods(validMethods),
		jwt.WithExpirationRequired(),
	}
	if config.Issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(config.Issuer))
	}
	if config.Audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(config.Audience))
	}

	return &JWTAuthenticator{
		config:     config,
		parserOpts: parserOpts,
		keyFunc:    keyFunc,
	}, nil
}

// parseSigningKey auto-detects the key type from the input.
// Returns the parsed key and the list of valid signing methods.
func parseSigningKey(input string) (any, []string, error) {
	// Check if input is a file path.
	info, err := os.Stat(input)
	if err == nil && !info.IsDir() {
		pemBytes, err := os.ReadFile(input)
		if err != nil {
			return nil, nil, fmt.Errorf("read PEM file: %w", err)
		}

		if key, err := jwt.ParseRSAPublicKeyFromPEM(pemBytes); err == nil {
			return key, []string{"RS256", "RS384", "RS512"}, nil
		}
		if key, err := jwt.ParseECPublicKeyFromPEM(pemBytes); err == nil {
			return key, []string{"ES256", "ES384", "ES512"}, nil
		}
		return nil, nil, errors.New("PEM file contains no recognized RSA or ECDSA public key")
	}

	// Treat as HMAC secret.
	return []byte(input), []string{"HS256", "HS384", "HS512"}, nil
}

// Validate parses and verifies a JWT token string, returning the extracted user identity.
func (a *JWTAuthenticator) Validate(tokenString string) (*UserIdentity, error) {
	token, err := jwt.Parse(tokenString, a.keyFunc, a.parserOpts...)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid JWT claims")
	}

	username, err := extractStringClaim(claims, a.config.UsernameClaim)
	if err != nil {
		return nil, fmt.Errorf("JWT missing %s claim: %w", a.config.UsernameClaim, err)
	}

	groups := extractGroupsClaim(claims, a.config.GroupsClaim)

	return &UserIdentity{
		UserName: username,
		Groups:   groups,
	}, nil
}

// extractStringClaim returns a string claim value, or an error if missing/empty.
func extractStringClaim(claims jwt.MapClaims, key string) (string, error) {
	v, ok := claims[key]
	if !ok {
		return "", fmt.Errorf("claim %q not found", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("claim %q is not a non-empty string", key)
	}
	return s, nil
}

// extractGroupsClaim flexibly extracts a groups claim from the JWT.
// Handles []interface{} (standard), comma-separated string, or absent claim.
func extractGroupsClaim(claims jwt.MapClaims, key string) []string {
	v, ok := claims[key]
	if !ok {
		return nil
	}

	switch val := v.(type) {
	case []any:
		groups := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok && s != "" {
				groups = append(groups, s)
			}
		}
		if len(groups) == 0 {
			return nil
		}
		return groups
	case string:
		if val == "" {
			return nil
		}
		parts := strings.Split(val, ",")
		groups := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				groups = append(groups, p)
			}
		}
		if len(groups) == 0 {
			return nil
		}
		return groups
	default:
		return nil
	}
}

// Ensure key types are used (avoid import cycle warnings).
var (
	_ *rsa.PublicKey   // used by parseSigningKey
	_ *ecdsa.PublicKey // used by parseSigningKey
)
