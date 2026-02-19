package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	// TokenPrefix is prepended to all generated backend tokens.
	TokenPrefix = "pul-"
	// tokenRandBytes is the number of random bytes in a token (32 bytes = 64 hex chars).
	tokenRandBytes = 32
)

// GenerateToken creates a new random access token with the "pul-" prefix.
// Format: "pul-" + 64 hex chars = 68 char token.
func GenerateToken() (string, error) {
	b := make([]byte, tokenRandBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return TokenPrefix + hex.EncodeToString(b), nil
}

// HashToken returns the SHA-256 hex digest of a token string.
// This hash is used as the primary key in the tokens table.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
