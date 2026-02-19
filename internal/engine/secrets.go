package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// SecretsEngine handles encryption/decryption of stack secrets using AES-256-GCM.
// Each stack gets its own data encryption key (DEK), which is itself encrypted
// via the configured SecretsProvider (local master key or GCP KMS).
type SecretsEngine struct {
	provider SecretsProvider
}

// NewSecretsEngine creates a new secrets engine backed by the given provider.
func NewSecretsEngine(provider SecretsProvider) *SecretsEngine {
	return &SecretsEngine{provider: provider}
}

// GenerateStackKey generates a new per-stack encryption key and returns both
// the raw key and the provider-encrypted version for storage.
func (s *SecretsEngine) GenerateStackKey(ctx context.Context) (rawKey, encryptedKey []byte, err error) {
	rawKey = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rawKey); err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	encryptedKey, err = s.provider.WrapKey(ctx, rawKey)
	if err != nil {
		return nil, nil, err
	}
	return rawKey, encryptedKey, nil
}

// DecryptKey decrypts a provider-encrypted stack key.
func (s *SecretsEngine) DecryptKey(ctx context.Context, encryptedKey []byte) ([]byte, error) {
	return s.provider.UnwrapKey(ctx, encryptedKey)
}

// Encrypt encrypts plaintext using the given stack key.
// Returns base64-encoded ciphertext for JSON transport.
func (s *SecretsEngine) Encrypt(stackKey, plaintext []byte) ([]byte, error) {
	raw, err := aesGCMSeal(stackKey, plaintext)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(encoded, raw)
	return encoded, nil
}

// Decrypt decrypts base64-encoded ciphertext using the given stack key.
func (s *SecretsEngine) Decrypt(stackKey, ciphertext []byte) ([]byte, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(ciphertext)))
	n, err := base64.StdEncoding.Decode(decoded, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return aesGCMOpen(stackKey, decoded[:n])
}
