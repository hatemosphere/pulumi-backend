package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// SecretsEngine handles encryption/decryption of stack secrets using AES-256-GCM.
// Each stack gets its own data encryption key (DEK), which is itself encrypted
// with the server's master key (KEK).
type SecretsEngine struct {
	masterKey []byte // 32 bytes for AES-256
}

// NewSecretsEngine creates a new secrets engine with the given master key.
func NewSecretsEngine(masterKey []byte) (*SecretsEngine, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be exactly 32 bytes, got %d", len(masterKey))
	}
	return &SecretsEngine{masterKey: masterKey}, nil
}

// GenerateStackKey generates a new per-stack encryption key and returns both
// the raw key and the master-key-encrypted version for storage.
func (s *SecretsEngine) GenerateStackKey() (rawKey, encryptedKey []byte, err error) {
	rawKey = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rawKey); err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	encryptedKey, err = s.encryptWithMaster(rawKey)
	if err != nil {
		return nil, nil, err
	}
	return rawKey, encryptedKey, nil
}

// DecryptKey decrypts a master-key-encrypted stack key.
func (s *SecretsEngine) DecryptKey(encryptedKey []byte) ([]byte, error) {
	return s.decryptWithMaster(encryptedKey)
}

// Encrypt encrypts plaintext using the given stack key.
func (s *SecretsEngine) Encrypt(stackKey, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(stackKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	// Return base64-encoded for JSON transport.
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(encoded, ciphertext)
	return encoded, nil
}

// Decrypt decrypts ciphertext using the given stack key.
func (s *SecretsEngine) Decrypt(stackKey, ciphertext []byte) ([]byte, error) {
	// Decode base64.
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(ciphertext)))
	n, err := base64.StdEncoding.Decode(decoded, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	decoded = decoded[:n]

	block, err := aes.NewCipher(stackKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(decoded) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := decoded[:nonceSize], decoded[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

func (s *SecretsEngine) encryptWithMaster(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *SecretsEngine) decryptWithMaster(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}
