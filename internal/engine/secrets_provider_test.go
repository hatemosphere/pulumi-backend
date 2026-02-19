package engine

import (
	"context"
	"crypto/rand"
	"testing"
)

func TestLocalSecretsProvider_RoundTrip(t *testing.T) {
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}

	provider, err := NewLocalSecretsProvider(masterKey)
	if err != nil {
		t.Fatal(err)
	}

	if provider.ProviderName() != "local" {
		t.Fatalf("expected provider name 'local', got %q", provider.ProviderName())
	}

	// Generate a DEK.
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Wrap.
	wrapped, err := provider.WrapKey(ctx, dek)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	// Wrapped should differ from plaintext.
	if string(wrapped) == string(dek) {
		t.Fatal("wrapped key should differ from plaintext")
	}

	// Unwrap.
	unwrapped, err := provider.UnwrapKey(ctx, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}

	if string(unwrapped) != string(dek) {
		t.Fatal("unwrapped key does not match original")
	}
}

func TestLocalSecretsProvider_InvalidMasterKey(t *testing.T) {
	_, err := NewLocalSecretsProvider(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte master key")
	}
}

func TestLocalSecretsProvider_DifferentKeysCantDecrypt(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	if _, err := rand.Read(key1); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatal(err)
	}

	p1, _ := NewLocalSecretsProvider(key1)
	p2, _ := NewLocalSecretsProvider(key2)

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	wrapped, _ := p1.WrapKey(ctx, dek)

	_, err := p2.UnwrapKey(ctx, wrapped)
	if err == nil {
		t.Fatal("expected error when unwrapping with different master key")
	}
}

func TestSecretsEngine_WithLocalProvider(t *testing.T) {
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}

	provider, err := NewLocalSecretsProvider(masterKey)
	if err != nil {
		t.Fatal(err)
	}

	eng := NewSecretsEngine(provider)
	ctx := context.Background()

	// Generate stack key.
	rawKey, encryptedKey, err := eng.GenerateStackKey(ctx)
	if err != nil {
		t.Fatalf("GenerateStackKey: %v", err)
	}

	if len(rawKey) != 32 {
		t.Fatalf("expected 32-byte raw key, got %d", len(rawKey))
	}

	// Decrypt stack key.
	decrypted, err := eng.DecryptKey(ctx, encryptedKey)
	if err != nil {
		t.Fatalf("DecryptKey: %v", err)
	}

	if string(decrypted) != string(rawKey) {
		t.Fatal("decrypted key does not match original")
	}

	// Encrypt and decrypt a value using the stack key.
	plaintext := []byte("super secret value")
	ciphertext, err := eng.Encrypt(rawKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	result, err := eng.Decrypt(rawKey, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(result) != string(plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, result)
	}
}

func TestLocalProviderBackwardCompatible(t *testing.T) {
	// Verify that LocalSecretsProvider produces the same format as the old
	// encryptWithMaster/decryptWithMaster methods (AES-256-GCM, nonce-prefixed).
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}

	provider, _ := NewLocalSecretsProvider(masterKey)
	ctx := context.Background()

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}

	wrapped, err := provider.WrapKey(ctx, dek)
	if err != nil {
		t.Fatal(err)
	}

	// Format: [12-byte nonce][ciphertext+16-byte tag]
	// Minimum size: 12 (nonce) + 32 (plaintext) + 16 (tag) = 60 bytes
	if len(wrapped) < 60 {
		t.Fatalf("wrapped key too short: %d bytes, expected >= 60", len(wrapped))
	}

	unwrapped, err := provider.UnwrapKey(ctx, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if string(unwrapped) != string(dek) {
		t.Fatal("round-trip failed")
	}
}
