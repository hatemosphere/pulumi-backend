package auth

import (
	"strings"
	"testing"
)

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(token, TokenPrefix) {
		t.Fatalf("expected prefix %q, got %q", TokenPrefix, token[:4])
	}

	// "pul-" (4) + 64 hex chars = 68
	if len(token) != 68 {
		t.Fatalf("expected token length 68, got %d", len(token))
	}
}

func TestGenerateToken_Unique(t *testing.T) {
	t1, _ := GenerateToken()
	t2, _ := GenerateToken()
	if t1 == t2 {
		t.Fatal("two generated tokens should not be equal")
	}
}

func TestHashToken(t *testing.T) {
	token := "pul-abc123"
	hash := HashToken(token)

	// SHA-256 produces 64 hex chars.
	if len(hash) != 64 {
		t.Fatalf("expected hash length 64, got %d", len(hash))
	}

	// Deterministic.
	if HashToken(token) != hash {
		t.Fatal("hash should be deterministic")
	}

	// Different input → different hash.
	if HashToken("pul-xyz789") == hash {
		t.Fatal("different tokens should produce different hashes")
	}
}
