package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// helper: sign a JWT with the given method and key, merging claims with default exp.
func signJWT(t *testing.T, method jwt.SigningMethod, key any, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = jwt.NewNumericDate(time.Now().Add(time.Hour))
	}
	token := jwt.NewWithClaims(method, claims)
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return s
}

// helper: write PEM-encoded key to a temp file.
func writePEM(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestJWT_HMAC_Valid(t *testing.T) {
	secret := "my-test-secret-key-1234567890"
	auth, err := NewJWTAuthenticator(JWTConfig{SigningKey: secret})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodHS256, []byte(secret), jwt.MapClaims{
		"sub":    "alice@example.com",
		"groups": []any{"devs", "admins"},
	})

	id, err := auth.Validate(tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserName != "alice@example.com" {
		t.Errorf("expected alice@example.com, got %s", id.UserName)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "devs" || id.Groups[1] != "admins" {
		t.Errorf("unexpected groups: %v", id.Groups)
	}
	if id.IsAdmin {
		t.Error("JWT users should not be admin by default")
	}
}

func TestJWT_RSA_Valid(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemPath := writePEM(t, dir, "rsa.pub", "PUBLIC KEY", pubDER)

	auth, err := NewJWTAuthenticator(JWTConfig{SigningKey: pemPath})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodRS256, privKey, jwt.MapClaims{
		"sub": "bob@example.com",
	})

	id, err := auth.Validate(tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserName != "bob@example.com" {
		t.Errorf("expected bob@example.com, got %s", id.UserName)
	}
}

func TestJWT_ECDSA_Valid(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemPath := writePEM(t, dir, "ec.pub", "PUBLIC KEY", pubDER)

	auth, err := NewJWTAuthenticator(JWTConfig{SigningKey: pemPath})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodES256, privKey, jwt.MapClaims{
		"sub": "carol@example.com",
	})

	id, err := auth.Validate(tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserName != "carol@example.com" {
		t.Errorf("expected carol@example.com, got %s", id.UserName)
	}
}

func TestJWT_ExpiredToken(t *testing.T) {
	secret := "test-secret"
	auth, err := NewJWTAuthenticator(JWTConfig{SigningKey: secret})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodHS256, []byte(secret), jwt.MapClaims{
		"sub": "user",
		"exp": jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	})

	_, err = auth.Validate(tok)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestJWT_MissingExp(t *testing.T) {
	secret := "test-secret"
	auth, err := NewJWTAuthenticator(JWTConfig{SigningKey: secret})
	if err != nil {
		t.Fatal(err)
	}

	// Sign without exp claim.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user"})
	tok, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.Validate(tok)
	if err == nil {
		t.Fatal("expected error for missing exp")
	}
}

func TestJWT_WrongSignature(t *testing.T) {
	auth, err := NewJWTAuthenticator(JWTConfig{SigningKey: "correct-key"})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodHS256, []byte("wrong-key"), jwt.MapClaims{
		"sub": "user",
	})

	_, err = auth.Validate(tok)
	if err == nil {
		t.Fatal("expected error for wrong signature")
	}
}

func TestJWT_WrongAudience(t *testing.T) {
	secret := "test-secret"
	auth, err := NewJWTAuthenticator(JWTConfig{
		SigningKey: secret,
		Audience:   "expected-audience",
	})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodHS256, []byte(secret), jwt.MapClaims{
		"sub": "user",
		"aud": "wrong-audience",
	})

	_, err = auth.Validate(tok)
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestJWT_WrongIssuer(t *testing.T) {
	secret := "test-secret"
	auth, err := NewJWTAuthenticator(JWTConfig{
		SigningKey: secret,
		Issuer:     "expected-issuer",
	})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodHS256, []byte(secret), jwt.MapClaims{
		"sub": "user",
		"iss": "wrong-issuer",
	})

	_, err = auth.Validate(tok)
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestJWT_MissingSub(t *testing.T) {
	secret := "test-secret"
	auth, err := NewJWTAuthenticator(JWTConfig{SigningKey: secret})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodHS256, []byte(secret), jwt.MapClaims{
		"name": "user",
	})

	_, err = auth.Validate(tok)
	if err == nil {
		t.Fatal("expected error for missing sub claim")
	}
}

func TestJWT_EmailClaim(t *testing.T) {
	secret := "test-secret"
	auth, err := NewJWTAuthenticator(JWTConfig{
		SigningKey:    secret,
		UsernameClaim: "email",
	})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodHS256, []byte(secret), jwt.MapClaims{
		"sub":   "user-id-123",
		"email": "user@example.com",
	})

	id, err := auth.Validate(tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserName != "user@example.com" {
		t.Errorf("expected user@example.com, got %s", id.UserName)
	}
}

func TestJWT_GroupsAsArray(t *testing.T) {
	secret := "test-secret"
	auth, err := NewJWTAuthenticator(JWTConfig{SigningKey: secret})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodHS256, []byte(secret), jwt.MapClaims{
		"sub":    "user",
		"groups": []any{"a", "b", "c"},
	})

	id, err := auth.Validate(tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(id.Groups) != 3 || id.Groups[0] != "a" || id.Groups[1] != "b" || id.Groups[2] != "c" {
		t.Errorf("unexpected groups: %v", id.Groups)
	}
}

func TestJWT_GroupsAsCommaSeparatedString(t *testing.T) {
	secret := "test-secret"
	auth, err := NewJWTAuthenticator(JWTConfig{SigningKey: secret})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodHS256, []byte(secret), jwt.MapClaims{
		"sub":    "user",
		"groups": "devs, admins, ops",
	})

	id, err := auth.Validate(tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(id.Groups) != 3 || id.Groups[0] != "devs" || id.Groups[1] != "admins" || id.Groups[2] != "ops" {
		t.Errorf("unexpected groups: %v", id.Groups)
	}
}

func TestJWT_GroupsAbsent(t *testing.T) {
	secret := "test-secret"
	auth, err := NewJWTAuthenticator(JWTConfig{SigningKey: secret})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodHS256, []byte(secret), jwt.MapClaims{
		"sub": "user",
	})

	id, err := auth.Validate(tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Groups != nil {
		t.Errorf("expected nil groups, got %v", id.Groups)
	}
}

func TestJWT_CustomGroupsClaim(t *testing.T) {
	secret := "test-secret"
	auth, err := NewJWTAuthenticator(JWTConfig{
		SigningKey:  secret,
		GroupsClaim: "roles",
	})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodHS256, []byte(secret), jwt.MapClaims{
		"sub":   "user",
		"roles": []any{"editor", "viewer"},
	})

	id, err := auth.Validate(tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "editor" || id.Groups[1] != "viewer" {
		t.Errorf("unexpected groups: %v", id.Groups)
	}
}

func TestJWT_AlgorithmMismatch_HMAC_vs_RSA(t *testing.T) {
	// Create RSA authenticator.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemPath := writePEM(t, dir, "rsa.pub", "PUBLIC KEY", pubDER)

	auth, err := NewJWTAuthenticator(JWTConfig{SigningKey: pemPath})
	if err != nil {
		t.Fatal(err)
	}

	// Sign with HMAC instead.
	tok := signJWT(t, jwt.SigningMethodHS256, []byte("some-secret"), jwt.MapClaims{
		"sub": "user",
	})

	_, err = auth.Validate(tok)
	if err == nil {
		t.Fatal("expected error for algorithm mismatch")
	}
}

func TestJWT_InvalidPEMFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(path, []byte("not a valid PEM file"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := NewJWTAuthenticator(JWTConfig{SigningKey: path})
	if err == nil {
		t.Fatal("expected error for invalid PEM file")
	}
}

func TestJWT_EmptySigningKey(t *testing.T) {
	_, err := NewJWTAuthenticator(JWTConfig{SigningKey: ""})
	if err == nil {
		t.Fatal("expected error for empty signing key")
	}
}

func TestJWT_IssuerAudienceOptional(t *testing.T) {
	secret := "test-secret"
	auth, err := NewJWTAuthenticator(JWTConfig{SigningKey: secret})
	if err != nil {
		t.Fatal(err)
	}

	// Token without iss/aud should be accepted.
	tok := signJWT(t, jwt.SigningMethodHS256, []byte(secret), jwt.MapClaims{
		"sub": "user",
	})

	id, err := auth.Validate(tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserName != "user" {
		t.Errorf("expected user, got %s", id.UserName)
	}
}

func TestJWT_ValidIssuerAndAudience(t *testing.T) {
	secret := "test-secret"
	auth, err := NewJWTAuthenticator(JWTConfig{
		SigningKey: secret,
		Issuer:     "my-issuer",
		Audience:   "my-audience",
	})
	if err != nil {
		t.Fatal(err)
	}

	tok := signJWT(t, jwt.SigningMethodHS256, []byte(secret), jwt.MapClaims{
		"sub": "user",
		"iss": "my-issuer",
		"aud": "my-audience",
	})

	id, err := auth.Validate(tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserName != "user" {
		t.Errorf("expected user, got %s", id.UserName)
	}
}
