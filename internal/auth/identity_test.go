package auth

import (
	"context"
	"testing"
)

func TestIdentity_RoundTrip(t *testing.T) {
	ctx := context.Background()
	id := &UserIdentity{
		UserName:  "alice@example.com",
		Groups:    []string{"devs", "admins"},
		TokenHash: "abc123",
		IsAdmin:   true,
	}

	ctx = WithIdentity(ctx, id)
	got := IdentityFromContext(ctx)

	if got == nil {
		t.Fatal("expected identity, got nil")
	}
	if got.UserName != id.UserName {
		t.Errorf("UserName: expected %s, got %s", id.UserName, got.UserName)
	}
	if len(got.Groups) != 2 || got.Groups[0] != "devs" || got.Groups[1] != "admins" {
		t.Errorf("Groups: expected %v, got %v", id.Groups, got.Groups)
	}
	if got.TokenHash != id.TokenHash {
		t.Errorf("TokenHash: expected %s, got %s", id.TokenHash, got.TokenHash)
	}
	if !got.IsAdmin {
		t.Error("expected IsAdmin=true")
	}
}

func TestIdentity_EmptyContext(t *testing.T) {
	got := IdentityFromContext(context.Background())
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestIdentity_Overwrite(t *testing.T) {
	ctx := context.Background()
	a := &UserIdentity{UserName: "alice"}
	b := &UserIdentity{UserName: "bob"}

	ctx = WithIdentity(ctx, a)
	ctx = WithIdentity(ctx, b)

	got := IdentityFromContext(ctx)
	if got == nil {
		t.Fatal("expected identity, got nil")
	}
	if got.UserName != "bob" {
		t.Errorf("expected bob, got %s", got.UserName)
	}
}
