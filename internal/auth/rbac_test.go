package auth

import (
	"context"
	"testing"
)

func mustNewRBACResolver(t *testing.T, config *RBACConfig) *RBACResolver {
	t.Helper()
	r, err := NewRBACResolver(config)
	if err != nil {
		t.Fatalf("NewRBACResolver: %v", err)
	}
	return r
}

func TestRBACResolver_AdminBypass(t *testing.T) {
	resolver := mustNewRBACResolver(t, &RBACConfig{DefaultPermission: "read"})
	identity := &UserIdentity{UserName: "admin", IsAdmin: true}

	perm := resolver.Resolve(identity, "org", "project", "stack")
	if perm != PermissionAdmin {
		t.Fatalf("expected admin, got %s", perm)
	}
}

func TestRBACResolver_DefaultPermission(t *testing.T) {
	resolver := mustNewRBACResolver(t, &RBACConfig{DefaultPermission: "read"})
	identity := &UserIdentity{UserName: "user@company.com", Groups: []string{"unknown@company.com"}}

	perm := resolver.Resolve(identity, "org", "project", "stack")
	if perm != PermissionRead {
		t.Fatalf("expected read, got %s", perm)
	}
}

func TestRBACResolver_GroupRole(t *testing.T) {
	resolver := mustNewRBACResolver(t, &RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []GroupRole{
			{Group: "developers@company.com", Permission: "write"},
			{Group: "infra-admins@company.com", Permission: "admin"},
		},
	})

	tests := []struct {
		name     string
		groups   []string
		expected Permission
	}{
		{"no matching group", []string{"random@company.com"}, PermissionRead},
		{"developer group", []string{"developers@company.com"}, PermissionWrite},
		{"admin group", []string{"infra-admins@company.com"}, PermissionAdmin},
		{"both groups - highest wins", []string{"developers@company.com", "infra-admins@company.com"}, PermissionAdmin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &UserIdentity{UserName: "user@company.com", Groups: tt.groups}
			perm := resolver.Resolve(identity, "org", "project", "stack")
			if perm != tt.expected {
				t.Fatalf("expected %s, got %s", tt.expected, perm)
			}
		})
	}
}

func TestRBACResolver_StackPolicy(t *testing.T) {
	resolver := mustNewRBACResolver(t, &RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []GroupRole{
			{Group: "developers@company.com", Permission: "read"},
		},
		StackPolicies: []StackPolicy{
			{Group: "frontend@company.com", StackPattern: "org/frontend-*/*", Permission: "write"},
			{Group: "security@company.com", StackPattern: "org/*/production", Permission: "admin"},
		},
	})

	tests := []struct {
		name           string
		groups         []string
		org, proj, stk string
		expected       Permission
	}{
		{
			"no match",
			[]string{"random@company.com"},
			"org", "backend-api", "dev",
			PermissionRead,
		},
		{
			"frontend team on frontend project",
			[]string{"frontend@company.com"},
			"org", "frontend-web", "staging",
			PermissionWrite,
		},
		{
			"frontend team on backend project - no match",
			[]string{"frontend@company.com"},
			"org", "backend-api", "dev",
			PermissionRead,
		},
		{
			"security team on production stack",
			[]string{"security@company.com"},
			"org", "backend-api", "production",
			PermissionAdmin,
		},
		{
			"security team on non-production stack",
			[]string{"security@company.com"},
			"org", "backend-api", "staging",
			PermissionRead,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &UserIdentity{UserName: "user@company.com", Groups: tt.groups}
			perm := resolver.Resolve(identity, tt.org, tt.proj, tt.stk)
			if perm != tt.expected {
				t.Fatalf("expected %s, got %s", tt.expected, perm)
			}
		})
	}
}

func TestRBACResolver_NilConfig(t *testing.T) {
	resolver := mustNewRBACResolver(t, nil)
	identity := &UserIdentity{UserName: "anyone"}

	perm := resolver.Resolve(identity, "org", "project", "stack")
	if perm != PermissionAdmin {
		t.Fatalf("nil config should default to admin, got %s", perm)
	}
}

func TestRBACResolver_NilIdentity(t *testing.T) {
	resolver := mustNewRBACResolver(t, &RBACConfig{DefaultPermission: "read"})

	perm := resolver.Resolve(nil, "org", "project", "stack")
	if perm != PermissionNone {
		t.Fatalf("nil identity should return none, got %s", perm)
	}
}

func TestRequirePermission_AdminBypass(t *testing.T) {
	resolver := mustNewRBACResolver(t, &RBACConfig{DefaultPermission: "read"})
	ctx := WithIdentity(context.Background(), &UserIdentity{IsAdmin: true})

	if err := RequirePermission(ctx, resolver, "org", "project", "stack", PermissionAdmin); err != nil {
		t.Fatalf("admin should bypass RBAC: %v", err)
	}
}

func TestRequirePermission_Denied(t *testing.T) {
	resolver := mustNewRBACResolver(t, &RBACConfig{DefaultPermission: "read"})
	ctx := WithIdentity(context.Background(), &UserIdentity{UserName: "user@company.com"})

	err := RequirePermission(ctx, resolver, "org", "project", "stack", PermissionWrite)
	if err == nil {
		t.Fatal("expected permission denied")
	}
}

func TestRequirePermission_NilResolver(t *testing.T) {
	ctx := WithIdentity(context.Background(), &UserIdentity{UserName: "user@company.com"})

	if err := RequirePermission(ctx, nil, "org", "project", "stack", PermissionAdmin); err != nil {
		t.Fatalf("nil resolver should allow all: %v", err)
	}
}

func TestRBACResolver_OverlappingStackPolicies(t *testing.T) {
	resolver := mustNewRBACResolver(t, &RBACConfig{
		DefaultPermission: "none",
		StackPolicies: []StackPolicy{
			{Group: "devs@co.com", StackPattern: "org/app/*", Permission: "read"},
			{Group: "devs@co.com", StackPattern: "org/app/staging", Permission: "write"},
		},
	})

	identity := &UserIdentity{UserName: "user", Groups: []string{"devs@co.com"}}
	// Both policies match "org/app/staging" — highest (write) should win.
	perm := resolver.Resolve(identity, "org", "app", "staging")
	if perm != PermissionWrite {
		t.Fatalf("expected write, got %s", perm)
	}
}

func TestRBACResolver_WildcardPatterns(t *testing.T) {
	resolver := mustNewRBACResolver(t, &RBACConfig{
		DefaultPermission: "read",
		StackPolicies: []StackPolicy{
			{Group: "admins@co.com", StackPattern: "*/*/*", Permission: "admin"},
			{Group: "prod-ops@co.com", StackPattern: "org/*/production", Permission: "write"},
		},
	})

	tests := []struct {
		name           string
		groups         []string
		org, proj, stk string
		expected       Permission
	}{
		{
			"triple wildcard matches everything",
			[]string{"admins@co.com"},
			"org", "any-project", "any-stack",
			PermissionAdmin,
		},
		{
			"production wildcard",
			[]string{"prod-ops@co.com"},
			"org", "backend", "production",
			PermissionWrite,
		},
		{
			"production wildcard no match - falls back to default",
			[]string{"prod-ops@co.com"},
			"org", "backend", "staging",
			PermissionRead,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &UserIdentity{UserName: "user", Groups: tt.groups}
			perm := resolver.Resolve(identity, tt.org, tt.proj, tt.stk)
			if perm != tt.expected {
				t.Fatalf("expected %s, got %s", tt.expected, perm)
			}
		})
	}
}

func TestRBACResolver_EmptyGroups(t *testing.T) {
	resolver := mustNewRBACResolver(t, &RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []GroupRole{
			{Group: "devs@co.com", Permission: "write"},
		},
	})

	identity := &UserIdentity{UserName: "user", Groups: nil}
	perm := resolver.Resolve(identity, "org", "project", "stack")
	if perm != PermissionRead {
		t.Fatalf("expected default read, got %s", perm)
	}
}

func TestRBACResolver_StackPolicyOverridesGroupRole(t *testing.T) {
	resolver := mustNewRBACResolver(t, &RBACConfig{
		DefaultPermission: "none",
		GroupRoles: []GroupRole{
			{Group: "devs@co.com", Permission: "read"},
		},
		StackPolicies: []StackPolicy{
			{Group: "devs@co.com", StackPattern: "org/app/dev", Permission: "admin"},
		},
	})

	identity := &UserIdentity{UserName: "user", Groups: []string{"devs@co.com"}}
	// Stack policy gives admin, group role gives read — highest wins.
	perm := resolver.Resolve(identity, "org", "app", "dev")
	if perm != PermissionAdmin {
		t.Fatalf("expected admin (stack policy), got %s", perm)
	}
}

func TestRBACResolver_InvalidPermissionInConfig(t *testing.T) {
	resolver := mustNewRBACResolver(t, &RBACConfig{
		DefaultPermission: "read",
		GroupRoles: []GroupRole{
			{Group: "devs@co.com", Permission: "superadmin"},
		},
	})

	identity := &UserIdentity{UserName: "user", Groups: []string{"devs@co.com"}}
	// Invalid "superadmin" should be skipped, fallback to default.
	perm := resolver.Resolve(identity, "org", "project", "stack")
	if perm != PermissionRead {
		t.Fatalf("expected read (invalid perm skipped), got %s", perm)
	}
}

func TestNewRBACResolver_InvalidDefaultPermission(t *testing.T) {
	_, err := NewRBACResolver(&RBACConfig{DefaultPermission: "superpower"})
	if err == nil {
		t.Fatal("expected error for invalid default permission")
	}
}

func TestRequirePermission_NoIdentity(t *testing.T) {
	resolver := mustNewRBACResolver(t, &RBACConfig{DefaultPermission: "read"})
	// Context without identity.
	err := RequirePermission(context.Background(), resolver, "org", "project", "stack", PermissionRead)
	if err == nil {
		t.Fatal("expected error when no identity in context")
	}
}

func TestPermissionOrdering(t *testing.T) {
	if PermissionNone >= PermissionRead {
		t.Fatal("none should be less than read")
	}
	if PermissionRead >= PermissionWrite {
		t.Fatal("read should be less than write")
	}
	if PermissionWrite >= PermissionAdmin {
		t.Fatal("write should be less than admin")
	}
}

func TestParsePermission(t *testing.T) {
	tests := []struct {
		input    string
		expected Permission
		wantErr  bool
	}{
		{"read", PermissionRead, false},
		{"write", PermissionWrite, false},
		{"admin", PermissionAdmin, false},
		{"invalid", PermissionNone, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			p, err := ParsePermission(tt.input)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p != tt.expected {
				t.Fatalf("expected %s, got %s", tt.expected, p)
			}
		})
	}
}
