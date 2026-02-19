package auth

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/danielgtaylor/huma/v2"
)

// RBACResolver resolves the effective permission for a user on a given stack.
type RBACResolver struct {
	config            *RBACConfig
	defaultPermission Permission
}

// NewRBACResolver creates a resolver from the given config.
// If config is nil, all users are treated as admin (single-tenant fallback).
func NewRBACResolver(config *RBACConfig) *RBACResolver {
	if config == nil {
		return &RBACResolver{defaultPermission: PermissionAdmin}
	}
	dp, err := ParsePermission(config.DefaultPermission)
	if err != nil {
		dp = PermissionRead // safe default
	}
	return &RBACResolver{
		config:            config,
		defaultPermission: dp,
	}
}

// Resolve returns the highest permission the identity has on the specified stack.
// Resolution order: stack-specific policies > group-level roles > default.
// The highest permission across all matching groups wins.
func (r *RBACResolver) Resolve(identity *UserIdentity, org, project, stack string) Permission {
	if identity == nil {
		return PermissionNone
	}
	// Admin users (single-tenant mode) bypass RBAC entirely.
	if identity.IsAdmin {
		return PermissionAdmin
	}
	if r.config == nil {
		return r.defaultPermission
	}

	groupSet := make(map[string]struct{}, len(identity.Groups))
	for _, g := range identity.Groups {
		groupSet[g] = struct{}{}
	}

	best := r.defaultPermission
	stackPath := org + "/" + project + "/" + stack

	// Check stack-specific policies first (more specific).
	for _, sp := range r.config.StackPolicies {
		if _, ok := groupSet[sp.Group]; !ok {
			continue
		}
		matched, err := filepath.Match(sp.StackPattern, stackPath)
		if err != nil || !matched {
			continue
		}
		perm, err := ParsePermission(sp.Permission)
		if err != nil {
			continue
		}
		if perm > best {
			best = perm
		}
	}

	// Check group-level roles.
	for _, gr := range r.config.GroupRoles {
		if _, ok := groupSet[gr.Group]; !ok {
			continue
		}
		perm, err := ParsePermission(gr.Permission)
		if err != nil {
			continue
		}
		if perm > best {
			best = perm
		}
	}

	return best
}

// RequirePermission checks whether the authenticated user has the required
// permission on the given stack. Returns nil if allowed, or a huma error if denied.
// Admin users (single-tenant mode) always pass.
func RequirePermission(ctx context.Context, resolver *RBACResolver, org, project, stack string, required Permission) error {
	identity := IdentityFromContext(ctx)
	if identity != nil && identity.IsAdmin {
		return nil
	}
	if resolver == nil {
		return nil
	}
	effective := resolver.Resolve(identity, org, project, stack)
	if effective >= required {
		return nil
	}
	return huma.NewError(http.StatusForbidden,
		fmt.Sprintf("insufficient permissions: require %s, have %s", required, effective))
}
