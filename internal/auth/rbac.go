package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"

	"github.com/danielgtaylor/huma/v2"

	"github.com/hatemosphere/pulumi-backend/internal/audit"
)

// RBACResolver resolves the effective permission for a user on a given stack.
type RBACResolver struct {
	config            *RBACConfig
	defaultPermission Permission
}

// NewRBACResolver creates a resolver from the given config.
// If config is nil, all users are treated as admin (single-tenant fallback).
// Returns an error if the config's DefaultPermission is invalid.
func NewRBACResolver(config *RBACConfig) (*RBACResolver, error) {
	if config == nil {
		return &RBACResolver{defaultPermission: PermissionAdmin}, nil
	}
	dp, err := ParsePermission(config.DefaultPermission)
	if err != nil {
		return nil, fmt.Errorf("invalid default permission %q: %w", config.DefaultPermission, err)
	}
	return &RBACResolver{
		config:            config,
		defaultPermission: dp,
	}, nil
}

// Config returns the underlying RBAC configuration (may be nil if no config was loaded).
func (r *RBACResolver) Config() *RBACConfig {
	return r.config
}

// Resolve returns the highest permission the identity has on the specified stack.
// Resolution order: stack-specific policies > group-level roles > default.
// The highest permission across all matching groups wins.
func (r *RBACResolver) Resolve(identity *UserIdentity, org, project, stack string) Permission {
	if identity == nil {
		return PermissionNone
	}

	stackPath := org + "/" + project + "/" + stack

	// Admin users (single-tenant mode) bypass RBAC entirely.
	if identity.IsAdmin {
		slog.Debug("RBAC bypass: user is admin", "user", identity.UserName, "stack", stackPath)
		return PermissionAdmin
	}
	if r.config == nil {
		slog.Debug("RBAC disabled: using default permission", "user", identity.UserName, "stack", stackPath, "default", r.defaultPermission)
		return r.defaultPermission
	}

	groupSet := make(map[string]struct{}, len(identity.Groups))
	for _, g := range identity.Groups {
		groupSet[g] = struct{}{}
	}

	best := r.defaultPermission

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
			slog.Warn("RBAC config error: invalid stack policy permission", "group", sp.Group, "pattern", sp.StackPattern, "permission", sp.Permission)
			continue
		}
		if perm > best {
			slog.Debug("RBAC match: stack policy applied", "user", identity.UserName, "group", sp.Group, "pattern", sp.StackPattern, "permission", sp.Permission)
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
			slog.Warn("RBAC config error: invalid group role permission", "group", gr.Group, "permission", gr.Permission)
			continue
		}
		if perm > best {
			slog.Debug("RBAC match: group role applied", "user", identity.UserName, "group", gr.Group, "permission", gr.Permission)
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
		slog.Debug("RBAC check passed", "user", identity.UserName, "stack", org+"/"+project+"/"+stack, "required", required, "effective", effective)
		return nil
	}

	actor := "anonymous"
	if identity != nil {
		actor = identity.UserName
	}

	audit.Event{
		Actor:    actor,
		Action:   "access_stack_endpoint",
		Status:   "denied",
		Resource: org + "/" + project + "/" + stack,
		Reason:   fmt.Sprintf("insufficient_permissions (require %s, have %s)", required, effective),
	}.Warn("Audit Log: Access Denied")

	return huma.NewError(http.StatusForbidden,
		fmt.Sprintf("insufficient permissions: require %s, have %s", required, effective))
}
