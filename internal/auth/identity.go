package auth

import "context"

// UserIdentity represents an authenticated user and their resolved permissions.
type UserIdentity struct {
	UserName  string   // email (Google mode) or configured default user (single-tenant)
	Groups    []string // Google Workspace group emails (empty in single-tenant mode)
	TokenHash string   // SHA-256 hash of the access token used for this request
	IsAdmin   bool     // true in single-tenant mode — bypasses all RBAC checks
}

type contextKey struct{}

// WithIdentity stores a UserIdentity in the context.
func WithIdentity(ctx context.Context, id *UserIdentity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// IdentityFromContext retrieves the UserIdentity from the context.
// Returns nil if no identity is set.
func IdentityFromContext(ctx context.Context) *UserIdentity {
	id, _ := ctx.Value(contextKey{}).(*UserIdentity)
	return id
}
