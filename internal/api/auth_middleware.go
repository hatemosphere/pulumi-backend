package api

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// authHumaMiddleware returns a huma middleware that validates the Authorization
// header and sets a UserIdentity on the request context.
func (s *Server) authHumaMiddleware(api huma.API) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		authHeader := ctx.Header("Authorization")
		if authHeader == "" {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "missing Authorization header")
			return
		}

		if !strings.HasPrefix(authHeader, "token ") && !strings.HasPrefix(authHeader, "update-token ") {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "invalid Authorization header format")
			return
		}

		ipCtx := auth.WithClientIP(ctx.Context(), ctx.RemoteAddr())
		ctx = huma.WithContext(ctx, ipCtx)

		if s.handleUpdateTokenHuma(api, ctx, next, authHeader) {
			return
		}

		switch s.authMode {
		case "jwt":
			s.authJWTHuma(api, ctx, next, authHeader)
		case "google", "oidc":
			s.authOIDCHuma(api, ctx, next, authHeader)
		default:
			tokenValue := strings.TrimPrefix(authHeader, "token ")
			if s.singleTenantTokenHash == "" {
				_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "single-tenant token is not configured")
				return
			}
			if subtle.ConstantTimeCompare([]byte(auth.HashToken(tokenValue)), []byte(s.singleTenantTokenHash)) != 1 {
				_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "invalid access token")
				return
			}
			identity := &auth.UserIdentity{UserName: s.defaultUser, IsAdmin: true}
			next(huma.WithContext(ctx, auth.WithIdentity(ctx.Context(), identity)))
		}
	}
}

// handleUpdateTokenHuma checks for "update-token" auth headers.
func (s *Server) handleUpdateTokenHuma(api huma.API, ctx huma.Context, next func(huma.Context), authHeader string) bool {
	if !strings.HasPrefix(authHeader, "update-token ") {
		return false
	}
	tokenValue := strings.TrimPrefix(authHeader, "update-token ")
	updateID := ctx.Param("updateID")
	if updateID == "" {
		_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "update-token requires an update-scoped endpoint")
		return true
	}
	if err := s.engine.ValidateUpdateToken(ctx.Context(), updateID, tokenValue); err != nil {
		slog.Debug("update-token validation failed", "updateID", updateID, "error", err)
		_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "invalid or expired update token")
		return true
	}
	identity := &auth.UserIdentity{UserName: "update-agent", IsUpdateToken: true}
	next(huma.WithContext(ctx, auth.WithIdentity(ctx.Context(), identity)))
	return true
}

// authJWTHuma handles JWT auth mode.
func (s *Server) authJWTHuma(api huma.API, ctx huma.Context, next func(huma.Context), authHeader string) {
	tokenValue := strings.TrimPrefix(authHeader, "token ")
	identity, err := s.jwtAuth.Validate(tokenValue)
	if err != nil {
		slog.Warn("JWT validation failed", "error", err)
		_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "invalid JWT: "+err.Error())
		return
	}

	slog.Debug("JWT authentication successful", "user", identity.UserName, "groups", identity.Groups)
	next(huma.WithContext(ctx, auth.WithIdentity(ctx.Context(), identity)))
}

// authOIDCHuma handles OIDC auth mode.
func (s *Server) authOIDCHuma(api huma.API, ctx huma.Context, next func(huma.Context), authHeader string) {
	tokenValue := strings.TrimPrefix(authHeader, "token ")
	tokenHash := auth.HashToken(tokenValue)

	tok, err := s.tokenStore.GetToken(ctx.Context(), tokenHash)
	if err != nil {
		slog.Error("token lookup failed", "error", err)
		_ = huma.WriteErr(api, ctx, http.StatusInternalServerError, "internal error")
		return
	}
	if tok == nil {
		slog.Debug("invalid access token provided")
		_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "invalid access token")
		return
	}
	if tok.ExpiresAt != nil && tok.ExpiresAt.Before(s.clock.Now()) {
		slog.Debug("access token expired", "user", tok.UserName, "expires_at", tok.ExpiresAt)
		_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "access token expired")
		return
	}

	identity := &auth.UserIdentity{UserName: tok.UserName, TokenHash: tokenHash}

	if s.groupsCache != nil {
		groups, err := s.groupsCache.ResolveGroups(ctx.Context(), tok.UserName)
		if err != nil {
			slog.Warn("groups resolution failed", "user", tok.UserName, "error", err) //nolint:gosec
		} else {
			identity.Groups = groups
			slog.Debug("groups resolved successfully", "user", tok.UserName, "group_count", len(groups))
		}
	} else if len(tok.Groups) > 0 {
		identity.Groups = tok.Groups
	}

	slog.Debug("OIDC authentication successful", "user", identity.UserName)
	next(huma.WithContext(ctx, auth.WithIdentity(ctx.Context(), identity)))

	s.scheduleOIDCFollowUp(tokenHash, tok)
}

// shouldRevalidate returns true if the token should be re-validated.
func (s *Server) shouldRevalidate(tok *storage.Token) bool {
	if tok.ExpiresAt == nil {
		return false
	}
	totalTTL := tok.ExpiresAt.Sub(tok.CreatedAt)
	elapsed := time.Since(tok.CreatedAt)
	return elapsed > totalTTL/2
}

// rbacMiddleware enforces RBAC permissions based on the request path and method.
func (s *Server) rbacMiddleware(api huma.API) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		orgName := ctx.Param("orgName")
		if orgName == "" {
			next(ctx)
			return
		}

		projectName := ctx.Param("projectName")
		stackName := ctx.Param("stackName")
		perm := requiredPermission(ctx.Method(), ctx.Operation().Path)

		if err := auth.RequirePermission(ctx.Context(), s.rbac, orgName, projectName, stackName, perm); err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, err.Error())
			return
		}
		next(ctx)
	}
}

// requiredPermission maps an HTTP method and operation path to the minimum permission level required.
func requiredPermission(method, path string) auth.Permission {
	if method == http.MethodDelete {
		return auth.PermissionAdmin
	}
	if strings.HasSuffix(path, "/rename") {
		return auth.PermissionAdmin
	}
	if method == http.MethodGet || method == http.MethodHead {
		return auth.PermissionRead
	}
	if strings.HasSuffix(path, "/decrypt") || strings.HasSuffix(path, "/batch-decrypt") {
		return auth.PermissionRead
	}
	return auth.PermissionWrite
}
