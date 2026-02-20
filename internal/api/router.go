package api

import (
	"context"
	stdjson "encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/klauspost/compress/gzip"

	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// Server is the HTTP API server.
type Server struct {
	engine             *engine.Manager
	defaultOrg         string
	defaultUser        string
	deltaCutoffBytes   int
	historyPageSize    int
	humaAPI            huma.API
	authMode           string                    // "single-tenant" (default), "google", or "jwt"
	tokenStore         storage.Store             // required in google auth mode
	googleAuth         *auth.GoogleAuthenticator // required in google auth mode
	groupsCache        *auth.GroupsCache         // optional: resolves groups in google auth mode
	jwtAuth            *auth.JWTAuthenticator    // required in jwt auth mode
	rbac               *auth.RBACResolver        // nil = no RBAC enforcement
	googleClientSecret string                    // OAuth2 client secret for browser login
}

// NewServer creates a new API server.
func NewServer(engine *engine.Manager, defaultOrg, defaultUser string, opts ...ServerOption) *Server {
	s := &Server{
		engine:           engine,
		defaultOrg:       defaultOrg,
		defaultUser:      defaultUser,
		deltaCutoffBytes: 1024 * 1024, // 1MB default
		historyPageSize:  10,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ServerOption configures the API server.
type ServerOption func(*Server)

// WithDeltaCutoff sets the checkpoint size threshold for delta mode.
func WithDeltaCutoff(bytes int) ServerOption {
	return func(s *Server) { s.deltaCutoffBytes = bytes }
}

// WithHistoryPageSize sets the default history page size.
func WithHistoryPageSize(size int) ServerOption {
	return func(s *Server) { s.historyPageSize = size }
}

// WithAuthMode sets the authentication mode ("single-tenant", "google", or "jwt").
func WithAuthMode(mode string) ServerOption {
	return func(s *Server) { s.authMode = mode }
}

// WithTokenStore sets the storage backend for token-based auth lookups.
func WithTokenStore(store storage.Store) ServerOption {
	return func(s *Server) { s.tokenStore = store }
}

// WithGoogleAuth sets the Google authenticator for token exchange.
func WithGoogleAuth(ga *auth.GoogleAuthenticator) ServerOption {
	return func(s *Server) { s.googleAuth = ga }
}

// WithJWTAuth sets the JWT authenticator for stateless token validation.
func WithJWTAuth(ja *auth.JWTAuthenticator) ServerOption {
	return func(s *Server) { s.jwtAuth = ja }
}

// WithGroupsCache sets the groups cache for resolving group memberships in google auth mode.
func WithGroupsCache(gc *auth.GroupsCache) ServerOption {
	return func(s *Server) { s.groupsCache = gc }
}

// WithRBAC sets the RBAC resolver for permission enforcement.
func WithRBAC(resolver *auth.RBACResolver) ServerOption {
	return func(s *Server) { s.rbac = resolver }
}

// WithGoogleClientSecret sets the OAuth2 client secret for the browser login flow.
func WithGoogleClientSecret(secret string) ServerOption {
	return func(s *Server) { s.googleClientSecret = secret }
}

// humaJSONFormat uses stdlib encoding/json for huma request/response serialization.
var humaJSONFormat = huma.Format{
	Marshal: func(w io.Writer, v any) error {
		return stdjson.NewEncoder(w).Encode(v)
	},
	Unmarshal: stdjson.Unmarshal,
}

// newHumaConfig creates the huma configuration for the API.
func newHumaConfig() huma.Config {
	registry := huma.NewMapRegistry("#/components/schemas/", huma.DefaultSchemaNamer)
	config := huma.Config{
		OpenAPI: &huma.OpenAPI{
			OpenAPI: "3.1.0",
			Info: &huma.Info{
				Title:   "Pulumi Backend API",
				Version: "0.1.0",
			},
			Components: &huma.Components{
				Schemas: registry,
			},
		},
		OpenAPIPath:   "", // Disabled — we serve the spec via our own route.
		DocsPath:      "",
		SchemasPath:   "",
		Formats:       map[string]huma.Format{"application/json": humaJSONFormat, "json": humaJSONFormat},
		DefaultFormat: "application/json",
	}
	// Allow extra fields in request bodies (Pulumi CLI sends fields we don't parse).
	config.AllowAdditionalPropertiesByDefault = true
	// Make body fields optional by default (CLI doesn't always send all fields).
	config.FieldsOptionalByDefault = true
	return config
}

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Router returns the configured HTTP handler with all endpoints.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()

	// Public huma routes (no auth).
	publicAPI := humago.New(mux, newHumaConfig())
	publicAPI.UseMiddleware(metricsHumaMiddleware)
	s.registerPublicRoutes(publicAPI)

	// Browser login page (raw mux, serves HTML not JSON).
	if s.googleAuth != nil && s.googleClientSecret != "" {
		s.registerLoginPage(mux)
	}

	// Auth-protected API routes.
	api := humago.New(mux, newHumaConfig())
	api.UseMiddleware(metricsHumaMiddleware)
	api.UseMiddleware(s.authHumaMiddleware(api))
	api.UseMiddleware(s.rbacMiddleware(api))
	s.humaAPI = api

	// Register huma operations.
	s.registerCapabilities(api)
	s.registerUser(api)
	s.registerStacks(api)
	s.registerSecrets(api)
	s.registerUpdates(api)
	s.registerHistory(api)
	s.registerAdmin(api)

	// HTTP-level middleware (outermost applied last).
	var handler http.Handler = mux
	handler = gzipDecompressor(handler)
	handler = requestLogger(handler)
	handler = recoverer(handler)
	handler = realIP(handler)
	return handler
}

// registerPublicRoutes registers unauthenticated huma operations.
func (s *Server) registerPublicRoutes(api huma.API) {
	// Health check.
	huma.Register(api, huma.Operation{
		OperationID: "healthCheck",
		Method:      http.MethodGet,
		Path:        "/",
		Tags:        []string{"Health"},
	}, func(ctx context.Context, input *struct{}) (*HealthCheckOutput, error) {
		out := &HealthCheckOutput{}
		out.Body.Status = "ok"
		return out, nil
	})

	// Prometheus metrics.
	huma.Register(api, huma.Operation{
		OperationID: "getMetrics",
		Method:      http.MethodGet,
		Path:        "/metrics",
		Tags:        []string{"Meta"},
	}, func(ctx context.Context, input *struct{}) (*huma.StreamResponse, error) {
		return &huma.StreamResponse{
			Body: func(ctx huma.Context) {
				rec := httptest.NewRecorder()
				MetricsHandler().ServeHTTP(rec, &http.Request{})
				for k, vals := range rec.Header() {
					for _, v := range vals {
						ctx.SetHeader(k, v)
					}
				}
				_, _ = ctx.BodyWriter().Write(rec.Body.Bytes())
			},
		}, nil
	})

	// Google token exchange (only active in google auth mode).
	if s.googleAuth != nil {
		s.registerGoogleAuth(api)
	}

	// OpenAPI spec.
	huma.Register(api, huma.Operation{
		OperationID: "getOpenAPISpec",
		Method:      http.MethodGet,
		Path:        "/api/openapi",
		Tags:        []string{"Meta"},
	}, func(ctx context.Context, input *struct{}) (*huma.StreamResponse, error) {
		return &huma.StreamResponse{
			Body: func(ctx huma.Context) {
				ctx.SetHeader("Content-Type", "application/json")
				if s.humaAPI != nil {
					data, _ := stdjson.Marshal(s.humaAPI.OpenAPI())
					_, _ = ctx.BodyWriter().Write(data)
				} else {
					_, _ = ctx.BodyWriter().Write([]byte(`{}`))
				}
			},
		}, nil
	})
}

// authHumaMiddleware returns a huma middleware that validates the Authorization
// header and sets a UserIdentity on the request context. Behaviour depends on
// the configured auth mode:
//   - single-tenant: any valid-format token grants full admin access.
//   - jwt: stateless JWT validation, identity + groups extracted from claims.
//   - google: backend-issued opaque token looked up in the database.
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

		switch s.authMode {
		case "jwt":
			s.authJWTHuma(api, ctx, next, authHeader)
		case "google":
			s.authGoogleHuma(api, ctx, next, authHeader)
		default: // single-tenant
			identity := &auth.UserIdentity{
				UserName: s.defaultUser,
				IsAdmin:  true,
			}
			next(huma.WithContext(ctx, auth.WithIdentity(ctx.Context(), identity)))
		}
	}
}

// handleUpdateTokenHuma checks for "update-token" auth headers and passes
// through with a minimal identity. Returns true if handled.
func handleUpdateTokenHuma(ctx huma.Context, next func(huma.Context), authHeader string) bool {
	if !strings.HasPrefix(authHeader, "update-token ") {
		return false
	}
	identity := &auth.UserIdentity{
		UserName: "update-agent",
	}
	next(huma.WithContext(ctx, auth.WithIdentity(ctx.Context(), identity)))
	return true
}

// authJWTHuma handles JWT auth mode: stateless token validation with identity
// and groups extracted directly from JWT claims.
func (s *Server) authJWTHuma(api huma.API, ctx huma.Context, next func(huma.Context), authHeader string) {
	if handleUpdateTokenHuma(ctx, next, authHeader) {
		return
	}

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

// authGoogleHuma handles Google auth mode: opaque backend-issued tokens looked
// up in the database, with optional group resolution via the groups cache.
func (s *Server) authGoogleHuma(api huma.API, ctx huma.Context, next func(huma.Context), authHeader string) {
	if handleUpdateTokenHuma(ctx, next, authHeader) {
		return
	}

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
	if tok.ExpiresAt != nil && tok.ExpiresAt.Before(time.Now()) {
		slog.Debug("access token expired", "user", tok.UserName, "expires_at", tok.ExpiresAt)
		_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "access token expired")
		return
	}

	identity := &auth.UserIdentity{
		UserName:  tok.UserName,
		TokenHash: tokenHash,
	}

	// Resolve groups if a groups cache is available.
	if s.groupsCache != nil {
		groups, err := s.groupsCache.ResolveGroups(ctx.Context(), tok.UserName)
		if err != nil {
			slog.Warn("groups resolution failed", "user", tok.UserName, "error", err) //nolint:gosec // structured logger, not format string
		} else {
			identity.Groups = groups
			slog.Debug("groups resolved successfully", "user", tok.UserName, "group_count", len(groups))
		}
	}

	slog.Debug("Google authentication successful", "user", identity.UserName)
	next(huma.WithContext(ctx, auth.WithIdentity(ctx.Context(), identity)))

	// Async: touch last_used_at + re-validate against Google if refresh token is stored.
	go func() {
		if err := s.tokenStore.TouchToken(context.Background(), tokenHash); err != nil {
			slog.Warn("failed to touch token", "error", err)
		}

		// Re-validate against Google when the token is past half its TTL.
		// This detects deactivated users without adding latency to every request.
		if tok.RefreshToken != "" && s.googleClientSecret != "" && s.googleAuth != nil && s.shouldRevalidate(tok) {
			if err := s.googleAuth.Revalidate(context.Background(), tok.RefreshToken, s.googleClientSecret); err != nil {
				slog.Warn("google re-validation failed, revoking token",
					"user", tok.UserName,
					"error", err,
				)
				if delErr := s.tokenStore.DeleteToken(context.Background(), tokenHash); delErr != nil {
					slog.Error("failed to delete revoked token", "error", delErr)
				}
			}
		}
	}()
}

// shouldRevalidate returns true if the token should be re-validated against Google.
// Triggers when the token is past half its TTL (checked via CreatedAt and ExpiresAt).
func (s *Server) shouldRevalidate(tok *storage.Token) bool {
	if tok.ExpiresAt == nil {
		return false // no expiry = no TTL-based revalidation
	}

	totalTTL := tok.ExpiresAt.Sub(tok.CreatedAt)
	elapsed := time.Since(tok.CreatedAt)

	return elapsed > totalTTL/2
}

// rbacMiddleware returns a huma middleware that enforces RBAC permissions based
// on the request path and HTTP method. It runs after authHumaMiddleware, which
// sets the user identity on the request context.
func (s *Server) rbacMiddleware(api huma.API) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		orgName := ctx.Param("orgName")
		if orgName == "" {
			// Non-stack-scoped endpoint (e.g. /api/user, /api/admin/backup).
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

// requiredPermission maps an HTTP method and operation path to the minimum
// permission level required.
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

// metricsHumaMiddleware records Prometheus metrics for each huma request using
// the operation path as the route label for clean, low-cardinality metrics.
func metricsHumaMiddleware(ctx huma.Context, next func(huma.Context)) {
	start := time.Now()
	next(ctx)
	elapsed := time.Since(start)

	route := ctx.Operation().Path
	status := ctx.Status()
	if status == 0 {
		status = 200
	}

	httpRequestsTotal.WithLabelValues(ctx.Method(), route, strconv.Itoa(status)).Inc()
	httpRequestDuration.WithLabelValues(ctx.Method(), route).Observe(elapsed.Seconds())
}

// requestLogger logs each HTTP request with method, path, status, and latency.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		slog.Info("request", //nolint:gosec // structured logger, not format string
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"latency", time.Since(start),
		)
	})
}

// realIP extracts the real client IP from X-Real-Ip or X-Forwarded-For headers.
func realIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rip := r.Header.Get("X-Real-Ip"); rip != "" {
			r.RemoteAddr = rip
		} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i > 0 {
				r.RemoteAddr = strings.TrimSpace(xff[:i])
			} else {
				r.RemoteAddr = xff
			}
		}
		next.ServeHTTP(w, r)
	})
}

// recoverer recovers from panics and returns a 500 Internal Server Error.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil {
				slog.Error("panic recovered", "error", rvr, "method", r.Method, "path", r.URL.Path) //nolint:gosec // structured logger, not format string
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// gzipDecompressor transparently decompresses gzip request bodies.
func gzipDecompressor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = stdjson.NewEncoder(w).Encode(map[string]any{
					"code":    http.StatusBadRequest,
					"message": "invalid gzip body",
				})
				return
			}
			r.Body = io.NopCloser(gz)
			r.Header.Del("Content-Encoding")
		}
		next.ServeHTTP(w, r)
	})
}
