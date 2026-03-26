package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/segmentio/encoding/json"

	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/clockutil"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// AccessLog is the destination for per-request access log entries.
// Defaults to slog.Default(). Set to a no-op logger to disable access logging,
// or to a separate logger to route access logs independently.
var AccessLog *slog.Logger

func accessLog() *slog.Logger {
	if AccessLog != nil {
		return AccessLog
	}
	return slog.Default()
}

// Server is the HTTP API server.
type Server struct {
	engine                *engine.Manager
	defaultOrg            string
	defaultUser           string
	deltaCutoffBytes      int
	historyPageSize       int
	humaAPI               huma.API
	authMode              string                 // "single-tenant" (default), "google", "oidc", or "jwt"
	singleTenantTokenHash string                 // required in single-tenant auth mode
	tokenStore            storage.Store          // required in google/oidc auth modes
	oidcAuth              auth.OIDCAuthenticator // required in google/oidc auth modes
	groupsCache           *auth.GroupsCache      // optional: resolves groups via external API (e.g. Google Admin SDK)
	jwtAuth               *auth.JWTAuthenticator // required in jwt auth mode
	rbac                  *auth.RBACResolver     // nil = no RBAC enforcement
	publicURL             string                 // public base URL for redirect URIs (mitigates Host header poisoning)
	skipManagementRoutes  bool                   // skip /healthz, /readyz, /metrics on main mux (served on management port)
	cliSessionNonces      *nonceStore            // server-side CLI session nonce store
	trustedProxies        []*net.IPNet           // CIDRs allowed to set forwarded headers (nil = trust none)
	oidcFollowUp          *oidcFollowUpScheduler
	backgroundCtx         context.Context
	cancel                context.CancelFunc
	clock                 clockutil.Clock
}

// NewServer creates a new API server.
func NewServer(engine *engine.Manager, defaultOrg, defaultUser string, opts ...ServerOption) *Server {
	bgCtx, cancel := context.WithCancel(context.Background())
	s := &Server{
		engine:           engine,
		defaultOrg:       defaultOrg,
		defaultUser:      defaultUser,
		deltaCutoffBytes: 1024 * 1024, // 1MB default
		historyPageSize:  10,
		cliSessionNonces: newNonceStore(5 * time.Minute),
		backgroundCtx:    bgCtx,
		cancel:           cancel,
		clock:            clockutil.RealClock{},
		oidcFollowUp:     newOIDCFollowUpScheduler(bgCtx, clockutil.RealClock{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Close releases server-owned background resources.
func (s *Server) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
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

// WithAuthMode sets the authentication mode ("single-tenant", "google", "oidc", or "jwt").
func WithAuthMode(mode string) ServerOption {
	return func(s *Server) { s.authMode = mode }
}

// WithSingleTenantToken sets the shared access token for single-tenant mode.
func WithSingleTenantToken(token string) ServerOption {
	return func(s *Server) { s.singleTenantTokenHash = auth.HashToken(token) }
}

// WithTokenStore sets the storage backend for token-based auth lookups.
func WithTokenStore(store storage.Store) ServerOption {
	return func(s *Server) { s.tokenStore = store }
}

// WithOIDCAuth sets the OIDC authenticator (used for both "google" and "oidc" modes).
func WithOIDCAuth(oa auth.OIDCAuthenticator) ServerOption {
	return func(s *Server) { s.oidcAuth = oa }
}

// WithJWTAuth sets the JWT authenticator for stateless token validation.
func WithJWTAuth(ja *auth.JWTAuthenticator) ServerOption {
	return func(s *Server) { s.jwtAuth = ja }
}

// WithGroupsCache sets the groups cache for resolving group memberships.
func WithGroupsCache(gc *auth.GroupsCache) ServerOption {
	return func(s *Server) { s.groupsCache = gc }
}

// WithRBAC sets the RBAC resolver for permission enforcement.
func WithRBAC(resolver *auth.RBACResolver) ServerOption {
	return func(s *Server) { s.rbac = resolver }
}

// WithPublicURL sets the public base URL for redirect URI construction.
func WithPublicURL(url string) ServerOption {
	return func(s *Server) { s.publicURL = strings.TrimRight(url, "/") }
}

// WithSkipManagementRoutes tells the server not to register /healthz, /readyz,
// /metrics on the main mux (they will be served on a separate management port).
func WithSkipManagementRoutes() ServerOption {
	return func(s *Server) { s.skipManagementRoutes = true }
}

// WithTrustedProxies sets the CIDR ranges of trusted reverse proxies.
// Only requests from these ranges will have X-Forwarded-For/X-Real-Ip honoured.
func WithTrustedProxies(cidrs []*net.IPNet) ServerOption {
	return func(s *Server) { s.trustedProxies = cidrs }
}

// ParseTrustedProxies parses a comma-separated string of CIDRs into []*net.IPNet.
func ParseTrustedProxies(raw string) ([]*net.IPNet, error) {
	if raw == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for cidr := range strings.SplitSeq(raw, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, errors.New("invalid trusted proxy CIDR: " + cidr)
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
}

// humaJSONFormat uses stdlib encoding/json for huma request/response serialization.
var humaJSONFormat = huma.Format{
	Marshal: func(w io.Writer, v any) error {
		return json.NewEncoder(w).Encode(v)
	},
	Unmarshal: json.Unmarshal,
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
		OpenAPIPath:   "",
		DocsPath:      "",
		SchemasPath:   "",
		Formats:       map[string]huma.Format{"application/json": humaJSONFormat, "json": humaJSONFormat},
		DefaultFormat: "application/json",
	}
	config.AllowAdditionalPropertiesByDefault = true
	config.FieldsOptionalByDefault = true
	return config
}

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader captures the status code and delegates to the underlying ResponseWriter.
func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Router returns the configured HTTP handler with all endpoints.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()

	publicAPI := humago.New(mux, newHumaConfig())
	publicAPI.UseMiddleware(metricsHumaMiddleware)
	s.registerPublicRoutes(publicAPI)

	if s.oidcAuth != nil {
		s.registerLogin(publicAPI)
	}

	api := humago.New(mux, newHumaConfig())
	api.UseMiddleware(metricsHumaMiddleware)
	api.UseMiddleware(s.authHumaMiddleware(api))
	api.UseMiddleware(s.rbacMiddleware(api))
	api.UseMiddleware(auditHumaMiddleware)
	s.humaAPI = api

	s.registerCapabilities(api)
	s.registerUser(api)
	s.registerStacks(api)
	s.registerSecrets(api)
	s.registerUpdates(api)
	s.registerHistory(api)
	s.registerAdmin(api)
	if s.tokenStore != nil {
		s.registerUserTokens(api)
	}
	s.registerOrg(api)

	var handler http.Handler = mux
	handler = gzipDecompressor(handler)
	handler = securityHeaders(handler)
	handler = requestLogger(handler)
	handler = recoverer(handler)
	handler = realIP(handler, s.trustedProxies)
	return handler
}
