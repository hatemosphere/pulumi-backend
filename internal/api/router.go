package api

import (
	"context"
	stdjson "encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/klauspost/compress/gzip"

	"github.com/hatemosphere/pulumi-backend/internal/engine"
)

// Server is the HTTP API server.
type Server struct {
	engine           *engine.Manager
	defaultOrg       string
	defaultUser      string
	deltaCutoffBytes int
	historyPageSize  int
	humaAPI          huma.API
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

// Router returns the configured chi router with all endpoints.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	// Middleware.
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(slogRequestLogger)
	r.Use(metricsMiddleware)
	r.Use(gzipDecompressor) // Decompress gzip request bodies from CLI.

	// Public huma routes (no auth).
	publicAPI := humachi.New(r, newHumaConfig())
	s.registerPublicRoutes(publicAPI)

	// Auth-protected API routes.
	r.Group(func(r chi.Router) {
		r.Use(s.authMiddleware)

		// Create huma API wrapping this group.
		api := humachi.New(r, newHumaConfig())
		s.humaAPI = api

		// Register huma operations.
		s.registerCapabilities(api)
		s.registerUser(api)
		s.registerStacks(api)
		s.registerSecrets(api)
		s.registerUpdates(api)
		s.registerHistory(api)
		s.registerAdmin(api)
	})

	return r
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

// authMiddleware is a simple token-based auth. Accepts any token in single-tenant mode.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = stdjson.NewEncoder(w).Encode(map[string]any{
				"code":    http.StatusUnauthorized,
				"message": "missing Authorization header",
			})
			return
		}

		// Accept both "token <xxx>" and "update-token <xxx>" formats.
		if strings.HasPrefix(auth, "token ") || strings.HasPrefix(auth, "update-token ") {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = stdjson.NewEncoder(w).Encode(map[string]any{
			"code":    http.StatusUnauthorized,
			"message": "invalid Authorization header format",
		})
	})
}

// slogRequestLogger logs each HTTP request with method, path, status code, and latency.
func slogRequestLogger(next http.Handler) http.Handler {
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
