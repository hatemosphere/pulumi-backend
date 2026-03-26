package api

import (
	"context"
	"net/http"
	"net/http/httptest"

	"github.com/danielgtaylor/huma/v2"
	"github.com/segmentio/encoding/json"
)

// registerPublicRoutes registers unauthenticated huma operations.
func (s *Server) registerPublicRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "healthCheck",
		Method:      http.MethodGet,
		Path:        "/{$}",
		Tags:        []string{"Health"},
	}, func(ctx context.Context, input *struct{}) (*HealthCheckOutput, error) {
		out := &HealthCheckOutput{}
		out.Body.Status = "ok"
		return out, nil
	})

	if !s.skipManagementRoutes {
		huma.Register(api, huma.Operation{
			OperationID: "livenessCheck",
			Method:      http.MethodGet,
			Path:        "/healthz",
			Tags:        []string{"Health"},
		}, func(ctx context.Context, input *struct{}) (*HealthCheckOutput, error) {
			out := &HealthCheckOutput{}
			out.Body.Status = "ok"
			return out, nil
		})

		huma.Register(api, huma.Operation{
			OperationID: "readinessCheck",
			Method:      http.MethodGet,
			Path:        "/readyz",
			Tags:        []string{"Health"},
			Errors:      []int{503},
		}, func(ctx context.Context, input *struct{}) (*HealthCheckOutput, error) {
			if err := s.engine.Ping(ctx); err != nil {
				return nil, huma.NewError(http.StatusServiceUnavailable, "service not ready")
			}
			out := &HealthCheckOutput{}
			out.Body.Status = "ok"
			return out, nil
		})

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
	}

	if s.oidcAuth != nil {
		s.registerTokenExchange(api)
	}

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
					data, _ := json.Marshal(s.humaAPI.OpenAPI())
					_, _ = ctx.BodyWriter().Write(data)
				} else {
					_, _ = ctx.BodyWriter().Write([]byte(`{}`))
				}
			},
		}, nil
	})
}
