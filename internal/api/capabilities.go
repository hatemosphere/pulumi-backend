package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"encoding/json"
)

func (s *Server) registerCapabilities(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "getCapabilities",
		Method:      http.MethodGet,
		Path:        "/api/capabilities",
		Tags:        []string{"Capabilities"},
	}, func(ctx context.Context, input *struct{}) (*GetCapabilitiesOutput, error) {
		deltaConfig, _ := json.Marshal(map[string]any{
			"checkpointCutoffSizeBytes": s.deltaCutoffBytes,
		})
		out := &GetCapabilitiesOutput{}
		out.Body.Capabilities = []Capability{
			{
				Capability:    "delta-checkpoint-uploads-v2",
				Version:       2,
				Configuration: json.RawMessage(deltaConfig),
			},
			{
				Capability: "batch-encrypt",
			},
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "getCLIVersion",
		Method:      http.MethodGet,
		Path:        "/api/cli/version",
		Tags:        []string{"Capabilities"},
	}, func(ctx context.Context, input *struct{}) (*GetCLIVersionOutput, error) {
		out := &GetCLIVersionOutput{}
		out.Body.LatestVersion = "3.211.0"
		out.Body.OldestWithoutWarning = "3.0.0"
		out.Body.LatestDevVersion = ""
		return out, nil
	})
}
