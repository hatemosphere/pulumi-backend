package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"encoding/json"
)

// exportStack handles both versioned and unversioned stack export with gzip negotiation.
func (s *Server) exportStack(ctx context.Context, org, project, stack string, version *int) (*huma.StreamResponse, error) {
	// Pre-fetch both compressed and uncompressed; the StreamResponse body
	// decides which to send based on Accept-Encoding from huma.Context.
	data, isGzip, compErr := s.engine.ExportStateCompressed(ctx, org, project, stack, version)
	if compErr != nil {
		// Fall through to uncompressed path.
		deployment, err := s.engine.ExportState(ctx, org, project, stack, version)
		if err != nil {
			return nil, huma.NewError(http.StatusNotFound, err.Error())
		}
		return &huma.StreamResponse{
			Body: func(ctx huma.Context) {
				ctx.SetHeader("Content-Type", "application/json")
				ctx.BodyWriter().Write(deployment)
			},
		}, nil
	}

	return &huma.StreamResponse{
		Body: func(ctx huma.Context) {
			ctx.SetHeader("Content-Type", "application/json")
			if isGzip && strings.Contains(ctx.Header("Accept-Encoding"), "gzip") {
				ctx.SetHeader("Content-Encoding", "gzip")
				ctx.BodyWriter().Write(data)
			} else if isGzip {
				// Client doesn't accept gzip; decompress before sending.
				deployment, err := s.engine.ExportState(ctx.Context(), org, project, stack, version)
				if err != nil {
					ctx.SetStatus(http.StatusInternalServerError)
					return
				}
				ctx.BodyWriter().Write(deployment)
			} else {
				ctx.BodyWriter().Write(data)
			}
		},
	}, nil
}

func (s *Server) registerStacks(api huma.API) {
	// --- Project exists (HEAD) ---
	huma.Register(api, huma.Operation{
		OperationID:   "projectExists",
		Method:        http.MethodHead,
		Path:          "/api/stacks/{orgName}/{projectName}",
		Tags:          []string{"Stacks"},
		DefaultStatus: 200,
	}, func(ctx context.Context, input *ProjectExistsInput) (*struct{}, error) {
		exists, err := s.engine.ProjectExists(ctx, input.OrgName, input.ProjectName)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		if !exists {
			return nil, huma.NewError(http.StatusNotFound, "project not found")
		}
		return nil, nil
	})

	// --- Create stack ---
	huma.Register(api, huma.Operation{
		OperationID: "createStack",
		Method:      http.MethodPost,
		Path:        "/api/stacks/{orgName}/{projectName}",
		Tags:        []string{"Stacks"},
	}, func(ctx context.Context, input *CreateStackInput) (*CreateStackOutput, error) {
		if input.Body.StackName == "" {
			return nil, huma.NewError(http.StatusBadRequest, "stackName is required")
		}
		if err := validateName(input.Body.StackName, "stack"); err != nil {
			return nil, huma.NewError(http.StatusBadRequest, err.Error())
		}
		if err := validateName(input.ProjectName, "project"); err != nil {
			return nil, huma.NewError(http.StatusBadRequest, err.Error())
		}

		err := s.engine.CreateStack(ctx, input.OrgName, input.ProjectName, input.Body.StackName, nil)
		if err != nil {
			return nil, huma.NewError(http.StatusConflict, err.Error())
		}

		return &CreateStackOutput{}, nil
	})

	// --- Get stack ---
	huma.Register(api, huma.Operation{
		OperationID: "getStack",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}",
		Tags:        []string{"Stacks"},
	}, func(ctx context.Context, input *GetStackInput) (*GetStackOutput, error) {
		st, err := s.engine.GetStack(ctx, input.OrgName, input.ProjectName, input.StackName)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		if st == nil {
			return nil, huma.NewError(http.StatusNotFound, "stack not found")
		}

		out := &GetStackOutput{}
		out.Body.OrgName = st.OrgName
		out.Body.ProjectName = st.ProjectName
		out.Body.StackName = st.StackName
		out.Body.Tags = st.Tags
		out.Body.Version = st.Version

		activeUpdate, _ := s.engine.GetActiveUpdate(ctx, input.OrgName, input.ProjectName, input.StackName)
		if activeUpdate != nil {
			out.Body.ActiveUpdate = &activeUpdate.ID
		}

		return out, nil
	})

	// --- Delete stack ---
	huma.Register(api, huma.Operation{
		OperationID:   "deleteStack",
		Method:        http.MethodDelete,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}",
		Tags:          []string{"Stacks"},
		DefaultStatus: 204,
	}, func(ctx context.Context, input *DeleteStackInput) (*struct{}, error) {
		err := s.engine.DeleteStack(ctx, input.OrgName, input.ProjectName, input.StackName, input.Force)
		if err != nil {
			return nil, huma.NewError(http.StatusBadRequest, err.Error())
		}
		return nil, nil
	})

	// --- Update stack tags ---
	huma.Register(api, huma.Operation{
		OperationID:   "updateStackTags",
		Method:        http.MethodPatch,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}/tags",
		Tags:          []string{"Stacks"},
		DefaultStatus: 204,
	}, func(ctx context.Context, input *UpdateStackTagsInput) (*struct{}, error) {
		err := s.engine.UpdateStackTags(ctx, input.OrgName, input.ProjectName, input.StackName, input.Body)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		return nil, nil
	})

	// --- Rename stack ---
	huma.Register(api, huma.Operation{
		OperationID:   "renameStack",
		Method:        http.MethodPost,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}/rename",
		Tags:          []string{"Stacks"},
		DefaultStatus: 204,
	}, func(ctx context.Context, input *RenameStackInput) (*struct{}, error) {
		if err := validateName(input.Body.NewName, "stack"); err != nil {
			return nil, huma.NewError(http.StatusBadRequest, err.Error())
		}

		newProject := input.Body.NewProject
		if newProject == "" {
			newProject = input.ProjectName
		} else if err := validateName(newProject, "project"); err != nil {
			return nil, huma.NewError(http.StatusBadRequest, err.Error())
		}

		err := s.engine.RenameStack(ctx, input.OrgName, input.ProjectName, input.StackName, newProject, input.Body.NewName)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		return nil, nil
	})

	// --- Export stack (StreamResponse for zero-copy gzip) ---
	huma.Register(api, huma.Operation{
		OperationID: "exportStack",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/export",
		Tags:        []string{"Stacks"},
	}, func(ctx context.Context, input *ExportStackInput) (*huma.StreamResponse, error) {
		return s.exportStack(ctx, input.OrgName, input.ProjectName, input.StackName, nil)
	})

	// --- Export stack version ---
	huma.Register(api, huma.Operation{
		OperationID: "exportStackVersion",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/export/{version}",
		Tags:        []string{"Stacks"},
	}, func(ctx context.Context, input *ExportStackVersionInput) (*huma.StreamResponse, error) {
		version := input.Version
		return s.exportStack(ctx, input.OrgName, input.ProjectName, input.StackName, &version)
	})

	// --- Import stack ---
	huma.Register(api, huma.Operation{
		OperationID:  "importStack",
		Method:       http.MethodPost,
		Path:         "/api/stacks/{orgName}/{projectName}/{stackName}/import",
		Tags:         []string{"Stacks"},
		MaxBodyBytes: 64 << 20, // 64MB
	}, func(ctx context.Context, input *ImportStackInput) (*ImportStackOutput, error) {
		// Copy RawBody: huma returns the underlying buffer to a pool after
		// the handler returns, but the engine caches deployment bytes in an
		// LRU that outlives the request.
		deployment := make(json.RawMessage, len(input.RawBody))
		copy(deployment, input.RawBody)

		result, err := s.engine.CreateUpdate(ctx, input.OrgName, input.ProjectName, input.StackName, "import", nil, nil)
		if err != nil {
			return nil, huma.NewError(http.StatusConflict, err.Error())
		}

		_, err = s.engine.StartUpdate(ctx, result.UpdateID, nil, 0)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}

		err = s.engine.SaveCheckpoint(ctx, result.UpdateID, deployment)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}

		err = s.engine.CompleteUpdate(ctx, result.UpdateID, "succeeded", json.RawMessage(`{}`))
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}

		out := &ImportStackOutput{}
		out.Body.UpdateID = result.UpdateID
		return out, nil
	})

	// --- Stack config ---
	huma.Register(api, huma.Operation{
		OperationID: "getStackConfig",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/config",
		Tags:        []string{"Stacks"},
	}, func(ctx context.Context, input *GetStackConfigInput) (*GetStackConfigOutput, error) {
		return &GetStackConfigOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "updateStackConfig",
		Method:        http.MethodPut,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}/config",
		Tags:          []string{"Stacks"},
		DefaultStatus: 200,
	}, func(ctx context.Context, input *UpdateStackConfigInput) (*struct{}, error) {
		return nil, nil
	})
}
