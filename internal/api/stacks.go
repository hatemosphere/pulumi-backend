package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
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
				_, _ = ctx.BodyWriter().Write(deployment)
			},
		}, nil
	}

	return &huma.StreamResponse{
		Body: func(ctx huma.Context) {
			ctx.SetHeader("Content-Type", "application/json")
			if isGzip && strings.Contains(ctx.Header("Accept-Encoding"), "gzip") {
				ctx.SetHeader("Content-Encoding", "gzip")
				_, _ = ctx.BodyWriter().Write(data)
			} else if isGzip {
				// Client doesn't accept gzip; decompress before sending.
				deployment, err := s.engine.ExportState(ctx.Context(), org, project, stack, version)
				if err != nil {
					ctx.SetStatus(http.StatusInternalServerError)
					return
				}
				_, _ = ctx.BodyWriter().Write(deployment)
			} else {
				_, _ = ctx.BodyWriter().Write(data)
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
		Errors:        []int{404},
	}, func(ctx context.Context, input *ProjectExistsInput) (*struct{}, error) {
		exists, err := s.engine.ProjectExists(ctx, input.OrgName, input.ProjectName)
		if err != nil {
			return nil, internalError(err)
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
		Errors:      []int{400, 409},
	}, func(ctx context.Context, input *CreateStackInput) (*CreateStackOutput, error) {
		if input.Body.StackName == "" {
			return nil, huma.NewError(http.StatusBadRequest, "stackName is required")
		}
		if err := validateName(input.OrgName, "organization"); err != nil {
			return nil, huma.NewError(http.StatusBadRequest, err.Error())
		}
		if err := validateName(input.Body.StackName, "stack"); err != nil {
			return nil, huma.NewError(http.StatusBadRequest, err.Error())
		}
		if err := validateName(input.ProjectName, "project"); err != nil {
			return nil, huma.NewError(http.StatusBadRequest, err.Error())
		}

		err := s.engine.CreateStack(ctx, input.OrgName, input.ProjectName, input.Body.StackName, nil)
		if err != nil {
			return nil, huma.NewError(http.StatusConflict, sanitizeError(err))
		}

		stackOperationsTotal.WithLabelValues("create").Inc()
		return &CreateStackOutput{}, nil
	})

	// --- Get stack ---
	huma.Register(api, huma.Operation{
		OperationID: "getStack",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}",
		Tags:        []string{"Stacks"},
		Errors:      []int{404},
	}, func(ctx context.Context, input *GetStackInput) (*GetStackOutput, error) {
		st, err := s.engine.GetStack(ctx, input.OrgName, input.ProjectName, input.StackName)
		if err != nil {
			return nil, internalError(err)
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
		Errors:        []int{400},
	}, func(ctx context.Context, input *DeleteStackInput) (*struct{}, error) {
		err := s.engine.DeleteStack(ctx, input.OrgName, input.ProjectName, input.StackName, input.Force)
		if err != nil {
			return nil, huma.NewError(http.StatusBadRequest, err.Error())
		}
		stackOperationsTotal.WithLabelValues("delete").Inc()
		return nil, nil
	})

	// --- Update stack tags ---
	huma.Register(api, huma.Operation{
		OperationID:   "updateStackTags",
		Method:        http.MethodPatch,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}/tags",
		Tags:          []string{"Stacks"},
		DefaultStatus: 204,
		Errors:        []int{400},
	}, func(ctx context.Context, input *UpdateStackTagsInput) (*struct{}, error) {
		for key := range input.Body {
			if key == "" {
				return nil, huma.NewError(http.StatusBadRequest, "tag key must not be empty")
			}
		}
		err := s.engine.UpdateStackTags(ctx, input.OrgName, input.ProjectName, input.StackName, input.Body)
		if err != nil {
			return nil, internalError(err)
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
		Errors:        []int{400, 409},
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
			if strings.Contains(err.Error(), "already exists") {
				return nil, huma.NewError(http.StatusConflict, "a stack with that name already exists")
			}
			return nil, internalError(err)
		}
		stackOperationsTotal.WithLabelValues("rename").Inc()
		return nil, nil
	})

	// --- Export stack (StreamResponse for zero-copy gzip) ---
	huma.Register(api, huma.Operation{
		OperationID: "exportStack",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/export",
		Tags:        []string{"Stacks"},
		Errors:      []int{404},
	}, func(ctx context.Context, input *ExportStackInput) (*huma.StreamResponse, error) {
		return s.exportStack(ctx, input.OrgName, input.ProjectName, input.StackName, nil)
	})

	// --- Export stack version ---
	huma.Register(api, huma.Operation{
		OperationID: "exportStackVersion",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/export/{version}",
		Tags:        []string{"Stacks"},
		Errors:      []int{400, 404},
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
		Errors:       []int{400, 409},
	}, func(ctx context.Context, input *ImportStackInput) (*ImportStackOutput, error) {
		if len(input.RawBody) == 0 {
			return nil, huma.NewError(http.StatusBadRequest, "request body is required")
		}
		// Copy RawBody: huma pools the buffer, but the engine caches
		// deployment bytes in an LRU that outlives the request.
		deployment := copyBody(input.RawBody)

		result, err := s.engine.CreateUpdate(ctx, input.OrgName, input.ProjectName, input.StackName, "import", nil, nil)
		if err != nil {
			return nil, huma.NewError(http.StatusConflict, sanitizeError(err))
		}

		_, err = s.engine.StartUpdate(ctx, result.UpdateID, nil, 0)
		if err != nil {
			return nil, conflictOrInternalError(err)
		}

		err = s.engine.SaveCheckpoint(ctx, result.UpdateID, deployment)
		if err != nil {
			return nil, conflictOrInternalError(err)
		}

		err = s.engine.CompleteUpdate(ctx, result.UpdateID, "succeeded", json.RawMessage(`{}`))
		if err != nil {
			return nil, conflictOrInternalError(err)
		}

		stackOperationsTotal.WithLabelValues("import").Inc()
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
		Errors:      []int{404},
	}, func(ctx context.Context, input *GetStackConfigInput) (*GetStackConfigOutput, error) {
		st, err := s.engine.GetStack(ctx, input.OrgName, input.ProjectName, input.StackName)
		if err != nil {
			return nil, internalError(err)
		}
		if st == nil {
			return nil, huma.NewError(http.StatusNotFound, "stack not found")
		}
		return &GetStackConfigOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "updateStackConfig",
		Method:        http.MethodPut,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}/config",
		Tags:          []string{"Stacks"},
		DefaultStatus: 200,
		Errors:        []int{400},
	}, func(ctx context.Context, input *UpdateStackConfigInput) (*struct{}, error) {
		return nil, nil
	})
}
