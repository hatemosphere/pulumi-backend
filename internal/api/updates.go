package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"encoding/json"
)

func (s *Server) registerUpdates(api huma.API) {
	// --- Create update (4 kinds) ---
	for _, kind := range []string{"preview", "update", "refresh", "destroy"} {
		kind := kind // capture loop variable
		huma.Register(api, huma.Operation{
			OperationID: "create" + ucfirst(kind),
			Method:      http.MethodPost,
			Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/" + kind,
			Tags:        []string{"Updates"},
		}, func(ctx context.Context, input *CreateUpdateInput) (*CreateUpdateOutput, error) {
			// Extract config/metadata from raw body to preserve all fields
			// (the typed Body is used only for OpenAPI schema generation).
			var raw struct {
				Config   json.RawMessage `json:"config"`
				Metadata json.RawMessage `json:"metadata"`
			}
			json.Unmarshal(input.RawBody, &raw)
			result, err := s.engine.CreateUpdate(ctx, input.OrgName, input.ProjectName, input.StackName, kind, raw.Config, raw.Metadata)
			if err != nil {
				return nil, huma.NewError(http.StatusConflict, err.Error())
			}
			out := &CreateUpdateOutput{}
			out.Body.UpdateID = result.UpdateID
			out.Body.RequiredPolicies = []RequiredPolicy{}
			out.Body.Messages = []Message{}
			return out, nil
		})
	}

	// --- Start update ---
	huma.Register(api, huma.Operation{
		OperationID: "startUpdate",
		Method:      http.MethodPost,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}",
		Tags:        []string{"Updates"},
	}, func(ctx context.Context, input *StartUpdateInput) (*StartUpdateOutput, error) {
		result, err := s.engine.StartUpdate(ctx, input.UpdateID, input.Body.Tags, input.Body.JournalVersion)
		if err != nil {
			return nil, huma.NewError(http.StatusConflict, err.Error())
		}
		out := &StartUpdateOutput{}
		out.Body.Version = result.Version
		out.Body.Token = result.Token
		out.Body.TokenExpiration = result.TokenExpiration
		out.Body.JournalVersion = result.JournalVersion
		return out, nil
	})

	// --- Get update status ---
	huma.Register(api, huma.Operation{
		OperationID: "getUpdateStatus",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}",
		Tags:        []string{"Updates"},
	}, func(ctx context.Context, input *GetUpdateStatusInput) (*GetUpdateStatusOutput, error) {
		u, err := s.engine.GetUpdate(ctx, input.UpdateID)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		if u == nil {
			return nil, huma.NewError(http.StatusNotFound, "update not found")
		}

		out := &GetUpdateStatusOutput{}
		out.Body.Status = u.Status
		out.Body.Events = []any{}
		if u.Status == "in-progress" || u.Status == "not-started" {
			token := ""
			out.Body.ContinuationToken = &token
		}
		return out, nil
	})

	// --- Complete update ---
	huma.Register(api, huma.Operation{
		OperationID:   "completeUpdate",
		Method:        http.MethodPost,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/complete",
		Tags:          []string{"Updates"},
		DefaultStatus: 200,
	}, func(ctx context.Context, input *CompleteUpdateInput) (*struct{}, error) {
		err := s.engine.CompleteUpdate(ctx, input.UpdateID, input.Body.Status, input.Body.Result)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		return nil, nil
	})

	// --- Renew lease ---
	huma.Register(api, huma.Operation{
		OperationID: "renewLease",
		Method:      http.MethodPost,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/renew_lease",
		Tags:        []string{"Updates"},
	}, func(ctx context.Context, input *RenewLeaseInput) (*RenewLeaseOutput, error) {
		duration := time.Duration(input.Body.Duration) * time.Second
		result, err := s.engine.RenewLease(ctx, input.UpdateID, duration)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		out := &RenewLeaseOutput{}
		out.Body.Token = result.Token
		out.Body.TokenExpiration = result.TokenExpiration
		return out, nil
	})

	// --- Cancel update ---
	huma.Register(api, huma.Operation{
		OperationID:   "cancelUpdate",
		Method:        http.MethodPost,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/cancel",
		Tags:          []string{"Updates"},
		DefaultStatus: 200,
	}, func(ctx context.Context, input *CancelUpdateInput) (*struct{}, error) {
		err := s.engine.CancelUpdate(ctx, input.OrgName, input.ProjectName, input.StackName)
		if err != nil {
			return nil, huma.NewError(http.StatusConflict, err.Error())
		}
		return nil, nil
	})

	// --- Checkpoints ---

	huma.Register(api, huma.Operation{
		OperationID:   "patchCheckpoint",
		Method:        http.MethodPatch,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/checkpoint",
		Tags:          []string{"Checkpoints"},
		MaxBodyBytes:  64 << 20,
		DefaultStatus: 200,
	}, func(ctx context.Context, input *PatchCheckpointInput) (*struct{}, error) {
		if input.Body.IsInvalid {
			return nil, nil
		}

		envelope := map[string]any{
			"version":    input.Body.Version,
			"deployment": input.Body.Deployment,
		}
		if len(input.Body.Features) > 0 {
			envelope["features"] = input.Body.Features
		}
		full, _ := json.Marshal(envelope)

		err := s.engine.SaveCheckpoint(ctx, input.UpdateID, full)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "patchCheckpointVerbatim",
		Method:        http.MethodPatch,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/checkpointverbatim",
		Tags:          []string{"Checkpoints"},
		MaxBodyBytes:  64 << 20,
		DefaultStatus: 200,
	}, func(ctx context.Context, input *PatchCheckpointVerbatimInput) (*struct{}, error) {
		err := s.engine.SaveCheckpoint(ctx, input.UpdateID, input.Body.UntypedDeployment)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "patchCheckpointDelta",
		Method:        http.MethodPatch,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/checkpointdelta",
		Tags:          []string{"Checkpoints"},
		MaxBodyBytes:  64 << 20,
		DefaultStatus: 200,
	}, func(ctx context.Context, input *PatchCheckpointDeltaInput) (*struct{}, error) {
		err := s.engine.SaveCheckpointDelta(ctx, input.UpdateID, input.Body.CheckpointHash, input.Body.DeploymentDelta, input.Body.SequenceNumber)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		return nil, nil
	})

	// --- Journal Entries ---

	huma.Register(api, huma.Operation{
		OperationID:   "saveJournalEntries",
		Method:        http.MethodPatch,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/journalentries",
		Tags:          []string{"Journal"},
		MaxBodyBytes:  16 << 20,
		DefaultStatus: 200,
	}, func(ctx context.Context, input *SaveJournalEntriesInput) (*struct{}, error) {
		var req struct {
			Entries []json.RawMessage `json:"entries"`
		}
		if err := json.Unmarshal(input.RawBody, &req); err != nil {
			return nil, huma.NewError(http.StatusBadRequest, err.Error())
		}

		err := s.engine.SaveJournalEntries(ctx, input.UpdateID, req.Entries)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		return nil, nil
	})

	// --- Engine Events ---

	huma.Register(api, huma.Operation{
		OperationID:   "postEvent",
		Method:        http.MethodPost,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/events",
		Tags:          []string{"Events"},
		MaxBodyBytes:  4 << 20,
		DefaultStatus: 200,
	}, func(ctx context.Context, input *PostEventInput) (*struct{}, error) {
		// Copy RawBody: huma returns the underlying buffer to a pool after
		// the handler returns, but SaveEngineEvents buffers events
		// asynchronously, so we must own our own copy of the bytes.
		event := make(json.RawMessage, len(input.RawBody))
		copy(event, input.RawBody)
		err := s.engine.SaveEngineEvents(ctx, input.UpdateID, []json.RawMessage{event})
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "postEventsBatch",
		Method:        http.MethodPost,
		Path:          "/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/events/batch",
		Tags:          []string{"Events"},
		MaxBodyBytes:  16 << 20,
		DefaultStatus: 200,
	}, func(ctx context.Context, input *PostEventsBatchInput) (*struct{}, error) {
		err := s.engine.SaveEngineEvents(ctx, input.UpdateID, input.Body.Events)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		return nil, nil
	})

	// --- Get events ---
	huma.Register(api, huma.Operation{
		OperationID: "getEvents",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/events",
		Tags:        []string{"Events"},
	}, func(ctx context.Context, input *GetEventsInput) (*GetEventsOutput, error) {
		u, err := s.engine.GetUpdate(ctx, input.UpdateID)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		if u == nil {
			return nil, huma.NewError(http.StatusNotFound, "update not found")
		}

		var offset int
		if input.ContinuationToken != "" {
			offset, _ = strconv.Atoi(input.ContinuationToken)
		}

		events, err := s.engine.GetEngineEvents(ctx, input.UpdateID, offset, 100)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}

		eventPayloads := make([]json.RawMessage, len(events))
		for i, e := range events {
			eventPayloads[i] = e.Event
		}

		out := &GetEventsOutput{}
		out.Body.Status = u.Status
		out.Body.Events = eventPayloads

		if u.Status == "in-progress" || u.Status == "not-started" {
			nextOffset := strconv.Itoa(offset + len(events))
			out.Body.ContinuationToken = &nextOffset
		}
		return out, nil
	})
}

// --- History ---

func (s *Server) registerHistory(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "getUpdates",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/updates",
		Tags:        []string{"History"},
	}, func(ctx context.Context, input *GetUpdatesInput) (*GetUpdatesOutput, error) {
		pageSize := input.PageSize
		if pageSize <= 0 {
			pageSize = s.historyPageSize
		}

		history, err := s.engine.GetHistory(ctx, input.OrgName, input.ProjectName, input.StackName, pageSize, input.Page)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}

		updates := make([]UpdateSummary, 0, len(history))
		for _, h := range history {
			u := UpdateSummary{
				Kind:      h.Kind,
				Result:    h.Status,
				Message:   h.Message,
				Version:   h.Version,
				StartTime: h.StartTime.Unix(),
			}
			if h.EndTime != nil {
				endTime := h.EndTime.Unix()
				u.EndTime = &endTime
			}
			if len(h.ResourceChanges) > 0 {
				u.ResourceChanges = json.RawMessage(h.ResourceChanges)
			}
			if len(h.Environment) > 0 {
				var env map[string]string
				if json.Unmarshal(h.Environment, &env) == nil {
					u.Environment = env
				}
			}
			if len(h.Config) > 0 {
				var cfg map[string]any
				if json.Unmarshal(h.Config, &cfg) == nil {
					u.Config = cfg
				}
			}
			updates = append(updates, u)
		}

		out := &GetUpdatesOutput{}
		out.Body.Updates = updates
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "getLatestUpdate",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/updates/latest",
		Tags:        []string{"History"},
	}, func(ctx context.Context, input *GetLatestUpdateInput) (*GetLatestUpdateOutput, error) {
		history, err := s.engine.GetHistory(ctx, input.OrgName, input.ProjectName, input.StackName, 1, 0)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		if len(history) == 0 {
			return nil, huma.NewError(http.StatusNotFound, "no updates found")
		}

		h := history[0]
		info := UpdateInfo{
			Kind:      h.Kind,
			Result:    h.Status,
			Message:   h.Message,
			Version:   h.Version,
			StartTime: h.StartTime.Unix(),
		}
		if h.EndTime != nil {
			endTime := h.EndTime.Unix()
			info.EndTime = &endTime
		}
		if len(h.Config) > 0 {
			var cfg map[string]any
			if json.Unmarshal(h.Config, &cfg) == nil {
				info.Config = cfg
			}
		}

		out := &GetLatestUpdateOutput{}
		out.Body.Info = info
		out.Body.UpdateID = h.UpdateID
		out.Body.Version = h.Version
		out.Body.LatestVersion = h.Version
		out.Body.RequestedBy = RequestedBy{
			Name:        s.defaultUser,
			GitHubLogin: s.defaultUser,
			AvatarURL:   "",
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "getUpdateByVersion",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/updates/{version}",
		Tags:        []string{"History"},
	}, func(ctx context.Context, input *GetUpdateByVersionInput) (*GetUpdateByVersionOutput, error) {
		h, err := s.engine.GetHistoryByVersion(ctx, input.OrgName, input.ProjectName, input.StackName, input.Version)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		if h == nil {
			return nil, huma.NewError(http.StatusNotFound, "update not found")
		}

		info := UpdateInfo{
			Kind:      h.Kind,
			Result:    h.Status,
			Message:   h.Message,
			Version:   h.Version,
			StartTime: h.StartTime.Unix(),
		}
		if h.EndTime != nil {
			endTime := h.EndTime.Unix()
			info.EndTime = &endTime
		}
		if len(h.ResourceChanges) > 0 {
			info.ResourceChanges = json.RawMessage(h.ResourceChanges)
		}

		out := &GetUpdateByVersionOutput{}
		out.Body.Info = info
		out.Body.UpdateID = h.UpdateID
		out.Body.Version = h.Version
		out.Body.LatestVersion = h.Version
		out.Body.RequestedBy = RequestedBy{
			Name:        s.defaultUser,
			GitHubLogin: s.defaultUser,
			AvatarURL:   "",
		}
		return out, nil
	})
}

// --- Admin ---

func (s *Server) registerAdmin(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "createBackup",
		Method:      http.MethodPost,
		Path:        "/api/admin/backup",
		Tags:        []string{"Admin"},
	}, func(ctx context.Context, input *struct{}) (*CreateBackupOutput, error) {
		path, err := s.engine.Backup(ctx)
		if err != nil {
			return nil, huma.NewError(http.StatusInternalServerError, err.Error())
		}
		out := &CreateBackupOutput{}
		out.Body.Path = path
		return out, nil
	})
}

// ucfirst capitalizes the first character of a string.
func ucfirst(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]-32) + s[1:]
}
