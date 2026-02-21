package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/hatemosphere/pulumi-backend/internal/audit"
	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

var uuidPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// isConflictError returns true if err is an engine state-conflict sentinel.
func isConflictError(err error) bool {
	return errors.Is(err, engine.ErrUpdateNotInProgress) ||
		errors.Is(err, engine.ErrStackHasActiveUpdate) ||
		errors.Is(err, engine.ErrNoActiveUpdate)
}

// sanitizeError returns a client-safe error message.
// Sentinel errors pass through. Internal errors are scrubbed of UUIDs and SQL details.
func sanitizeError(err error) string {
	if isConflictError(err) {
		return err.Error()
	}
	msg := err.Error()
	for _, indicator := range []string{
		"UNIQUE constraint", "no such table", "database is locked",
		"SQLITE_", "sql:", "constraint failed",
	} {
		if strings.Contains(msg, indicator) {
			return "internal error"
		}
	}
	if uuidPattern.MatchString(msg) {
		return "internal error"
	}
	return msg
}

func (s *Server) registerUpdates(api huma.API) {
	// --- Create update (4 kinds) ---
	for _, kind := range []string{"preview", "update", "refresh", "destroy"} {
		huma.Register(api, huma.Operation{
			OperationID: "create" + ucfirst(kind),
			Method:      http.MethodPost,
			Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/" + kind,
			Tags:        []string{"Updates"},
			Errors:      []int{409},
		}, func(ctx context.Context, input *CreateUpdateInput) (*CreateUpdateOutput, error) {
			// Extract config/metadata from raw body to preserve all fields
			// (the typed Body is used only for OpenAPI schema generation).
			var raw struct {
				Config   json.RawMessage `json:"config"`
				Metadata json.RawMessage `json:"metadata"`
			}
			if err := json.Unmarshal(input.RawBody, &raw); err != nil {
				slog.Warn("failed to extract config/metadata from request body", "error", err)
			}
			result, err := s.engine.CreateUpdate(ctx, input.OrgName, input.ProjectName, input.StackName, kind, raw.Config, raw.Metadata)
			if err != nil {
				return nil, huma.NewError(http.StatusConflict, sanitizeError(err))
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
		Errors:      []int{409},
	}, func(ctx context.Context, input *StartUpdateInput) (*StartUpdateOutput, error) {
		result, err := s.engine.StartUpdate(ctx, input.UpdateID, input.Body.Tags, input.Body.JournalVersion)
		if err != nil {
			return nil, huma.NewError(http.StatusConflict, sanitizeError(err))
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
		Errors:      []int{404},
	}, func(ctx context.Context, input *GetUpdateStatusInput) (*GetUpdateStatusOutput, error) {
		u, err := s.engine.GetUpdate(ctx, input.UpdateID)
		if err != nil {
			return nil, internalError(err)
		}
		if u == nil {
			return nil, huma.NewError(http.StatusNotFound, "update not found")
		}

		out := &GetUpdateStatusOutput{}
		out.Body.Status = u.Status
		out.Body.Events = []any{}
		if u.Status == "in-progress" || u.Status == "not-started" {
			out.Body.ContinuationToken = ptrString("")
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
		Errors:        []int{409},
	}, func(ctx context.Context, input *CompleteUpdateInput) (*struct{}, error) {
		err := s.engine.CompleteUpdate(ctx, input.UpdateID, input.Body.Status, input.Body.Result)
		if err != nil {
			return nil, conflictOrInternalError(err)
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
			return nil, internalError(err)
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
		Errors:        []int{409},
	}, func(ctx context.Context, input *CancelUpdateInput) (*struct{}, error) {
		err := s.engine.CancelUpdate(ctx, input.OrgName, input.ProjectName, input.StackName)
		if err != nil {
			return nil, huma.NewError(http.StatusConflict, sanitizeError(err))
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
		Errors:        []int{409},
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
			return nil, conflictOrInternalError(err)
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
		Errors:        []int{409},
	}, func(ctx context.Context, input *PatchCheckpointVerbatimInput) (*struct{}, error) {
		err := s.engine.SaveCheckpoint(ctx, input.UpdateID, input.Body.UntypedDeployment)
		if err != nil {
			return nil, conflictOrInternalError(err)
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
		Errors:        []int{409},
	}, func(ctx context.Context, input *PatchCheckpointDeltaInput) (*struct{}, error) {
		err := s.engine.SaveCheckpointDelta(ctx, input.UpdateID, input.Body.CheckpointHash, input.Body.DeploymentDelta, input.Body.SequenceNumber)
		if err != nil {
			return nil, conflictOrInternalError(err)
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
		Errors:        []int{400},
	}, func(ctx context.Context, input *SaveJournalEntriesInput) (*struct{}, error) {
		var req struct {
			Entries []json.RawMessage `json:"entries"`
		}
		if err := json.Unmarshal(input.RawBody, &req); err != nil {
			return nil, huma.NewError(http.StatusBadRequest, err.Error())
		}

		err := s.engine.SaveJournalEntries(ctx, input.UpdateID, req.Entries)
		if err != nil {
			return nil, internalError(err)
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
		// Copy RawBody: huma pools the buffer, but SaveEngineEvents
		// buffers events asynchronously beyond the handler lifetime.
		event := copyBody(input.RawBody)
		err := s.engine.SaveEngineEvents(ctx, input.UpdateID, []json.RawMessage{event})
		if err != nil {
			return nil, internalError(err)
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
			return nil, internalError(err)
		}
		return nil, nil
	})

	// --- Get events ---
	huma.Register(api, huma.Operation{
		OperationID: "getEvents",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/{updateKind}/{updateID}/events",
		Tags:        []string{"Events"},
		Errors:      []int{404},
	}, func(ctx context.Context, input *GetEventsInput) (*GetEventsOutput, error) {
		u, err := s.engine.GetUpdate(ctx, input.UpdateID)
		if err != nil {
			return nil, internalError(err)
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
			return nil, internalError(err)
		}

		eventPayloads := make([]json.RawMessage, len(events))
		for i, e := range events {
			eventPayloads[i] = e.Event
		}

		out := &GetEventsOutput{}
		out.Body.Status = u.Status
		out.Body.Events = eventPayloads

		if u.Status == "in-progress" || u.Status == "not-started" {
			out.Body.ContinuationToken = ptrString(strconv.Itoa(offset + len(events)))
		}
		return out, nil
	})
}

// --- History ---

// historyToUpdateInfo converts a storage.UpdateHistory to an UpdateInfo.
func historyToUpdateInfo(h *storage.UpdateHistory) UpdateInfo {
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
	if len(h.Environment) > 0 {
		var env map[string]string
		if json.Unmarshal(h.Environment, &env) == nil {
			info.Environment = env
		}
	}
	if len(h.Config) > 0 {
		var cfg map[string]any
		if json.Unmarshal(h.Config, &cfg) == nil {
			info.Config = cfg
		}
	}
	return info
}

func (s *Server) registerHistory(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "getUpdates",
		Method:      http.MethodGet,
		Path:        "/api/stacks/{orgName}/{projectName}/{stackName}/updates",
		Tags:        []string{"History"},
		Errors:      []int{400},
	}, func(ctx context.Context, input *GetUpdatesInput) (*GetUpdatesOutput, error) {
		if input.Page < 0 {
			return nil, huma.NewError(http.StatusBadRequest, "Invalid 'page' value.")
		}
		if input.PageSize < 0 {
			return nil, huma.NewError(http.StatusBadRequest, "Invalid 'pageSize' value.")
		}
		pageSize := input.PageSize
		if pageSize <= 0 {
			pageSize = s.historyPageSize
		}

		history, err := s.engine.GetHistory(ctx, input.OrgName, input.ProjectName, input.StackName, pageSize, input.Page)
		if err != nil {
			return nil, internalError(err)
		}

		updates := make([]UpdateSummary, 0, len(history))
		for _, h := range history {
			info := historyToUpdateInfo(&h)
			updates = append(updates, info)
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
		Errors:      []int{404},
	}, func(ctx context.Context, input *GetLatestUpdateInput) (*GetLatestUpdateOutput, error) {
		history, err := s.engine.GetHistory(ctx, input.OrgName, input.ProjectName, input.StackName, 1, 0)
		if err != nil {
			return nil, internalError(err)
		}
		if len(history) == 0 {
			return nil, huma.NewError(http.StatusNotFound, "no updates found")
		}

		h := history[0]
		out := &GetLatestUpdateOutput{}
		out.Body.Info = historyToUpdateInfo(&h)
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
		Errors:      []int{404},
	}, func(ctx context.Context, input *GetUpdateByVersionInput) (*GetUpdateByVersionOutput, error) {
		h, err := s.engine.GetHistoryByVersion(ctx, input.OrgName, input.ProjectName, input.StackName, input.Version)
		if err != nil {
			return nil, internalError(err)
		}
		if h == nil {
			return nil, huma.NewError(http.StatusNotFound, "update not found")
		}

		out := &GetUpdateByVersionOutput{}
		out.Body.Info = historyToUpdateInfo(h)
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

// requireAdmin checks that the authenticated user has admin access. In single-tenant
// mode this is always true (IsAdmin flag). In Google/JWT mode, admin is granted via
// RBAC (group with "admin" permission).
func (s *Server) requireAdmin(ctx context.Context) error {
	identity := auth.IdentityFromContext(ctx)
	if identity == nil {
		return huma.NewError(http.StatusForbidden, "admin access required")
	}
	if identity.IsAdmin {
		return nil
	}
	// In RBAC mode, check if the user has a global admin role (empty stack path).
	if s.rbac != nil {
		perm := s.rbac.Resolve(identity, "", "", "")
		if perm >= auth.PermissionAdmin {
			return nil
		}
	}
	return huma.NewError(http.StatusForbidden, "admin access required")
}

func (s *Server) registerAdmin(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "createBackup",
		Method:      http.MethodPost,
		Path:        "/api/admin/backup",
		Tags:        []string{"Admin"},
	}, func(ctx context.Context, input *struct{}) (*CreateBackupOutput, error) {
		if err := s.requireAdmin(ctx); err != nil {
			return nil, err
		}
		path, err := s.engine.Backup(ctx)
		if err != nil {
			return nil, internalError(err)
		}
		out := &CreateBackupOutput{}
		out.Body.Path = path
		return out, nil
	})

	// Token management (only available in Google auth mode with a token store).
	if s.tokenStore != nil {
		s.registerAdminTokens(api)
	}
}

func (s *Server) registerAdminTokens(api huma.API) {
	// List a user's tokens (admin only).
	huma.Register(api, huma.Operation{
		OperationID: "listUserTokens",
		Method:      http.MethodGet,
		Path:        "/api/admin/tokens/{userName}",
		Tags:        []string{"Admin"},
	}, func(ctx context.Context, input *ListUserTokensInput) (*ListUserTokensOutput, error) {
		if err := s.requireAdmin(ctx); err != nil {
			return nil, err
		}

		tokens, err := s.tokenStore.ListTokensByUser(ctx, input.UserName)
		if err != nil {
			return nil, internalError(err)
		}

		out := &ListUserTokensOutput{}
		for _, t := range tokens {
			info := AdminTokenInfo{
				TokenHashPrefix: t.TokenHash[:min(8, len(t.TokenHash))],
				Description:     t.Description,
				CreatedAt:       t.CreatedAt.Unix(),
				HasRefreshToken: t.RefreshToken != "",
			}
			if t.LastUsedAt != nil {
				lu := t.LastUsedAt.Unix()
				info.LastUsedAt = &lu
			}
			if t.ExpiresAt != nil {
				ea := t.ExpiresAt.Unix()
				info.ExpiresAt = &ea
			}
			out.Body.Tokens = append(out.Body.Tokens, info)
		}
		return out, nil
	})

	// Revoke all tokens for a user (admin only).
	huma.Register(api, huma.Operation{
		OperationID: "revokeUserTokens",
		Method:      http.MethodDelete,
		Path:        "/api/admin/tokens/{userName}",
		Tags:        []string{"Admin"},
	}, func(ctx context.Context, input *RevokeUserTokensInput) (*RevokeUserTokensOutput, error) {
		if err := s.requireAdmin(ctx); err != nil {
			return nil, err
		}

		identity := auth.IdentityFromContext(ctx)
		revoked, err := s.tokenStore.DeleteTokensByUser(ctx, input.UserName)
		if err != nil {
			return nil, internalError(err)
		}

		audit.Event{
			Actor:      identity.UserName,
			Action:     "revokeUserTokens",
			TargetUser: input.UserName,
			Extra:      []any{slog.Int64("revoked_count", revoked)},
		}.Info("Audit Log: Token Revocation")

		out := &RevokeUserTokensOutput{}
		out.Body.Revoked = revoked
		return out, nil
	})
}

// ucfirst capitalizes the first character of a string.
func ucfirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
