package api

import (
	"context"
	"net/http"

	"github.com/segmentio/encoding/json"

	"github.com/danielgtaylor/huma/v2"

	"github.com/hatemosphere/pulumi-backend/internal/auth"
)

// PulumiError matches the error format the Pulumi CLI expects: {"code": int, "message": string}.
type PulumiError struct {
	status  int
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Error returns the error message.
func (e *PulumiError) Error() string {
	return e.Message
}

// GetStatus implements huma.StatusError.
func (e *PulumiError) GetStatus() int {
	return e.status
}

func init() {
	huma.NewError = func(status int, msg string, errs ...error) huma.StatusError {
		if len(errs) > 0 && msg == "" {
			msg = errs[0].Error()
		}
		return &PulumiError{
			status:  status,
			Code:    status,
			Message: msg,
		}
	}
}

// internalError returns a 500 error with a sanitized message.
func internalError(err error) error {
	return huma.NewError(http.StatusInternalServerError, sanitizeError(err))
}

func badRequestError(err error) error {
	return huma.NewError(http.StatusBadRequest, sanitizeError(err))
}

// conflictError returns a 409 error with a sanitized message.
func conflictError(err error) error {
	return huma.NewError(http.StatusConflict, sanitizeError(err))
}

// conflictOrInternalError returns a 409 for engine state-conflict sentinels,
// otherwise a 500.
func conflictOrInternalError(err error) error {
	if isConflictError(err) {
		return conflictError(err)
	}
	return internalError(err)
}

func stackNotFoundError() error {
	return huma.NewError(http.StatusNotFound, "stack not found")
}

func updateNotFoundError() error {
	return huma.NewError(http.StatusNotFound, "update not found")
}

func stackNotFoundOrInternalError(err error) error {
	if isNotFoundError(err) {
		return stackNotFoundError()
	}
	return internalError(err)
}

func updateNotFoundOrInternalError(err error) error {
	if isNotFoundError(err) {
		return updateNotFoundError()
	}
	return internalError(err)
}

// requireIdentity extracts the authenticated user from the context,
// returning a 401 if no identity is present.
func requireIdentity(ctx context.Context) (*auth.UserIdentity, error) {
	identity := auth.IdentityFromContext(ctx)
	if identity == nil {
		return nil, huma.NewError(http.StatusUnauthorized, "authentication required")
	}
	return identity, nil
}

// copyBody returns a copy of src that is safe to store beyond the handler
// lifetime. huma pools request body buffers, so any RawBody stored
// asynchronously must be copied.
func copyBody(src []byte) json.RawMessage {
	dst := make(json.RawMessage, len(src))
	copy(dst, src)
	return dst
}
