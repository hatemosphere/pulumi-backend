package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/hatemosphere/pulumi-backend/internal/auth"
)

// PulumiError matches the error format the Pulumi CLI expects: {"code": int, "message": string}.
type PulumiError struct {
	status  int
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *PulumiError) Error() string {
	return e.Message
}

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

// conflictOrInternalError returns a 409 for engine state-conflict sentinels,
// otherwise a 500.
func conflictOrInternalError(err error) error {
	if isConflictError(err) {
		return huma.NewError(http.StatusConflict, sanitizeError(err))
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

// ptrString returns a pointer to s.
func ptrString(s string) *string {
	return &s
}
