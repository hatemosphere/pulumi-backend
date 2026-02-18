package api

import (
	"github.com/danielgtaylor/huma/v2"
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
