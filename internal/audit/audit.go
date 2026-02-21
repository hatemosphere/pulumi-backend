package audit

import "log/slog"

// Enabled controls whether audit log entries are emitted. Set to false to
// suppress all audit output (useful in tests that don't exercise auditing).
var Enabled = true

// Event represents a structured audit log entry with typed fields.
// Only non-zero fields are included in the log output.
type Event struct {
	Actor      string // Who performed the action (username or "anonymous").
	Action     string // What was done (operation ID or action name).
	Status     string // Outcome: "granted", "denied", "failed".
	Resource   string // Target resource (e.g. org/project/stack).
	Method     string // HTTP method.
	HTTPStatus int    // HTTP response status code.
	Reason     string // Explanation for denial or failure.
	IP         string // Client IP address.
	AuthMethod string // Authentication method used (e.g. "oidc").
	TargetUser string // Target user for admin operations.
	Extra      []any  // Additional slog attrs for one-off fields.
}

// Info emits the event as an INFO-level structured audit log entry.
func (e Event) Info(msg string) {
	if !Enabled {
		return
	}
	slog.Info(msg, slog.Group("audit", e.attrs()...)) //nolint:gosec // structured logger safely escapes taint
}

// Warn emits the event as a WARN-level structured audit log entry.
func (e Event) Warn(msg string) {
	if !Enabled {
		return
	}
	slog.Warn(msg, slog.Group("audit", e.attrs()...)) //nolint:gosec // structured logger safely escapes taint
}

// attrs builds the slog attribute list, skipping zero-value fields.
func (e Event) attrs() []any {
	var attrs []any
	if e.Actor != "" {
		attrs = append(attrs, slog.String("actor", e.Actor))
	}
	if e.Action != "" {
		attrs = append(attrs, slog.String("action", e.Action))
	}
	if e.Status != "" {
		attrs = append(attrs, slog.String("status", e.Status))
	}
	if e.Resource != "" {
		attrs = append(attrs, slog.String("resource", e.Resource))
	}
	if e.Method != "" {
		attrs = append(attrs, slog.String("method", e.Method))
	}
	if e.HTTPStatus != 0 {
		attrs = append(attrs, slog.Int("http_status", e.HTTPStatus))
	}
	if e.Reason != "" {
		attrs = append(attrs, slog.String("reason", e.Reason))
	}
	if e.IP != "" {
		attrs = append(attrs, slog.String("ip_address", e.IP))
	}
	if e.AuthMethod != "" {
		attrs = append(attrs, slog.String("auth_method", e.AuthMethod))
	}
	if e.TargetUser != "" {
		attrs = append(attrs, slog.String("target_user", e.TargetUser))
	}
	attrs = append(attrs, e.Extra...)
	return attrs
}
