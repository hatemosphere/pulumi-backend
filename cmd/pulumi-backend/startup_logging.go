package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/audit"
	"github.com/hatemosphere/pulumi-backend/internal/config"
)

// --- Logging ---

func setupLogging(cfg *config.Config) (io.Closer, error) {
	slog.SetDefault(slog.New(newLogHandler(cfg.LogFormat, os.Stdout)))

	var auditCloser io.Closer
	if cfg.AuditLogPath != "" {
		auditHandler, closer, err := openLogDest(cfg.AuditLogPath, cfg.LogFormat)
		if err != nil {
			return nil, fmt.Errorf("open audit log destination %q: %w", cfg.AuditLogPath, err)
		}
		auditCloser = closer
		audit.Logger = slog.New(auditHandler)
		slog.Info("audit log destination configured", "path", cfg.AuditLogPath)
	}

	if !cfg.AuditLogs {
		audit.Enabled = false
	}
	if !cfg.AccessLogs {
		api.AccessLog = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	return auditCloser, nil
}

// openLogDest opens a log destination by path.
func openLogDest(path, format string) (slog.Handler, io.Closer, error) {
	switch path {
	case "stdout":
		return newLogHandler(format, os.Stdout), nil, nil
	case "stderr":
		return newLogHandler(format, os.Stderr), nil, nil
	default:
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) //nolint:gosec
		if err != nil {
			return nil, nil, err
		}
		return newLogHandler(format, f), f, nil
	}
}

func newLogHandler(format string, w io.Writer) slog.Handler {
	if format == "text" {
		return slog.NewTextHandler(w, nil)
	}
	return slog.NewJSONHandler(w, nil)
}
