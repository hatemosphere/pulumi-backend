package main

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/segmentio/encoding/json"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/audit"
	"github.com/hatemosphere/pulumi-backend/internal/config"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Set by goreleaser ldflags.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	cfg, err := config.Parse()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := validateRuntimeConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(1)
	}

	// Configure logging format.
	var logHandler slog.Handler
	if cfg.LogFormat == "text" {
		logHandler = slog.NewTextHandler(os.Stdout, nil)
	} else {
		logHandler = slog.NewJSONHandler(os.Stdout, nil)
	}
	slog.SetDefault(slog.New(logHandler))

	// Configure audit logger destination.
	if cfg.AuditLogPath != "" {
		auditHandler, auditCloser, err := openLogDest(cfg.AuditLogPath, cfg.LogFormat)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open audit log destination: %v\n", err)
			os.Exit(1)
		}
		if auditCloser != nil {
			defer auditCloser.Close()
		}
		audit.Logger = slog.New(auditHandler)
		slog.Info("audit log destination configured", "path", cfg.AuditLogPath)
	}

	// Disable audit logging if configured.
	if !cfg.AuditLogs {
		audit.Enabled = false
	}

	// Disable access logging if configured.
	if !cfg.AccessLogs {
		api.AccessLog = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Open storage.
	store, err := storage.NewSQLiteStore(cfg.DBPath, storage.SQLiteStoreConfig{
		MaxStateVersions:  cfg.MaxStateVersions,
		StackListPageSize: cfg.StackListPageSize,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	// Create secrets provider.
	secretsProvider, err := buildSecretsProvider(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create secrets provider: %v\n", err)
		os.Exit(1)
	}
	if closer, ok := secretsProvider.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	// Secrets key migration: re-wrap all per-stack DEKs from old to new provider, then exit.
	if cfg.MigrateSecretsKey {
		oldProvider, err := buildOldSecretsProvider(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to build old secrets provider: %v\n", err)
			os.Exit(1)
		}
		if closer, ok := oldProvider.(interface{ Close() error }); ok {
			defer closer.Close()
		}

		// Verify the old provider can decrypt the existing canary.
		if err := verifySecretsProvider(store, oldProvider); err != nil {
			fmt.Fprintf(os.Stderr, "old secrets provider verification failed (cannot decrypt existing data): %v\n", err)
			os.Exit(1)
		}

		if err := migrateSecretsKeys(store, oldProvider, secretsProvider); err != nil {
			fmt.Fprintf(os.Stderr, "secrets key migration failed: %v\n", err)
			os.Exit(1)
		}

		// Verify the new provider works before clearing the old canary.
		// This ensures we don't lose the canary if the new provider is misconfigured.
		if err := verifyNewProvider(secretsProvider); err != nil {
			fmt.Fprintf(os.Stderr, "new secrets provider verification failed: %v\n", err)
			os.Exit(1)
		}
		// Now safe to replace the canary: clear old, then store new.
		if err := store.SetConfig(context.Background(), "secrets_canary", ""); err != nil {
			fmt.Fprintf(os.Stderr, "failed to clear old canary: %v\n", err)
			os.Exit(1)
		}
		if err := verifySecretsProvider(store, secretsProvider); err != nil {
			fmt.Fprintf(os.Stderr, "failed to store new canary: %v\n", err)
			os.Exit(1)
		}

		slog.Info("secrets key migration complete")
		store.Close()
		os.Exit(0)
	}

	// Verify the secrets provider can decrypt existing data (canary check).
	if err := verifySecretsProvider(store, secretsProvider); err != nil {
		fmt.Fprintf(os.Stderr, "secrets provider verification failed: %v\n", err)
		os.Exit(1)
	}

	secrets := engine.NewSecretsEngine(secretsProvider)

	// Set up backup provider from destination URI.
	backupProviders, err := buildBackupProviders(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create backup provider: %v\n", err)
		os.Exit(1)
	}

	// Create engine manager.
	mgr, err := engine.NewManager(store, secrets, engine.ManagerConfig{
		LeaseDuration:      cfg.LeaseDuration,
		CacheSize:          cfg.CacheSize,
		EventBufferSize:    cfg.EventBufferSize,
		EventFlushInterval: cfg.EventFlushInterval,
		BackupDir:          cfg.BackupDir,
		BackupProviders:    backupProviders,
		BackupSchedule:     cfg.BackupSchedule,
		BackupRetention:    cfg.BackupRetention,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create engine: %v\n", err)
		os.Exit(1)
	}

	// Register Prometheus active-updates gauge.
	api.RegisterActiveUpdatesGauge(func() float64 {
		return float64(mgr.ActiveUpdateCount())
	})

	// Create API server.
	serverOpts, err := buildServerOptions(context.Background(), cfg, store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build server options: %v\n", err)
		os.Exit(1)
	}

	// Initialize OpenTelemetry tracing if configured.
	tp, err := initializeTracer(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize OpenTelemetry: %v\n", err)
		os.Exit(1)
	}

	srv := api.NewServer(mgr, cfg.DefaultOrg, cfg.DefaultUser, serverOpts...)

	handler := srv.Router()
	if tp != nil {
		handler = otelhttp.NewHandler(handler, "pulumi-backend")
	}

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start separate management server for health probes and metrics.
	var mgmtServer *http.Server
	if cfg.ManagementAddr != "" {
		mgmtMux := http.NewServeMux()
		mgmtMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		})
		mgmtMux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
			if err := mgr.Ping(r.Context()); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "error"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		})
		mgmtMux.Handle("GET /metrics", api.MetricsHandler())

		mgmtServer = &http.Server{
			Addr:              cfg.ManagementAddr,
			Handler:           mgmtMux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			slog.Info("management server starting", "addr", cfg.ManagementAddr)
			if err := mgmtServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("management server error", "error", err)
			}
		}()
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	done := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("shutting down", "signal", sig.String())

		// Give in-flight requests 30 seconds to complete.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if mgmtServer != nil {
			if err := mgmtServer.Shutdown(ctx); err != nil {
				slog.Error("management server shutdown error", "error", err)
			}
		}
		if err := httpServer.Shutdown(ctx); err != nil {
			slog.Error("http server shutdown error", "error", err)
		}
		close(done)
	}()

	slog.Info("pulumi backend starting", "addr", cfg.Addr, "version", version, "commit", commit)
	slog.Info("login command", "cmd", "pulumi login http://localhost"+cfg.Addr) //nolint:gosec // structured logger

	if cfg.TLS {
		err = httpServer.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	} else {
		err = httpServer.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}

	// Wait for shutdown to complete.
	<-done

	// Flush buffered events, shut down tracing, and close storage.
	slog.Info("flushing events and closing storage")
	mgr.Shutdown()
	if tp != nil {
		if err := tp.Shutdown(context.Background()); err != nil {
			slog.Error("tracer provider shutdown error", "error", err)
		}
	}
	slog.Info("shutdown complete")
}

func parseCSVList(s string) []string {
	var result []string
	for v := range strings.SplitSeq(s, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			result = append(result, v)
		}
	}
	return result
}

// canaryPlaintext is a known value used to verify the secrets provider on startup.
const canaryPlaintext = "pulumi-backend-secrets-canary"

// verifySecretsProvider checks that the current secrets provider can decrypt a
// previously stored canary value. On first run (no canary in DB), it creates
// one. On subsequent runs, it verifies decryption succeeds — a mismatch means
// the wrong key/KMS was provided, and all secrets would be undecryptable.
func verifySecretsProvider(store *storage.SQLiteStore, provider engine.SecretsProvider) error {
	ctx := context.Background()

	storedCanary, err := store.GetConfig(ctx, "secrets_canary")
	if err != nil {
		return fmt.Errorf("read canary from database: %w", err)
	}

	if storedCanary == "" {
		// First run — encrypt and store the canary.
		ciphertext, err := provider.WrapKey(ctx, []byte(canaryPlaintext))
		if err != nil {
			return fmt.Errorf("encrypt canary: %w", err)
		}
		canaryHex := hex.EncodeToString(ciphertext)
		if err := store.SetConfig(ctx, "secrets_canary", canaryHex); err != nil {
			return fmt.Errorf("store canary in database: %w", err)
		}
		slog.Info("secrets provider canary stored", "provider", provider.ProviderName())
		return nil
	}

	// Subsequent run — verify the provider can decrypt the canary.
	ciphertext, err := hex.DecodeString(storedCanary)
	if err != nil {
		return fmt.Errorf("decode stored canary: %w", err)
	}
	plaintext, err := provider.UnwrapKey(ctx, ciphertext)
	if err != nil {
		return fmt.Errorf("wrong secrets key: cannot decrypt verification canary (%s provider, did the key change?)", provider.ProviderName())
	}
	if subtle.ConstantTimeCompare(plaintext, []byte(canaryPlaintext)) != 1 {
		return errors.New("secrets canary mismatch: decrypted value does not match expected canary")
	}

	return nil
}

// verifyNewProvider checks that a secrets provider can round-trip encrypt/decrypt.
// Called during key migration to verify the new provider before clearing the old canary.
func verifyNewProvider(provider engine.SecretsProvider) error {
	ctx := context.Background()
	ciphertext, err := provider.WrapKey(ctx, []byte(canaryPlaintext))
	if err != nil {
		return fmt.Errorf("encrypt test: %w", err)
	}
	plaintext, err := provider.UnwrapKey(ctx, ciphertext)
	if err != nil {
		return fmt.Errorf("decrypt test: %w", err)
	}
	if subtle.ConstantTimeCompare(plaintext, []byte(canaryPlaintext)) != 1 {
		return errors.New("round-trip mismatch: decrypted value does not match original")
	}
	return nil
}

// initTracer sets up an OTLP gRPC trace exporter and returns the TracerProvider.
// Exporter endpoint is configured via standard OTEL_EXPORTER_OTLP_ENDPOINT env var
// (default: localhost:4317).
func initTracer(ctx context.Context, serviceName string) (*sdktrace.TracerProvider, error) {
	exporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create OTLP exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
		)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp, nil
}

// migrateSecretsKeys re-wraps all per-stack DEKs from oldProvider to newProvider.
func migrateSecretsKeys(store *storage.SQLiteStore, oldProvider, newProvider engine.SecretsProvider) error {
	ctx := context.Background()

	keys, err := store.ListSecretsKeys(ctx)
	if err != nil {
		return fmt.Errorf("list secrets keys: %w", err)
	}

	if len(keys) == 0 {
		slog.Info("no secrets keys to migrate")
		return nil
	}

	slog.Info("migrating secrets keys",
		"count", len(keys),
		"from", oldProvider.ProviderName(),
		"to", newProvider.ProviderName(),
	)

	for i, entry := range keys {
		// Unwrap with old provider.
		rawDEK, err := oldProvider.UnwrapKey(ctx, entry.EncryptedKey)
		if err != nil {
			return fmt.Errorf("unwrap key for %s/%s/%s: %w", entry.OrgName, entry.ProjectName, entry.StackName, err)
		}

		// Re-wrap with new provider.
		newWrapped, err := newProvider.WrapKey(ctx, rawDEK)
		if err != nil {
			return fmt.Errorf("wrap key for %s/%s/%s: %w", entry.OrgName, entry.ProjectName, entry.StackName, err)
		}

		// Save the re-wrapped key.
		if err := store.SaveSecretsKey(ctx, entry.OrgName, entry.ProjectName, entry.StackName, newWrapped); err != nil {
			return fmt.Errorf("save key for %s/%s/%s: %w", entry.OrgName, entry.ProjectName, entry.StackName, err)
		}

		slog.Info("migrated secrets key",
			"stack", fmt.Sprintf("%s/%s/%s", entry.OrgName, entry.ProjectName, entry.StackName),
			"progress", fmt.Sprintf("%d/%d", i+1, len(keys)),
		)
	}

	return nil
}

// openLogDest opens a log destination by path and returns a slog.Handler and
// optional closer. Supports "stdout", "stderr", or a file path.
func openLogDest(path, format string) (slog.Handler, io.Closer, error) {
	var w io.Writer
	var closer io.Closer

	switch path {
	case "stdout":
		w = os.Stdout
	case "stderr":
		w = os.Stderr
	default:
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) //nolint:gosec // log file, not secrets
		if err != nil {
			return nil, nil, err
		}
		w = f
		closer = f
	}

	var h slog.Handler
	if format == "text" {
		h = slog.NewTextHandler(w, nil)
	} else {
		h = slog.NewJSONHandler(w, nil)
	}
	return h, closer, nil
}
