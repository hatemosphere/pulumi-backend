package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/config"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Set by goreleaser ldflags.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	cfg, err := config.Parse()
	if err != nil {
		fatalf("%v", err)
	}
	if err := validateRuntimeConfig(cfg); err != nil {
		fatalf("configuration error: %v", err)
	}

	auditCloser, err := setupLogging(cfg)
	if err != nil {
		fatalf("logging setup: %v", err)
	}
	if auditCloser != nil {
		defer auditCloser.Close()
	}

	store, err := storage.NewSQLiteStore(cfg.DBPath, storage.SQLiteStoreConfig{
		MaxStateVersions:  cfg.MaxStateVersions,
		StackListPageSize: cfg.StackListPageSize,
	})
	if err != nil {
		fatalf("failed to open database: %v", err)
	}
	defer store.Close()

	secretsProvider, err := buildSecretsProvider(context.Background(), cfg)
	if err != nil {
		fatalf("failed to create secrets provider: %v", err)
	}
	if closer, ok := secretsProvider.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	store.SetTokenEncryptor(storage.NewTokenEncryptor(
		func(pt []byte) ([]byte, error) { return secretsProvider.WrapKey(context.Background(), pt) },
		func(ct []byte) ([]byte, error) { return secretsProvider.UnwrapKey(context.Background(), ct) },
	))

	if cfg.MigrateSecretsKey {
		if err := runSecretsMigration(store, cfg, secretsProvider); err != nil {
			fatalf("secrets key migration: %v", err)
		}
		store.Close()
		os.Exit(0)
	}

	if err := verifySecretsProvider(store, secretsProvider); err != nil {
		fatalf("secrets provider verification: %v", err)
	}

	secrets := engine.NewSecretsEngine(secretsProvider)

	backupProviders, err := buildBackupProviders(context.Background(), cfg)
	if err != nil {
		fatalf("failed to create backup provider: %v", err)
	}

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
		fatalf("failed to create engine: %v", err)
	}

	api.RegisterActiveUpdatesGauge(func() float64 { return float64(mgr.ActiveUpdateCount()) })

	serverOpts, err := buildServerOptions(context.Background(), cfg, store)
	if err != nil {
		fatalf("failed to build server options: %v", err)
	}

	tp, err := initializeTracer(context.Background(), cfg)
	if err != nil {
		fatalf("failed to initialize OpenTelemetry: %v", err)
	}

	srv := api.NewServer(mgr, cfg.DefaultOrg, cfg.DefaultUser, serverOpts...)
	defer srv.Close()

	handler := srv.Router()
	if tp != nil {
		handler = otelhttp.NewHandler(handler, "pulumi-backend")
	}

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	if cfg.ACMEDomain != "" {
		configureACME(httpServer, store, cfg)
	}

	mgmtServer := startManagementServer(mgr, cfg)

	// Graceful shutdown on SIGINT/SIGTERM.
	done := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("shutting down", "signal", sig.String())

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

	if err := listenAndServe(httpServer, cfg); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}

	<-done

	slog.Info("flushing events and closing storage")
	mgr.Shutdown()
	if tp != nil {
		if err := tp.Shutdown(context.Background()); err != nil {
			slog.Error("tracer provider shutdown error", "error", err)
		}
	}
	slog.Info("shutdown complete")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
