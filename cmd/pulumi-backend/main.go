package main

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	stdjson "encoding/json"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/audit"
	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/backup"
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

func main() {
	cfg := config.Parse()

	// Configure logging format.
	var logHandler slog.Handler
	if cfg.LogFormat == "text" {
		logHandler = slog.NewTextHandler(os.Stdout, nil)
	} else {
		logHandler = slog.NewJSONHandler(os.Stdout, nil)
	}
	slog.SetDefault(slog.New(logHandler))

	// Disable audit logging if configured.
	if !cfg.AuditLogs {
		audit.Enabled = false
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

	// Create secrets provider.
	secretsProvider := createSecretsProvider(cfg)
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

	// Set up backup providers.
	var backupProviders []backup.Provider
	if cfg.BackupS3Bucket != "" {
		s3Provider, s3Err := backup.NewS3Provider(context.Background(), backup.S3Config{
			Bucket:         cfg.BackupS3Bucket,
			Region:         cfg.BackupS3Region,
			Endpoint:       cfg.BackupS3Endpoint,
			Prefix:         cfg.BackupS3Prefix,
			ForcePathStyle: cfg.BackupS3ForcePathStyle,
		})
		if s3Err != nil {
			fmt.Fprintf(os.Stderr, "failed to create S3 backup provider: %v\n", s3Err)
			os.Exit(1)
		}
		backupProviders = append(backupProviders, s3Provider)
		slog.Info("S3 backup enabled", "bucket", cfg.BackupS3Bucket, "prefix", cfg.BackupS3Prefix)
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
	serverOpts := []api.ServerOption{
		api.WithDeltaCutoff(cfg.DeltaCutoffBytes),
		api.WithHistoryPageSize(cfg.HistoryPageSize),
		api.WithAuthMode(cfg.AuthMode),
	}
	if cfg.PublicURL != "" {
		serverOpts = append(serverOpts, api.WithPublicURL(cfg.PublicURL))
		slog.Info("public URL configured", "url", cfg.PublicURL)
	}
	if cfg.PprofEnabled {
		serverOpts = append(serverOpts, api.WithPprof())
	}
	if cfg.TrustedProxies != "" {
		proxies, err := api.ParseTrustedProxies(cfg.TrustedProxies)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid trusted-proxies: %v\n", err)
			os.Exit(1)
		}
		serverOpts = append(serverOpts, api.WithTrustedProxies(proxies))
		slog.Info("trusted proxies configured", "cidrs", cfg.TrustedProxies)
	}

	switch cfg.AuthMode {
	case "google":
		if cfg.GoogleClientID == "" {
			fmt.Fprintf(os.Stderr, "google-client-id is required when auth-mode=google\n")
			os.Exit(1)
		}

		serverOpts = append(serverOpts, api.WithTokenStore(store))

		// Set up Google groups resolver if admin email is configured.
		var groupsCache *auth.GroupsCache
		if cfg.GoogleAdminEmail != "" {
			resolver, err := auth.NewGroupsResolver(
				context.Background(), cfg.GoogleSAKeyFile, cfg.GoogleSAEmail, cfg.GoogleAdminEmail, cfg.GoogleTransitiveGroups,
			)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create groups resolver: %v\n", err)
				os.Exit(1)
			}
			groupsCache = auth.NewGroupsCache(resolver, cfg.GroupsCacheTTL)
			slog.Info("google groups resolution enabled",
				"admin_email", cfg.GoogleAdminEmail,
				"transitive", cfg.GoogleTransitiveGroups,
			)
		}

		allowedDomains := parseCSVList(cfg.GoogleAllowedDomains)

		oidcAuth, err := auth.NewGoogleOIDCAuthenticator(context.Background(), auth.OIDCConfig{
			ClientID:       cfg.GoogleClientID,
			AllowedDomains: allowedDomains,
			TokenTTL:       cfg.TokenTTL,
		}, cfg.GoogleClientSecret, groupsCache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create Google OIDC authenticator: %v\n", err)
			os.Exit(1)
		}

		serverOpts = append(serverOpts, api.WithOIDCAuth(oidcAuth))
		if groupsCache != nil {
			serverOpts = append(serverOpts, api.WithGroupsCache(groupsCache))
		}
		slog.Info("auth mode: google", "client_id", cfg.GoogleClientID)

	case "oidc":
		if cfg.OIDCIssuer == "" || cfg.OIDCClientID == "" || cfg.OIDCClientSecret == "" {
			fmt.Fprintf(os.Stderr, "oidc-issuer, oidc-client-id, and oidc-client-secret are required when auth-mode=oidc\n")
			os.Exit(1)
		}

		serverOpts = append(serverOpts, api.WithTokenStore(store))

		allowedDomains := parseCSVList(cfg.OIDCAllowedDomains)
		scopes := parseCSVList(cfg.OIDCScopes)

		oidcAuth, err := auth.NewOIDCAuthenticator(context.Background(), auth.OIDCConfig{
			ClientID:       cfg.OIDCClientID,
			AllowedDomains: allowedDomains,
			TokenTTL:       cfg.TokenTTL,
			ProviderName:   cfg.OIDCProviderName,
			Scopes:         scopes,
			GroupsClaim:    cfg.OIDCGroupsClaim,
			UsernameClaim:  cfg.OIDCUsernameClaim,
		}, cfg.OIDCIssuer, cfg.OIDCClientSecret, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create OIDC authenticator: %v\n", err)
			os.Exit(1)
		}

		serverOpts = append(serverOpts, api.WithOIDCAuth(oidcAuth))
		slog.Info("auth mode: oidc",
			"issuer", cfg.OIDCIssuer,
			"client_id", cfg.OIDCClientID,
			"provider_name", cfg.OIDCProviderName,
		)

	case "jwt":
		if cfg.JWTSigningKey == "" {
			fmt.Fprintf(os.Stderr, "jwt-signing-key is required when auth-mode=jwt\n")
			os.Exit(1)
		}
		jwtAuth, err := auth.NewJWTAuthenticator(auth.JWTConfig{
			SigningKey:    cfg.JWTSigningKey,
			Issuer:        cfg.JWTIssuer,
			Audience:      cfg.JWTAudience,
			GroupsClaim:   cfg.JWTGroupsClaim,
			UsernameClaim: cfg.JWTUsernameClaim,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create JWT authenticator: %v\n", err)
			os.Exit(1)
		}
		serverOpts = append(serverOpts, api.WithJWTAuth(jwtAuth))
		slog.Info("auth mode: jwt",
			"issuer", cfg.JWTIssuer,
			"audience", cfg.JWTAudience,
			"username_claim", cfg.JWTUsernameClaim,
			"groups_claim", cfg.JWTGroupsClaim,
		)
	}

	// Load RBAC config if provided.
	if cfg.RBACConfigPath != "" {
		rbacCfg, err := auth.LoadRBACConfig(cfg.RBACConfigPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load RBAC config: %v\n", err)
			os.Exit(1)
		}
		rbacResolver, err := auth.NewRBACResolver(rbacCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid RBAC config: %v\n", err)
			os.Exit(1)
		}
		serverOpts = append(serverOpts, api.WithRBAC(rbacResolver))
		slog.Info("RBAC enabled", "config", cfg.RBACConfigPath)
	}

	// Initialize OpenTelemetry tracing if configured.
	var tp *sdktrace.TracerProvider
	if cfg.OTelServiceName != "" {
		var initErr error
		tp, initErr = initTracer(context.Background(), cfg.OTelServiceName)
		if initErr != nil {
			fmt.Fprintf(os.Stderr, "failed to initialize OpenTelemetry: %v\n", initErr)
			os.Exit(1)
		}
		slog.Info("OpenTelemetry tracing enabled", "service", cfg.OTelServiceName)
	}

	// When management-addr is set, health/metrics move to a separate server.
	if cfg.ManagementAddr != "" {
		serverOpts = append(serverOpts, api.WithSkipManagementRoutes())
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
			_ = stdjson.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		})
		mgmtMux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
			if err := mgr.Ping(r.Context()); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = stdjson.NewEncoder(w).Encode(map[string]string{"status": "error"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = stdjson.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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

	slog.Info("pulumi backend starting", "addr", cfg.Addr)
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
	store.Close()
	slog.Info("shutdown complete")
}

func parseCSVList(s string) []string {
	var result []string
	for _, v := range strings.Split(s, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			result = append(result, v)
		}
	}
	return result
}

// createSecretsProvider builds the secrets provider from config. Exits on error.
func createSecretsProvider(cfg *config.Config) engine.SecretsProvider {
	switch cfg.SecretsProvider {
	case "gcpkms":
		if cfg.KMSKeyResourceName == "" {
			fmt.Fprintf(os.Stderr, "GCP KMS key resource name is required when secrets-provider=gcpkms\n")
			os.Exit(1)
		}
		kmsProvider, err := engine.NewKMSSecretsProvider(context.Background(), cfg.KMSKeyResourceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create KMS secrets provider: %v\n", err)
			os.Exit(1)
		}
		slog.Info("secrets provider: GCP KMS", "key", cfg.KMSKeyResourceName)
		return kmsProvider
	default: // "local"
		masterKey, err := cfg.MasterKeyBytes()
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid master key: %v\n", err)
			os.Exit(1)
		}
		localProvider, err := engine.NewLocalSecretsProvider(masterKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create local secrets provider: %v\n", err)
			os.Exit(1)
		}
		return localProvider
	}
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
	if string(plaintext) != canaryPlaintext {
		return errors.New("round-trip mismatch: decrypted value does not match original")
	}
	return nil
}

// buildOldSecretsProvider constructs a SecretsProvider from the --old-* flags.
func buildOldSecretsProvider(cfg *config.Config) (engine.SecretsProvider, error) {
	switch cfg.OldSecretsProvider {
	case "gcpkms":
		if cfg.OldKMSKey == "" {
			return nil, errors.New("--old-kms-key is required when --old-secrets-provider=gcpkms")
		}
		return engine.NewKMSSecretsProvider(context.Background(), cfg.OldKMSKey)
	case "local":
		if cfg.OldMasterKey == "" {
			return nil, errors.New("--old-master-key is required when --old-secrets-provider=local")
		}
		key, err := hex.DecodeString(cfg.OldMasterKey)
		if err != nil {
			return nil, fmt.Errorf("invalid --old-master-key: %w", err)
		}
		return engine.NewLocalSecretsProvider(key)
	default:
		return nil, fmt.Errorf("--old-secrets-provider must be 'local' or 'gcpkms', got %q", cfg.OldSecretsProvider)
	}
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
