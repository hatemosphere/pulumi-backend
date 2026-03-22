package main

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/segmentio/encoding/json"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/audit"
	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/backup"
	"github.com/hatemosphere/pulumi-backend/internal/config"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// --- Config Validation ---

func validateRuntimeConfig(cfg *config.Config) error {
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}

	if cfg.ACMEDomain != "" {
		if cfg.TLS {
			return errors.New("acme-domain and tls/cert/key are mutually exclusive")
		}
		cfg.TLS = true // ACME implies TLS
	}

	if cfg.TLS && cfg.ACMEDomain == "" {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return errors.New("cert and key are required when tls is enabled")
		}
	}

	switch cfg.SecretsProvider {
	case "local":
		if cfg.MasterKey == "" && cfg.MigrateSecretsKey {
			return errors.New("master-key is required when migrate-secrets-key is used with secrets-provider=local")
		}
	case "gcpkms":
		if cfg.KMSKeyResourceName == "" {
			return errors.New("kms-key is required when secrets-provider=gcpkms")
		}
	default:
		return fmt.Errorf("unsupported secrets-provider %q", cfg.SecretsProvider)
	}

	switch cfg.AuthMode {
	case "single-tenant":
		if cfg.SingleTenantToken == "" {
			return errors.New("single-tenant-token is required when auth-mode=single-tenant")
		}
	case "google":
		if cfg.GoogleClientID == "" {
			return errors.New("google-client-id is required when auth-mode=google")
		}
		if cfg.RBACConfigPath == "" {
			return errors.New("rbac-config is required when auth-mode=google")
		}
		if cfg.GoogleClientSecret != "" && cfg.PublicURL == "" {
			return errors.New("public-url is required when browser login is enabled in auth-mode=google")
		}
	case "oidc":
		if cfg.OIDCIssuer == "" || cfg.OIDCClientID == "" || cfg.OIDCClientSecret == "" {
			return errors.New("oidc-issuer, oidc-client-id, and oidc-client-secret are required when auth-mode=oidc")
		}
		if cfg.RBACConfigPath == "" {
			return errors.New("rbac-config is required when auth-mode=oidc")
		}
		if cfg.PublicURL == "" {
			return errors.New("public-url is required when auth-mode=oidc")
		}
	case "jwt":
		if cfg.JWTSigningKey == "" {
			return errors.New("jwt-signing-key is required when auth-mode=jwt")
		}
		if cfg.RBACConfigPath == "" {
			return errors.New("rbac-config is required when auth-mode=jwt")
		}
	default:
		return fmt.Errorf("unsupported auth-mode %q", cfg.AuthMode)
	}

	if cfg.MigrateSecretsKey {
		switch cfg.OldSecretsProvider {
		case "local":
			if cfg.OldMasterKey == "" {
				return errors.New("old-master-key is required when old-secrets-provider=local")
			}
		case "gcpkms":
			if cfg.OldKMSKey == "" {
				return errors.New("old-kms-key is required when old-secrets-provider=gcpkms")
			}
		default:
			return errors.New("old-secrets-provider must be set to local or gcpkms when migrate-secrets-key is enabled")
		}
	}

	if !cfg.MigrateSecretsKey && !isLoopbackOnlyAddr(cfg.Addr) && cfg.ManagementAddr == "" {
		return errors.New("management-addr is required when addr binds to a non-loopback address")
	}

	if cfg.PprofEnabled && cfg.ManagementAddr == "" {
		return errors.New("management-addr is required when pprof is enabled")
	}

	return nil
}

// isLoopbackOnlyAddr reports whether addr binds exclusively to a loopback
// interface. Examples:
//
//	"127.0.0.1:8080" → true   (IPv4 loopback)
//	"[::1]:8080"     → true   (IPv6 loopback)
//	"localhost:8080"  → true
//	":8080"          → false  (all interfaces)
//	"0.0.0.0:8080"   → false  (all interfaces)
//	"10.0.0.1:8080"  → false  (external)
func isLoopbackOnlyAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // bare host without port
	}

	// ":8080" or "" → binds all interfaces.
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// --- Logging ---

// setupLogging configures the default, audit, and access loggers.
// Returns an io.Closer for the audit log file (nil if not file-based).
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

// openLogDest opens a log destination by path. Returns a handler and optional
// closer (non-nil only for file paths). Supports "stdout", "stderr", or a file path.
func openLogDest(path, format string) (slog.Handler, io.Closer, error) {
	switch path {
	case "stdout":
		return newLogHandler(format, os.Stdout), nil, nil
	case "stderr":
		return newLogHandler(format, os.Stderr), nil, nil
	default:
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) //nolint:gosec // log file, not secrets
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

// --- Secrets ---

// canaryPlaintext is a known value used to verify the secrets provider on startup.
const canaryPlaintext = "pulumi-backend-secrets-canary"

func buildSecretsProvider(ctx context.Context, cfg *config.Config) (engine.SecretsProvider, error) {
	masterKeyHex := cfg.MasterKey
	provider, err := newSecretsProvider(ctx, cfg.SecretsProvider, masterKeyHex, cfg.KMSKeyResourceName)
	if err != nil {
		return nil, err
	}
	if cfg.SecretsProvider == "gcpkms" {
		slog.Info("secrets provider: GCP KMS", "key", cfg.KMSKeyResourceName)
	}
	return provider, nil
}

func buildOldSecretsProvider(cfg *config.Config) (engine.SecretsProvider, error) {
	return newSecretsProvider(context.Background(), cfg.OldSecretsProvider, cfg.OldMasterKey, cfg.OldKMSKey)
}

func newSecretsProvider(ctx context.Context, providerType, masterKeyHex, kmsKey string) (engine.SecretsProvider, error) {
	switch providerType {
	case "gcpkms":
		return engine.NewKMSSecretsProvider(ctx, kmsKey)
	case "local":
		key, err := hex.DecodeString(masterKeyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid master key: %w", err)
		}
		return engine.NewLocalSecretsProvider(key)
	default:
		return nil, fmt.Errorf("unsupported secrets provider %q", providerType)
	}
}

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
		ciphertext, err := provider.WrapKey(ctx, []byte(canaryPlaintext))
		if err != nil {
			return fmt.Errorf("encrypt canary: %w", err)
		}
		if err := store.SetConfig(ctx, "secrets_canary", hex.EncodeToString(ciphertext)); err != nil {
			return fmt.Errorf("store canary in database: %w", err)
		}
		slog.Info("secrets provider canary stored", "provider", provider.ProviderName())
		return nil
	}

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

// runSecretsMigration re-wraps all per-stack DEKs from old to new provider,
// verifies the new provider, and swaps the canary.
func runSecretsMigration(store *storage.SQLiteStore, cfg *config.Config, newProvider engine.SecretsProvider) error {
	oldProvider, err := buildOldSecretsProvider(cfg)
	if err != nil {
		return fmt.Errorf("build old secrets provider: %w", err)
	}
	if closer, ok := oldProvider.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	if err := verifySecretsProvider(store, oldProvider); err != nil {
		return fmt.Errorf("old provider verification (cannot decrypt existing data): %w", err)
	}

	if err := migrateSecretsKeys(store, oldProvider, newProvider); err != nil {
		return err
	}

	if err := verifyNewProvider(newProvider); err != nil {
		return fmt.Errorf("new provider verification: %w", err)
	}

	// Swap canary: clear old, store new.
	if err := store.SetConfig(context.Background(), "secrets_canary", ""); err != nil {
		return fmt.Errorf("clear old canary: %w", err)
	}
	if err := verifySecretsProvider(store, newProvider); err != nil {
		return fmt.Errorf("store new canary: %w", err)
	}

	slog.Info("secrets key migration complete")
	return nil
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
		rawDEK, err := oldProvider.UnwrapKey(ctx, entry.EncryptedKey)
		if err != nil {
			return fmt.Errorf("unwrap key for %s/%s/%s: %w", entry.OrgName, entry.ProjectName, entry.StackName, err)
		}

		newWrapped, err := newProvider.WrapKey(ctx, rawDEK)
		if err != nil {
			return fmt.Errorf("wrap key for %s/%s/%s: %w", entry.OrgName, entry.ProjectName, entry.StackName, err)
		}

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

// --- Backup ---

func buildBackupProviders(ctx context.Context, cfg *config.Config) ([]backup.Provider, error) {
	if cfg.BackupDestination == "" {
		return nil, nil
	}

	provider, err := backup.ResolveDestination(ctx, cfg.BackupDestination, backup.S3Options{
		Region:         cfg.BackupS3Region,
		Endpoint:       cfg.BackupS3Endpoint,
		ForcePathStyle: cfg.BackupS3ForcePathStyle,
	})
	if err != nil {
		return nil, fmt.Errorf("create backup provider: %w", err)
	}

	slog.Info("backup enabled", "destination", cfg.BackupDestination)
	return []backup.Provider{provider}, nil
}

// --- Server Options & Auth ---

func buildServerOptions(ctx context.Context, cfg *config.Config, store storage.Store) ([]api.ServerOption, error) {
	serverOpts := []api.ServerOption{
		api.WithDeltaCutoff(cfg.DeltaCutoffBytes),
		api.WithHistoryPageSize(cfg.HistoryPageSize),
		api.WithAuthMode(cfg.AuthMode),
	}
	if cfg.AuthMode == "single-tenant" {
		serverOpts = append(serverOpts, api.WithSingleTenantToken(cfg.SingleTenantToken))
	}

	if cfg.PublicURL != "" {
		serverOpts = append(serverOpts, api.WithPublicURL(cfg.PublicURL))
		slog.Info("public URL configured", "url", cfg.PublicURL)
	}
	if cfg.PprofEnabled && cfg.ManagementAddr == "" {
		serverOpts = append(serverOpts, api.WithPprof())
	}
	if cfg.TrustedProxies != "" {
		proxies, err := api.ParseTrustedProxies(cfg.TrustedProxies)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted-proxies: %w", err)
		}
		serverOpts = append(serverOpts, api.WithTrustedProxies(proxies))
		slog.Info("trusted proxies configured", "cidrs", cfg.TrustedProxies)
	}
	if cfg.ManagementAddr != "" {
		serverOpts = append(serverOpts, api.WithSkipManagementRoutes())
	}

	authOpts, err := buildAuthOptions(ctx, cfg, store)
	if err != nil {
		return nil, err
	}
	serverOpts = append(serverOpts, authOpts...)

	if cfg.RBACConfigPath != "" {
		rbacCfg, err := auth.LoadRBACConfig(cfg.RBACConfigPath)
		if err != nil {
			return nil, fmt.Errorf("load RBAC config: %w", err)
		}
		rbacResolver, err := auth.NewRBACResolver(rbacCfg)
		if err != nil {
			return nil, fmt.Errorf("invalid RBAC config: %w", err)
		}
		serverOpts = append(serverOpts, api.WithRBAC(rbacResolver))
		slog.Info("RBAC enabled", "config", cfg.RBACConfigPath)
	}

	return serverOpts, nil
}

func buildAuthOptions(ctx context.Context, cfg *config.Config, store storage.Store) ([]api.ServerOption, error) {
	switch cfg.AuthMode {
	case "single-tenant":
		return buildSingleTenantAuth()
	case "google":
		return buildGoogleAuth(ctx, cfg, store)
	case "oidc":
		return buildOIDCAuth(ctx, cfg, store)
	case "jwt":
		return buildJWTAuth(cfg)
	default:
		return nil, fmt.Errorf("unsupported auth mode %q", cfg.AuthMode)
	}
}

func buildSingleTenantAuth() ([]api.ServerOption, error) {
	return nil, nil
}

func buildGoogleAuth(ctx context.Context, cfg *config.Config, store storage.Store) ([]api.ServerOption, error) {
	opts := []api.ServerOption{api.WithTokenStore(store)}

	// Build groups resolver if RBAC is configured (needs group memberships)
	// or if DWD is explicitly configured (admin-email set).
	var groupsCache *auth.GroupsCache
	if cfg.RBACConfigPath != "" || cfg.GoogleAdminEmail != "" {
		mode := auth.InferGoogleGroupsMode(cfg.GoogleSAKeyFile, cfg.GoogleSAEmail, cfg.GoogleAdminEmail)
		// Only admin-role mode needs the domain on API calls — DWD modes
		// inherit the domain from the impersonated Subject.
		var domain string
		if mode == "admin-role" {
			if domains := parseCSVList(cfg.GoogleAllowedDomains); len(domains) > 0 {
				domain = domains[0]
			}
		}
		groupsCfg := auth.GoogleGroupsConfig{
			Mode:       mode,
			SAKeyFile:  cfg.GoogleSAKeyFile,
			SAEmail:    cfg.GoogleSAEmail,
			AdminEmail: cfg.GoogleAdminEmail,
			Domain:     domain,
			Transitive: cfg.GoogleTransitiveGroups,
		}
		resolver, err := auth.NewGoogleGroupsResolver(ctx, groupsCfg)
		if err != nil {
			return nil, fmt.Errorf("create groups resolver: %w", err)
		}
		groupsCache = auth.NewGroupsCache(resolver, cfg.GroupsCacheTTL)
		slog.Info("google groups resolution enabled",
			"mode", groupsCfg.Mode,
			"transitive", groupsCfg.Transitive,
		)
	}

	oidcAuth, err := auth.NewGoogleOIDCAuthenticator(ctx, auth.OIDCConfig{
		ClientID:       cfg.GoogleClientID,
		AllowedDomains: parseCSVList(cfg.GoogleAllowedDomains),
		TokenTTL:       cfg.TokenTTL,
	}, cfg.GoogleClientSecret, groupsCache)
	if err != nil {
		return nil, fmt.Errorf("create Google OIDC authenticator: %w", err)
	}

	opts = append(opts, api.WithOIDCAuth(oidcAuth))
	if groupsCache != nil {
		opts = append(opts, api.WithGroupsCache(groupsCache))
	}
	slog.Info("auth mode: google", "client_id", cfg.GoogleClientID)
	return opts, nil
}

func buildOIDCAuth(ctx context.Context, cfg *config.Config, store storage.Store) ([]api.ServerOption, error) {
	oidcAuth, err := auth.NewOIDCAuthenticator(ctx, auth.OIDCConfig{
		ClientID:       cfg.OIDCClientID,
		AllowedDomains: parseCSVList(cfg.OIDCAllowedDomains),
		TokenTTL:       cfg.TokenTTL,
		ProviderName:   cfg.OIDCProviderName,
		Scopes:         parseCSVList(cfg.OIDCScopes),
		GroupsClaim:    cfg.OIDCGroupsClaim,
		UsernameClaim:  cfg.OIDCUsernameClaim,
	}, cfg.OIDCIssuer, cfg.OIDCClientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("create OIDC authenticator: %w", err)
	}

	slog.Info("auth mode: oidc",
		"issuer", cfg.OIDCIssuer,
		"client_id", cfg.OIDCClientID,
		"provider_name", cfg.OIDCProviderName,
	)
	return []api.ServerOption{
		api.WithTokenStore(store),
		api.WithOIDCAuth(oidcAuth),
	}, nil
}

func buildJWTAuth(cfg *config.Config) ([]api.ServerOption, error) {
	jwtAuth, err := auth.NewJWTAuthenticator(auth.JWTConfig{
		SigningKey:    cfg.JWTSigningKey,
		Issuer:        cfg.JWTIssuer,
		Audience:      cfg.JWTAudience,
		GroupsClaim:   cfg.JWTGroupsClaim,
		UsernameClaim: cfg.JWTUsernameClaim,
	})
	if err != nil {
		return nil, fmt.Errorf("create JWT authenticator: %w", err)
	}

	slog.Info("auth mode: jwt",
		"issuer", cfg.JWTIssuer,
		"audience", cfg.JWTAudience,
		"username_claim", cfg.JWTUsernameClaim,
		"groups_claim", cfg.JWTGroupsClaim,
	)
	return []api.ServerOption{api.WithJWTAuth(jwtAuth)}, nil
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

// --- Tracing ---

func initializeTracer(ctx context.Context, cfg *config.Config) (*sdktrace.TracerProvider, error) {
	if cfg.OTelServiceName == "" {
		return nil, nil
	}

	tp, err := initTracer(ctx, cfg.OTelServiceName)
	if err != nil {
		return nil, fmt.Errorf("initialize OpenTelemetry: %w", err)
	}

	slog.Info("OpenTelemetry tracing enabled", "service", cfg.OTelServiceName)
	return tp, nil
}

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

// --- Servers ---

// configureACME sets up automatic TLS via ACME on the HTTP server and starts
// an HTTP-01 challenge handler on port 80.
func configureACME(httpServer *http.Server, store *storage.SQLiteStore, cfg *config.Config) {
	m := &autocert.Manager{
		Cache:      storage.NewACMECache(store),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.ACMEDomain),
		Email:      cfg.ACMEEmail,
	}
	if cfg.ACMECA != "" {
		m.Client = &acme.Client{DirectoryURL: cfg.ACMECA}
	}
	httpServer.TLSConfig = m.TLSConfig()

	go func() {
		challengeServer := &http.Server{
			Addr:              ":80",
			Handler:           m.HTTPHandler(nil),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
		}
		slog.Info("ACME HTTP-01 challenge server starting", "addr", ":80", "domain", cfg.ACMEDomain)
		if err := challengeServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("ACME challenge server error", "error", err)
		}
	}()

	slog.Info("ACME automatic TLS enabled", "domain", cfg.ACMEDomain, "cache", "sqlite")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = json.NewEncoder(w).Encode(v)
}

// startManagementServer starts the management server (healthz, readyz, metrics,
// optional pprof) on a separate port. Returns nil if management-addr is not configured.
func startManagementServer(mgr *engine.Manager, cfg *config.Config) *http.Server {
	if cfg.ManagementAddr == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.Ping(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("GET /metrics", api.MetricsHandler())

	if cfg.PprofEnabled {
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
		slog.Info("pprof enabled on management server")
	}

	srv := &http.Server{
		Addr:              cfg.ManagementAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		slog.Info("management server starting", "addr", cfg.ManagementAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("management server error", "error", err)
		}
	}()

	return srv
}

// listenAndServe starts the HTTP server with the appropriate TLS configuration.
func listenAndServe(srv *http.Server, cfg *config.Config) error {
	switch {
	case cfg.ACMEDomain != "":
		return srv.ListenAndServeTLS("", "") // certs from autocert TLSConfig
	case cfg.TLS:
		return srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	default:
		return srv.ListenAndServe()
	}
}
