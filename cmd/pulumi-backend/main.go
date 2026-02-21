package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/audit"
	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/config"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
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
	var secretsProvider engine.SecretsProvider
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
		defer kmsProvider.Close()
		secretsProvider = kmsProvider
		slog.Info("secrets provider: GCP KMS", "key", cfg.KMSKeyResourceName)
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
		secretsProvider = localProvider
	}

	secrets := engine.NewSecretsEngine(secretsProvider)

	// Create engine manager.
	mgr, err := engine.NewManager(store, secrets, engine.ManagerConfig{
		LeaseDuration:      cfg.LeaseDuration,
		CacheSize:          cfg.CacheSize,
		EventBufferSize:    cfg.EventBufferSize,
		EventFlushInterval: cfg.EventFlushInterval,
		BackupDir:          cfg.BackupDir,
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

		var allowedDomains []string
		if cfg.GoogleAllowedDomains != "" {
			for _, d := range strings.Split(cfg.GoogleAllowedDomains, ",") {
				if d != "" {
					allowedDomains = append(allowedDomains, d)
				}
			}
		}

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

		var allowedDomains []string
		if cfg.OIDCAllowedDomains != "" {
			for _, d := range strings.Split(cfg.OIDCAllowedDomains, ",") {
				if d != "" {
					allowedDomains = append(allowedDomains, d)
				}
			}
		}
		var scopes []string
		if cfg.OIDCScopes != "" {
			for _, s := range strings.Split(cfg.OIDCScopes, ",") {
				if s != "" {
					scopes = append(scopes, s)
				}
			}
		}

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
		serverOpts = append(serverOpts, api.WithRBAC(auth.NewRBACResolver(rbacCfg)))
		slog.Info("RBAC enabled", "config", cfg.RBACConfigPath)
	}

	srv := api.NewServer(mgr, cfg.DefaultOrg, cfg.DefaultUser, serverOpts...)
	router := srv.Router()

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
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

	// Flush buffered events and stop background goroutine.
	slog.Info("flushing events and closing storage")
	mgr.Shutdown()
	store.Close()
	slog.Info("shutdown complete")
}
