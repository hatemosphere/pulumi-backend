package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/backup"
	"github.com/hatemosphere/pulumi-backend/internal/config"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

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

func buildSecretsProvider(ctx context.Context, cfg *config.Config) (engine.SecretsProvider, error) {
	switch cfg.SecretsProvider {
	case "gcpkms":
		kmsProvider, err := engine.NewKMSSecretsProvider(ctx, cfg.KMSKeyResourceName)
		if err != nil {
			return nil, fmt.Errorf("create KMS secrets provider: %w", err)
		}
		slog.Info("secrets provider: GCP KMS", "key", cfg.KMSKeyResourceName)
		return kmsProvider, nil
	case "local":
		masterKey, err := cfg.MasterKeyBytes()
		if err != nil {
			return nil, fmt.Errorf("invalid master key: %w", err)
		}
		localProvider, err := engine.NewLocalSecretsProvider(masterKey)
		if err != nil {
			return nil, fmt.Errorf("create local secrets provider: %w", err)
		}
		return localProvider, nil
	default:
		return nil, fmt.Errorf("unsupported secrets provider %q", cfg.SecretsProvider)
	}
}

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
		return nil, nil
	case "google":
		opts := []api.ServerOption{api.WithTokenStore(store)}

		var groupsCache *auth.GroupsCache
		if cfg.GoogleAdminEmail != "" {
			resolver, err := auth.NewGroupsResolver(
				ctx, cfg.GoogleSAKeyFile, cfg.GoogleSAEmail, cfg.GoogleAdminEmail, cfg.GoogleTransitiveGroups,
			)
			if err != nil {
				return nil, fmt.Errorf("create groups resolver: %w", err)
			}
			groupsCache = auth.NewGroupsCache(resolver, cfg.GroupsCacheTTL)
			slog.Info("google groups resolution enabled",
				"admin_email", cfg.GoogleAdminEmail,
				"transitive", cfg.GoogleTransitiveGroups,
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
	case "oidc":
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
	case "jwt":
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
	default:
		return nil, fmt.Errorf("unsupported auth mode %q", cfg.AuthMode)
	}
}

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

func buildOldSecretsProvider(cfg *config.Config) (engine.SecretsProvider, error) {
	switch cfg.OldSecretsProvider {
	case "gcpkms":
		return engine.NewKMSSecretsProvider(context.Background(), cfg.OldKMSKey)
	case "local":
		key, err := hex.DecodeString(cfg.OldMasterKey)
		if err != nil {
			return nil, fmt.Errorf("invalid --old-master-key: %w", err)
		}
		return engine.NewLocalSecretsProvider(key)
	default:
		return nil, fmt.Errorf("--old-secrets-provider must be 'local' or 'gcpkms', got %q", cfg.OldSecretsProvider)
	}
}
