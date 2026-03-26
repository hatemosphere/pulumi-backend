package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/backup"
	"github.com/hatemosphere/pulumi-backend/internal/config"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

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

	var groupsCache *auth.GroupsCache
	if cfg.RBACConfigPath != "" || cfg.GoogleAdminEmail != "" {
		mode := auth.InferGoogleGroupsMode(cfg.GoogleSAKeyFile, cfg.GoogleSAEmail, cfg.GoogleAdminEmail)
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
