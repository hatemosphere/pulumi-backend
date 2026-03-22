package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hatemosphere/pulumi-backend/internal/config"
)

func TestValidateRuntimeConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     config.Config
		wantErr string
	}{
		{
			name: "single tenant valid",
			cfg: config.Config{
				Addr:              "127.0.0.1:8080",
				AuthMode:          "single-tenant",
				SingleTenantToken: "test-token",
				SecretsProvider:   "local",
				MasterKey:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
		},
		{
			name: "tls missing certs",
			cfg: config.Config{
				Addr:              "127.0.0.1:8080",
				AuthMode:          "single-tenant",
				SingleTenantToken: "test-token",
				SecretsProvider:   "local",
				MasterKey:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				TLS:               true,
			},
			wantErr: "cert and key are required when tls is enabled",
		},
		{
			name: "single tenant missing token",
			cfg: config.Config{
				AuthMode:        "single-tenant",
				SecretsProvider: "local",
				MasterKey:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			wantErr: "single-tenant-token is required when auth-mode=single-tenant",
		},
		{
			name: "google missing client id",
			cfg: config.Config{
				AuthMode:        "google",
				RBACConfigPath:  "rbac.yaml",
				SecretsProvider: "local",
				MasterKey:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			wantErr: "google-client-id is required when auth-mode=google",
		},
		{
			name: "google missing rbac",
			cfg: config.Config{
				AuthMode:        "google",
				GoogleClientID:  "client-id",
				SecretsProvider: "local",
				MasterKey:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			wantErr: "rbac-config is required when auth-mode=google",
		},
		{
			name: "oidc missing settings",
			cfg: config.Config{
				AuthMode:        "oidc",
				RBACConfigPath:  "rbac.yaml",
				SecretsProvider: "local",
				MasterKey:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			wantErr: "oidc-issuer, oidc-client-id, and oidc-client-secret are required when auth-mode=oidc",
		},
		{
			name: "oidc missing rbac",
			cfg: config.Config{
				AuthMode:         "oidc",
				OIDCIssuer:       "https://issuer.example.com",
				OIDCClientID:     "client-id",
				OIDCClientSecret: "client-secret",
				PublicURL:        "https://pulumi.example.com",
				SecretsProvider:  "local",
				MasterKey:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			wantErr: "rbac-config is required when auth-mode=oidc",
		},
		{
			name: "oidc missing public url",
			cfg: config.Config{
				AuthMode:         "oidc",
				OIDCIssuer:       "https://issuer.example.com",
				OIDCClientID:     "client-id",
				OIDCClientSecret: "client-secret",
				RBACConfigPath:   "rbac.yaml",
				SecretsProvider:  "local",
				MasterKey:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			wantErr: "public-url is required when auth-mode=oidc",
		},
		{
			name: "jwt missing signing key",
			cfg: config.Config{
				AuthMode:        "jwt",
				RBACConfigPath:  "rbac.yaml",
				SecretsProvider: "local",
				MasterKey:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			wantErr: "jwt-signing-key is required when auth-mode=jwt",
		},
		{
			name: "jwt missing rbac",
			cfg: config.Config{
				AuthMode:        "jwt",
				JWTSigningKey:   "secret",
				SecretsProvider: "local",
				MasterKey:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			wantErr: "rbac-config is required when auth-mode=jwt",
		},
		{
			name: "gcpkms missing key",
			cfg: config.Config{
				AuthMode:          "single-tenant",
				SingleTenantToken: "test-token",
				SecretsProvider:   "gcpkms",
			},
			wantErr: "kms-key is required when secrets-provider=gcpkms",
		},
		{
			name: "migration missing old provider",
			cfg: config.Config{
				AuthMode:          "single-tenant",
				SingleTenantToken: "test-token",
				SecretsProvider:   "local",
				MasterKey:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				MigrateSecretsKey: true,
			},
			wantErr: "old-secrets-provider must be set to local or gcpkms when migrate-secrets-key is enabled",
		},
		{
			name: "migration missing old master key",
			cfg: config.Config{
				AuthMode:           "single-tenant",
				SingleTenantToken:  "test-token",
				SecretsProvider:    "local",
				MasterKey:          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				MigrateSecretsKey:  true,
				OldSecretsProvider: "local",
			},
			wantErr: "old-master-key is required when old-secrets-provider=local",
		},
		{
			name: "public bind requires management addr",
			cfg: config.Config{
				Addr:              ":8080",
				AuthMode:          "single-tenant",
				SingleTenantToken: "test-token",
				SecretsProvider:   "local",
				MasterKey:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			wantErr: "management-addr is required when addr binds to a non-loopback address",
		},
		{
			name: "pprof requires management addr",
			cfg: config.Config{
				Addr:              "127.0.0.1:8080",
				AuthMode:          "single-tenant",
				SingleTenantToken: "test-token",
				SecretsProvider:   "local",
				MasterKey:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				PprofEnabled:      true,
			},
			wantErr: "management-addr is required when pprof is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRuntimeConfig(&tt.cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.wantErr, err.Error())
		})
	}
}

func TestBuildServerOptionsTrustedProxyValidation(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		AuthMode:          "single-tenant",
		SingleTenantToken: "test-token",
		SecretsProvider:   "local",
		MasterKey:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		TrustedProxies:    "not-a-cidr",
	}

	_, err := buildServerOptions(t.Context(), cfg, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid trusted-proxies")
}
