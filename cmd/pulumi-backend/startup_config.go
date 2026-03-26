package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/hatemosphere/pulumi-backend/internal/config"
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
		cfg.TLS = true
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

// isLoopbackOnlyAddr reports whether addr binds exclusively to a loopback interface.
func isLoopbackOnlyAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
