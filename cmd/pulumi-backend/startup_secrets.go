package main

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"github.com/hatemosphere/pulumi-backend/internal/config"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// --- Secrets ---

const canaryPlaintext = "pulumi-backend-secrets-canary"

func buildSecretsProvider(ctx context.Context, cfg *config.Config) (engine.SecretsProvider, error) {
	provider, err := newSecretsProvider(ctx, cfg.SecretsProvider, cfg.MasterKey, cfg.KMSKeyResourceName)
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

	if err := store.SetConfig(context.Background(), "secrets_canary", ""); err != nil {
		return fmt.Errorf("clear old canary: %w", err)
	}
	if err := verifySecretsProvider(store, newProvider); err != nil {
		return fmt.Errorf("store new canary: %w", err)
	}

	slog.Info("secrets key migration complete")
	return nil
}

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
