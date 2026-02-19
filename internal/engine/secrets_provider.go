package engine

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// SecretsProvider abstracts KEK operations (wrap/unwrap per-stack DEKs).
// Implementations must be safe for concurrent use.
type SecretsProvider interface {
	// WrapKey encrypts a raw DEK with the provider's KEK.
	WrapKey(ctx context.Context, rawDEK []byte) ([]byte, error)
	// UnwrapKey decrypts a wrapped DEK, returning the raw key bytes.
	UnwrapKey(ctx context.Context, wrappedDEK []byte) ([]byte, error)
	// ProviderName returns a human-readable identifier (e.g., "local", "gcpkms").
	ProviderName() string
}

// LocalSecretsProvider wraps/unwraps DEKs using a local AES-256-GCM master key.
type LocalSecretsProvider struct {
	masterKey []byte // 32 bytes for AES-256
}

// NewLocalSecretsProvider creates a provider backed by a local AES-256 master key.
func NewLocalSecretsProvider(masterKey []byte) (*LocalSecretsProvider, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be exactly 32 bytes, got %d", len(masterKey))
	}
	return &LocalSecretsProvider{masterKey: masterKey}, nil
}

func (p *LocalSecretsProvider) ProviderName() string { return "local" }

func (p *LocalSecretsProvider) WrapKey(_ context.Context, rawDEK []byte) ([]byte, error) {
	return aesGCMSeal(p.masterKey, rawDEK)
}

func (p *LocalSecretsProvider) UnwrapKey(_ context.Context, wrappedDEK []byte) ([]byte, error) {
	return aesGCMOpen(p.masterKey, wrappedDEK)
}

// KMSSecretsProvider wraps/unwraps DEKs using Google Cloud KMS.
type KMSSecretsProvider struct {
	client      *kms.KeyManagementClient
	keyName     string // projects/P/locations/L/keyRings/R/cryptoKeys/K
	closeClient bool   // whether we own the client and should close it
}

// NewKMSSecretsProvider creates a provider backed by a GCP KMS key.
// The keyName must be a full resource name like
// "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key".
func NewKMSSecretsProvider(ctx context.Context, keyName string) (*KMSSecretsProvider, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create KMS client: %w", err)
	}
	return &KMSSecretsProvider{
		client:      client,
		keyName:     keyName,
		closeClient: true,
	}, nil
}

// NewKMSSecretsProviderWithClient creates a provider using an existing KMS client.
// Useful for testing with mock clients.
func NewKMSSecretsProviderWithClient(client *kms.KeyManagementClient, keyName string) *KMSSecretsProvider {
	return &KMSSecretsProvider{
		client:  client,
		keyName: keyName,
	}
}

func (p *KMSSecretsProvider) ProviderName() string { return "gcpkms" }

func (p *KMSSecretsProvider) WrapKey(ctx context.Context, rawDEK []byte) ([]byte, error) {
	resp, err := p.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      p.keyName,
		Plaintext: rawDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS encrypt: %w", err)
	}
	return resp.Ciphertext, nil
}

func (p *KMSSecretsProvider) UnwrapKey(ctx context.Context, wrappedDEK []byte) ([]byte, error) {
	resp, err := p.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       p.keyName,
		Ciphertext: wrappedDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS decrypt: %w", err)
	}
	return resp.Plaintext, nil
}

// Close releases resources held by the provider. Only needed for KMS.
func (p *KMSSecretsProvider) Close() error {
	if p.closeClient && p.client != nil {
		return p.client.Close()
	}
	return nil
}
