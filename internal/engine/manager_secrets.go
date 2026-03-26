package engine

import (
	"context"
)

// EncryptValue encrypts a value using the stack's per-stack DEK.
func (m *Manager) EncryptValue(ctx context.Context, org, project, stack string, plaintext []byte) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "engine.EncryptValue")
	defer span.End()
	key, err := m.getOrCreateSecretsKey(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	return m.secrets.Encrypt(key, plaintext)
}

// DecryptValue decrypts a value using the stack's per-stack DEK.
func (m *Manager) DecryptValue(ctx context.Context, org, project, stack string, ciphertext []byte) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "engine.DecryptValue")
	defer span.End()
	key, err := m.getOrCreateSecretsKey(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	return m.secrets.Decrypt(key, ciphertext)
}

func (m *Manager) getOrCreateSecretsKey(ctx context.Context, org, project, stack string) ([]byte, error) {
	cacheKey := stackKey(org, project, stack)
	if cached, ok := m.secretsCache.Get(cacheKey); ok {
		result := make([]byte, len(cached))
		copy(result, cached)
		return result, nil
	}

	existing, err := m.store.GetSecretsKey(ctx, org, project, stack)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		decrypted, err := m.secrets.DecryptKey(ctx, existing)
		if err != nil {
			return nil, err
		}
		return m.cacheSecretsKey(cacheKey, decrypted), nil
	}

	newStackKey, encryptedStackKey, err := m.secrets.GenerateStackKey(ctx)
	if err != nil {
		return nil, err
	}
	if err := m.store.SaveSecretsKey(ctx, org, project, stack, encryptedStackKey); err != nil {
		return nil, err
	}
	return m.cacheSecretsKey(cacheKey, newStackKey), nil
}

// cacheSecretsKey stores a copy of plaintext in the secrets cache and returns a separate copy for the caller.
func (m *Manager) cacheSecretsKey(cacheKey string, plaintext []byte) []byte {
	cached := make([]byte, len(plaintext))
	copy(cached, plaintext)
	m.secretsCache.Add(cacheKey, cached)
	result := make([]byte, len(plaintext))
	copy(result, plaintext)
	return result
}
