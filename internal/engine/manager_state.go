package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/hatemosphere/pulumi-backend/internal/gziputil"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// fetchStateRaw returns raw deployment bytes for the given version (or current if nil).
func (m *Manager) fetchStateRaw(ctx context.Context, org, project, stack string, version *int) ([]byte, bool, error) {
	if version != nil {
		return m.store.GetStateVersionRaw(ctx, org, project, stack, *version)
	}
	data, _, isCompressed, err := m.store.GetCurrentStateRaw(ctx, org, project, stack)
	return data, isCompressed, err
}

// ExportState returns the deployment JSON for a stack (current version if nil).
func (m *Manager) ExportState(ctx context.Context, org, project, stack string, version *int) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "engine.ExportState",
		trace.WithAttributes(attribute.String("stack", stackKey(org, project, stack))))
	defer span.End()
	key := stackKey(org, project, stack)

	if version == nil {
		if cachedCompressed, ok := m.cache.Get(key); ok {
			return gziputil.Decompress(cachedCompressed)
		}
	}

	data, isCompressed, err := m.fetchStateRaw(ctx, org, project, stack, version)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, ErrStackNotFound
	}

	if version == nil {
		if isCompressed {
			m.cache.Add(key, data)
		} else {
			if compressed, err := gziputil.Compress(data); err == nil {
				m.cache.Add(key, compressed)
			}
		}
	}

	if isCompressed {
		return gziputil.Decompress(data)
	}
	return data, nil
}

// ExportStateCompressed returns raw deployment bytes, potentially still gzip-compressed.
func (m *Manager) ExportStateCompressed(ctx context.Context, org, project, stack string, version *int) ([]byte, bool, error) {
	ctx, span := tracer.Start(ctx, "engine.ExportStateCompressed")
	defer span.End()
	key := stackKey(org, project, stack)

	if version == nil {
		if cachedCompressed, ok := m.cache.Get(key); ok {
			return cachedCompressed, true, nil
		}
	}

	var ver int
	if version != nil {
		ver = *version
	} else {
		st, err := m.store.GetStack(ctx, org, project, stack)
		if err != nil {
			return nil, false, err
		}
		if st == nil {
			return nil, false, ErrStackNotFound
		}
		ver = st.Version
	}
	if ver == 0 {
		return storage.EmptyDeployment, false, nil
	}

	data, isCompressed, err := m.store.GetStateVersionRaw(ctx, org, project, stack, ver)
	if err != nil {
		return nil, false, err
	}
	if data == nil {
		return nil, false, fmt.Errorf("state version %d not found", ver)
	}

	if version == nil && isCompressed {
		m.cache.Add(key, data)
	} else if version == nil && !isCompressed {
		if compressed, err := gziputil.Compress(data); err == nil {
			m.cache.Add(key, compressed)
			return compressed, true, nil
		}
	}

	return data, isCompressed, nil
}

// ImportState saves new deployment state for a stack, bumping the version.
func (m *Manager) ImportState(ctx context.Context, org, project, stack string, deployment []byte) error {
	ctx, span := tracer.Start(ctx, "engine.ImportState",
		trace.WithAttributes(attribute.String("stack", stackKey(org, project, stack))))
	defer span.End()
	key := stackKey(org, project, stack)

	st, err := m.store.GetStack(ctx, org, project, stack)
	if err != nil {
		return err
	}
	if st == nil {
		return ErrStackNotFound
	}

	newVersion := st.Version + 1
	hash := sha256.Sum256(deployment)
	resourceCount := storage.CountResources(deployment)

	compressed, err := gziputil.Compress(deployment)
	if err != nil {
		return fmt.Errorf("compress deployment: %w", err)
	}

	err = m.store.SaveState(ctx, &storage.StackState{
		OrgName:       org,
		ProjectName:   project,
		StackName:     stack,
		Version:       newVersion,
		Deployment:    compressed,
		Hash:          hex.EncodeToString(hash[:]),
		ResourceCount: resourceCount,
	})
	if err != nil {
		return err
	}

	m.cache.Add(key, compressed)
	return nil
}
