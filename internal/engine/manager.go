package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segmentio/encoding/json"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/hatemosphere/pulumi-backend/internal/backup"
	"github.com/hatemosphere/pulumi-backend/internal/clockutil"
	"github.com/hatemosphere/pulumi-backend/internal/gziputil"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

var tracer = otel.Tracer("pulumi-backend/engine")

// Sentinel errors for update state conflicts (mapped to HTTP 409 in the API layer).
var (
	ErrUpdateNotInProgress  = errors.New("The Update has not started or The Update has been cancelled or The Update has already completed")
	ErrStackHasActiveUpdate = errors.New("Another update is currently in progress.")
	ErrNoActiveUpdate       = errors.New("The Update has not started")
	ErrStackNotFound        = errors.New("stack not found")
	ErrUpdateNotFound       = errors.New("update not found")
	ErrInvalidUpdateToken   = errors.New("invalid update token")
	ErrUpdateTokenExpired   = errors.New("update token expired")
	ErrStackHasResources    = errors.New("Bad Request: Stack still contains resources.")
)

// ManagerConfig holds tuning parameters for the engine manager.
type ManagerConfig struct {
	LeaseDuration      time.Duration
	CacheSize          int
	EventBufferSize    int
	EventFlushInterval time.Duration
	BackupDir          string
	BackupProviders    []backup.Provider
	BackupSchedule     time.Duration
	BackupRetention    int
	BackgroundContext  context.Context
	Clock              clockutil.Clock
}

// BackupResult holds the result of a backup operation.
type BackupResult struct {
	LocalPath  string
	RemoteKeys map[string]string // provider name → remote key
}

// eventBuffer groups the fields used for async event buffering.
type eventBuffer struct {
	mu   sync.Mutex
	buf  []storage.EngineEvent
	max  int
	stop chan struct{}
	done chan struct{}
}

// Manager is the core engine orchestrating stacks, updates, and state.
type Manager struct {
	store         storage.Store
	secrets       *SecretsEngine
	cache         *lru.Cache[string, []byte] // key: org/project/stack, value: deployment JSON
	secretsCache  *lru.Cache[string, []byte] // key: org/project/stack, value: decrypted stack key
	stackLocks    sync.Map                   // key: org/project/stack -> *stackLock
	leaseDuration time.Duration
	backupDir     string

	// Remote backup providers (e.g., S3).
	backupProviders []backup.Provider
	backupRetention int
	backupScheduler *backup.Scheduler

	// Active update tracking.
	activeUpdates atomic.Int64

	// Async event buffering.
	events eventBuffer

	backgroundCtx context.Context
	cancel        context.CancelFunc
	clock         clockutil.Clock
}

type stackLock struct {
	mu       sync.Mutex
	updateID string
	expiry   time.Time
}

// NewManager creates a new engine manager.
func NewManager(store storage.Store, secrets *SecretsEngine, cfgs ...ManagerConfig) (*Manager, error) {
	cfg := ManagerConfig{
		LeaseDuration:      5 * time.Minute,
		CacheSize:          256,
		EventBufferSize:    1000,
		EventFlushInterval: time.Second,
		BackgroundContext:  context.Background(),
		Clock:              clockutil.RealClock{},
	}
	if len(cfgs) > 0 {
		c := cfgs[0]
		if c.LeaseDuration > 0 {
			cfg.LeaseDuration = c.LeaseDuration
		}
		if c.CacheSize > 0 {
			cfg.CacheSize = c.CacheSize
		}
		if c.EventBufferSize > 0 {
			cfg.EventBufferSize = c.EventBufferSize
		}
		if c.EventFlushInterval > 0 {
			cfg.EventFlushInterval = c.EventFlushInterval
		}
		cfg.BackupDir = c.BackupDir
		cfg.BackupProviders = c.BackupProviders
		cfg.BackupSchedule = c.BackupSchedule
		cfg.BackupRetention = c.BackupRetention
		if c.BackgroundContext != nil {
			cfg.BackgroundContext = c.BackgroundContext
		}
		if c.Clock != nil {
			cfg.Clock = c.Clock
		}
	}

	cache, err := lru.New[string, []byte](cfg.CacheSize)
	if err != nil {
		return nil, err
	}
	secretsCache, err := lru.NewWithEvict(cfg.CacheSize, func(_ string, value []byte) {
		for i := range value {
			value[i] = 0
		}
	})
	if err != nil {
		return nil, err
	}
	bgCtx, cancel := context.WithCancel(cfg.BackgroundContext)
	m := &Manager{
		store:           store,
		secrets:         secrets,
		cache:           cache,
		secretsCache:    secretsCache,
		leaseDuration:   cfg.LeaseDuration,
		backupDir:       cfg.BackupDir,
		backupProviders: cfg.BackupProviders,
		backupRetention: cfg.BackupRetention,
		backgroundCtx:   bgCtx,
		cancel:          cancel,
		clock:           cfg.Clock,
		events: eventBuffer{
			max:  cfg.EventBufferSize,
			stop: make(chan struct{}),
			done: make(chan struct{}),
		},
	}

	// Start the periodic event flusher.
	go m.eventFlusher(cfg.EventFlushInterval)

	// Start backup scheduler if configured.
	if cfg.BackupSchedule > 0 && (cfg.BackupDir != "" || len(cfg.BackupProviders) > 0) {
		m.backupScheduler = backup.NewScheduler(bgCtx, func(ctx context.Context) error {
			_, err := m.Backup(ctx)
			return err
		}, cfg.BackupSchedule)
	}

	return m, nil
}

// Shutdown flushes buffered events and stops background goroutines.
func (m *Manager) Shutdown() {
	m.cancel()
	close(m.events.stop)
	<-m.events.done

	if m.backupScheduler != nil {
		m.backupScheduler.Shutdown()
	}
}

// Ping checks that the underlying storage is reachable.
func (m *Manager) Ping(ctx context.Context) error {
	return m.store.Ping(ctx)
}

// ActiveUpdateCount returns the number of currently active (in-progress) updates.
func (m *Manager) ActiveUpdateCount() int64 {
	return m.activeUpdates.Load()
}

func stackKey(org, project, stack string) string {
	return org + "/" + project + "/" + stack
}

// --- Stack Operations ---

// CreateStack creates a new stack with the given tags.
func (m *Manager) CreateStack(ctx context.Context, org, project, stackName string, tags map[string]string) error {
	ctx, span := tracer.Start(ctx, "engine.CreateStack",
		trace.WithAttributes(attribute.String("stack", stackKey(org, project, stackName))))
	defer span.End()
	if tags == nil {
		tags = map[string]string{}
	}
	return m.store.CreateStack(ctx, &storage.Stack{
		OrgName:     org,
		ProjectName: project,
		StackName:   stackName,
		Tags:        tags,
	})
}

// GetStack returns the stack metadata, or nil if not found.
func (m *Manager) GetStack(ctx context.Context, org, project, stack string) (*storage.Stack, error) {
	return m.store.GetStack(ctx, org, project, stack)
}

// DeleteStack removes a stack. If force is false, it rejects deletion when resources remain.
func (m *Manager) DeleteStack(ctx context.Context, org, project, stack string, force bool) error {
	ctx, span := tracer.Start(ctx, "engine.DeleteStack",
		trace.WithAttributes(attribute.String("stack", stackKey(org, project, stack))))
	defer span.End()
	if !force {
		state, err := m.store.GetCurrentState(ctx, org, project, stack)
		if err != nil {
			return err
		}
		if state != nil && state.Version > 0 {
			// Check if there are resources.
			var deployment struct {
				Deployment struct {
					Resources []json.RawMessage `json:"resources"`
				} `json:"deployment"`
			}
			// Decompress if necessary before unmarshaling.
			deploymentData := state.Deployment
			if decompressed, err := gziputil.MaybeDecompress(state.Deployment); err == nil {
				deploymentData = decompressed
			}

			if err := json.Unmarshal(deploymentData, &deployment); err == nil {
				if len(deployment.Deployment.Resources) > 0 {
					return ErrStackHasResources
				}
			}
		}
	}
	m.cache.Remove(stackKey(org, project, stack))
	m.secretsCache.Remove(stackKey(org, project, stack))
	return m.store.DeleteStack(ctx, org, project, stack)
}

// ListStacks returns a page of stacks with an optional continuation token.
func (m *Manager) ListStacks(ctx context.Context, org, project, continuationToken string, pageSize int) ([]storage.Stack, string, error) {
	return m.store.ListStacks(ctx, org, project, continuationToken, pageSize)
}

// ProjectExists reports whether any stacks exist under the given project.
func (m *Manager) ProjectExists(ctx context.Context, org, project string) (bool, error) {
	return m.store.ProjectExists(ctx, org, project)
}

// UpdateStackTags replaces the tags on a stack.
func (m *Manager) UpdateStackTags(ctx context.Context, org, project, stack string, tags map[string]string) error {
	return m.store.UpdateStackTags(ctx, org, project, stack, tags)
}

// RenameStack moves a stack to a new project/name, invalidating caches.
func (m *Manager) RenameStack(ctx context.Context, org, oldProject, oldName, newProject, newName string) error {
	ctx, span := tracer.Start(ctx, "engine.RenameStack")
	defer span.End()
	m.cache.Remove(stackKey(org, oldProject, oldName))
	m.secretsCache.Remove(stackKey(org, oldProject, oldName))
	return m.store.RenameStack(ctx, org, oldProject, oldName, newProject, newName)
}
