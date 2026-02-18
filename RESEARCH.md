# Pulumi Self-Hosted Backend: Research & Architecture

## Table of Contents
1. [Problem Statement](#problem-statement)
2. [How Pulumi State Works](#how-pulumi-state-works)
3. [The HTTP API Protocol](#the-http-api-protocol)
4. [Performance Bottlenecks in Existing Backends](#performance-bottlenecks)
5. [Journaling: The Key Innovation](#journaling)
6. [Storage Engine Analysis](#storage-engine-analysis)
7. [Architecture Plan](#architecture-plan)

---

## 1. Problem Statement

Pulumi CLI communicates with a backend to store infrastructure state. There are two classes:

- **Pulumi Cloud** (SaaS at api.pulumi.com) — rich REST API, transactional, supports journaling, delta checkpoints. The fastest option.
- **DIY backends** (S3, GCS, Azure Blob, PostgreSQL, file://) — blob storage protocol, sequential writes, full-snapshot uploads. 2-3.5x slower than Pulumi Cloud.

**Goal**: Build a self-hosted backend that implements the Pulumi Cloud HTTP API protocol and matches or exceeds the performance of the SaaS offering, with a single-binary deployment model.

---

## 2. How Pulumi State Works

### State Structure

```go
type Snapshot struct {
    Manifest          Manifest
    SecretsManager    secrets.Manager
    Resources         []*resource.State    // all tracked resources
    PendingOperations []resource.Operation // in-flight operations for crash recovery
    Metadata          SnapshotMetadata
}
```

### Checkpoint JSON Format (top-level)

```json
{
    "version": 3,
    "deployment": {
        "manifest": { "time": "...", "magic": "...", "version": "..." },
        "secrets_providers": { "type": "service", "state": { "url": "...", "owner": "..." } },
        "resources": [
            {
                "urn": "urn:pulumi:stack::project::aws:s3/bucket:Bucket::my-bucket",
                "custom": true,
                "type": "aws:s3/bucket:Bucket",
                "id": "my-bucket-1234567",
                "inputs": { "bucket": "my-bucket" },
                "outputs": { "arn": "arn:aws:s3:::my-bucket", "bucket": "my-bucket" },
                "parent": "urn:pulumi:stack::project::pulumi:pulumi:Stack::project-stack",
                "provider": "urn:pulumi:stack::project::pulumi:providers:aws::default::1234",
                "dependencies": ["urn:pulumi:stack::project::aws:iam/role:Role::my-role"],
                "protect": false
            }
        ],
        "pending_operations": []
    }
}
```

### Size Characteristics
- Small stacks: 10-100KB
- Medium stacks: 100KB-1MB
- Large stacks: 1-10MB
- Very large stacks (1000+ resources with verbose outputs): 10-50MB+
- State scales linearly with resource count and output verbosity

---

## 3. The HTTP API Protocol (Critical Path)

### Authentication
```
Authorization: token {api_token}
Authorization: update-token {lease_token}
Accept: application/vnd.pulumi+8
Content-Type: application/json
```

### Core Endpoints (Minimum Viable Backend)

#### Capabilities
```
GET /api/capabilities
→ { "deltaCheckpointUpdates": { "checkpointCutoffSizeBytes": N }, "journaling": true, ... }
```

#### User / Auth
```
GET /api/user → { "githubLogin": "...", "organizations": [...], "tokenInformation": {...} }
GET /api/user/stacks → { "stacks": [...], "continuationToken": "..." }
GET /api/cli/version → { "latestVersion": "...", "oldestWithoutWarning": "..." }
```

#### Stack CRUD
```
POST   /api/stacks/{org}/{project}                          → create stack
GET    /api/stacks/{org}/{project}/{stack}                   → get stack info
DELETE /api/stacks/{org}/{project}/{stack}?force=bool        → delete stack
HEAD   /api/stacks/{org}/{project}                           → project exists?
PATCH  /api/stacks/{org}/{project}/{stack}/tags              → update tags
POST   /api/stacks/{org}/{project}/{stack}/rename            → rename stack
```

#### State Export/Import
```
GET  /api/stacks/{org}/{project}/{stack}/export              → full deployment state
GET  /api/stacks/{org}/{project}/{stack}/export/{version}    → versioned export
POST /api/stacks/{org}/{project}/{stack}/import              → import deployment
```

#### Secrets (must implement for Pulumi Cloud secrets manager)
```
POST /api/stacks/{org}/{project}/{stack}/encrypt             → encrypt a value
POST /api/stacks/{org}/{project}/{stack}/decrypt             → decrypt a value
POST /api/stacks/{org}/{project}/{stack}/batch-encrypt       → batch encrypt
POST /api/stacks/{org}/{project}/{stack}/batch-decrypt       → batch decrypt
```

#### Update Lifecycle (THE critical hot path)
```
POST /api/stacks/{org}/{project}/{stack}/{updateKind}        → create update (preview/update/refresh/destroy)
POST /api/stacks/{org}/{project}/{stack}/{updateKind}/{id}   → start update (returns lease token)
POST /api/stacks/{org}/{project}/{stack}/{updateKind}/{id}/renew_lease  → renew lease
POST /api/stacks/{org}/{project}/{stack}/{updateKind}/{id}/complete     → complete update

# Checkpoint persistence (3 modes):
PATCH /api/stacks/{org}/{project}/{stack}/{updateKind}/{id}/checkpoint          → full checkpoint
PATCH /api/stacks/{org}/{project}/{stack}/{updateKind}/{id}/checkpointverbatim  → full verbatim bytes
PATCH /api/stacks/{org}/{project}/{stack}/{updateKind}/{id}/checkpointdelta     → delta only

# Journaling (fastest mode):
PATCH /api/stacks/{org}/{project}/{stack}/{updateKind}/{id}/journalentries      → journal entries

# Engine events (for activity log):
POST /api/stacks/{org}/{project}/{stack}/{updateKind}/{id}/events/batch         → batched events
POST /api/stacks/{org}/{project}/{stack}/{updateKind}/{id}/events               → single event

# Cancel:
POST /api/stacks/{org}/{project}/{stack}/{updateKind}/{id}/cancel
```

#### Update History
```
GET /api/stacks/{org}/{project}/{stack}/updates              → list updates
GET /api/stacks/{org}/{project}/{stack}/updates/latest       → latest update info
GET /api/stacks/{org}/{project}/{stack}/updates/{version}    → specific update
```

### Update Lifecycle Sequence (pulumi up)

```
CLI                                    Backend
 │                                      │
 │── GET /api/capabilities ───────────→│  (what features supported?)
 │←─ { deltaCheckpoints, journaling } ─│
 │                                      │
 │── POST /api/stacks/.../update ─────→│  (create update session)
 │←─ { updateID, messages } ───────────│
 │                                      │
 │── POST /api/stacks/.../{updateID} ─→│  (start update, request journaling)
 │←─ { version, token, journalVer } ───│  (lease token for subsequent calls)
 │                                      │
 │── GET /api/stacks/.../export ──────→│  (fetch current state)
 │←─ { deployment: {...} } ────────────│
 │                                      │
 │   [engine runs, processes resources] │
 │                                      │
 │── PATCH .../journalentries ────────→│  (batch of journal entries)
 │── PATCH .../journalentries ────────→│  (parallel batches OK)
 │── POST .../events/batch ───────────→│  (engine events for activity log)
 │── POST .../renew_lease ────────────→│  (background, every duration/8)
 │←─ { token: "new_token" } ───────────│
 │── PATCH .../journalentries ────────→│
 │                                      │
 │── POST .../complete ───────────────→│  (succeeded/failed)
 │                                      │
```

### Checkpoint Modes (Server Selects via Capabilities)

| Mode | Endpoint | Data Sent | When Used |
|------|----------|-----------|-----------|
| Full | `/checkpoint` | Entire deployment JSON | Fallback, no capability |
| Verbatim | `/checkpointverbatim` | Raw JSON bytes + sequence# | Server supports verbatim |
| Delta | `/checkpointdelta` | SHA256 hash + unified diff | Large states, delta capable |
| **Journal** | `/journalentries` | **Small per-resource entries** | **Fastest: 20x improvement** |

---

## 4. Performance Bottlenecks in Existing Backends

### DIY (S3/file) Backend Issues

| Bottleneck | Impact | Details |
|------------|--------|---------|
| Full checkpoint on every step | O(state_size × resource_count) I/O | Every resource step uploads entire state |
| Sequential blob writes | No parallelism | Race prevention forces serial writes |
| Lock probing via List RPC | 4 RPCs per operation | Check, write, recheck, delete |
| `stackPath` probes bucket every access | Extra List RPC per call | No caching of .json vs .json.gz |
| `ListStacks` loads all checkpoints | O(3N+1) RPCs for N stacks | Full checkpoint read per stack |
| Backup on every save | 2-4 extra RPCs | Exists + Copy + optional Delete |
| History copy per update | Full object copy | Entire checkpoint duplicated |
| No caching | Every call hits storage | No in-memory cache |

### Benchmark: S3 vs Pulumi Cloud (from issue #10057)
- **Provisioning**: S3 is **3.5x slower** than Pulumi Cloud
- **Destruction**: S3 is **2x slower** than Pulumi Cloud
- Root cause: serial writes + go-cloud library overhead

### Journaling Performance (from Pulumi blog)

| Stack | Operation | Before | After | Speedup |
|-------|-----------|--------|-------|---------|
| 3,222 S3 objects | Full create | 58m 26s / 16.5MB | 2m 50s / 2.3MB | **~20x** |
| 3,222 S3 objects | Half update | 34m 49s / 13.8MB | 1m 45s / 2.3MB | **~20x** |
| Real app+API | Full deploy | 17m 52s / 18.5MB | 9m 12s / 5.9MB | ~2x |

---

## 5. Journaling: The Key Innovation

### Journal Entry Structure

```go
type JournalEntry struct {
    Version               int
    Kind                  JournalEntryKind   // BEGIN=0, SUCCESS=1, FAILURE=2, REFRESH_SUCCESS=3, OUTPUTS=4, WRITE=5, SECRETS_MANAGER=6, REBUILT_BASE_STATE=7
    SequenceID            int64              // replay ordering
    OperationID           int64
    RemoveOld             *int64
    RemoveNew             *int64
    PendingReplacementOld *int64
    PendingReplacementNew *int64
    DeleteOld             *int64
    DeleteNew             *int64
    State                 *ResourceV3
    Operation             *OperationV2
    RebuildDependencies   bool
    SecretsProvider       *SecretsProvidersV1
    NewSnapshot           *DeploymentV3
}
```

### Why Journaling is Fast
1. Each entry describes ONE resource change (tiny payload vs full snapshot)
2. Entries sent in parallel (SequenceID for ordering)
3. Server reconstructs full state by replaying entries against base snapshot
4. Network I/O reduced from O(state_size × N) to O(entry_size × N)

### Reconstruction Algorithm
1. Start from base snapshot
2. Replay journal entries in sequence order:
   - `BEGIN`: track as incomplete operation
   - `SUCCESS`: append new resource, mark old for deletion
   - `REFRESH_SUCCESS`: update/delete in base
   - `FAILURE`: remove from incomplete ops
   - `OUTPUTS`: update resource outputs in place
3. Merge new resources with untouched base resources
4. Collect pending ops from incomplete entries

### Client Batching
- Default batch size: 100 entries
- Default flush period: 50ms
- Buffered flush channel: capacity 100
- On HTTP 413 (too large): recursively split batch in half and retry
- `ElideWrite=true` entries are fire-and-forget (non-blocking)

---

## 6. Storage Engine Analysis

### Deployment Model: Central HTTP Server

```
Developer A (CLI) ──┐                    ┌──────────────────┐
Developer B (CLI) ──┼── HTTPS/network ──→│  Backend Server   │──→ Storage Engine
CI/CD pipeline   ──┘                    │  (single process) │
                                         └──────────────────┘
```

**Key insight**: This is NOT a direct-access database problem. The storage engine is
embedded INSIDE the HTTP server. All concurrency, locking, and multi-user coordination
happens at the application layer in Go — not at the storage layer. Multiple users access
the server over HTTP; the server serializes writes to the storage engine internally.

This is the same architecture as Pulumi Cloud itself (web service → database), except
we eliminate the network hop between service and storage by embedding the engine.

### Concurrency & Locking Model

| Concern | Solution | Layer |
|---------|----------|-------|
| Multiple users reading stacks | HTTP server handles concurrent GET requests | Application |
| Only one update per stack | In-memory `sync.Mutex` per stack + lease tokens | Application |
| Stale lock from crashed CLI | Lease expiry (token TTL, default 5 min) | Application |
| Server crash during update | `pending_operations` in persisted state | Storage |
| Multiple CLI reads during update | WAL mode: readers don't block writer | Storage |

Stack locking flow:
1. `POST .../update` → server acquires in-memory lock for `(org, project, stack)`
2. Returns lease token with TTL
3. All subsequent calls authenticate with lease token
4. `POST .../complete` → releases lock
5. If CLI crashes → token expires → lock auto-releases after TTL

### Requirements for Optimal Pulumi State Storage

| Requirement | Priority | Details |
|-------------|----------|---------|
| Low-latency reads | Critical | Export full state at update start |
| Low-latency writes | Critical | Journal entries / checkpoints during update |
| Concurrent reads | High | Multiple CLI clients reading different stacks |
| Durability | Critical | State must survive server restart |
| JSON document storage | High | State is JSON, 1KB-50MB |
| Versioning / history | Medium | Keep history of all updates |
| Crash recovery | High | Pending operations must survive crashes |
| Single binary deployment | High | Simplicity goal |
| Encryption at rest | Medium | Secrets in state |
| HA / horizontal scaling | Low (Phase 3) | Can be deferred; single server handles most teams |

### Storage Engine Comparison

| Engine | Type | Write Latency | Read Latency | Max Doc Size | Single Binary | HA Path | Notes |
|--------|------|--------------|-------------|-------------|---------------|---------|-------|
| **SQLite WAL** | Embedded SQL | ~10μs | ~5μs | Unlimited (BLOB) | Yes | LiteFS / Litestream | Proven, simple, excellent for single-node |
| **Pebble** | Embedded KV (LSM) | ~3μs | ~8μs | Unlimited | Yes | Manual replication | CockroachDB's engine, excellent write perf |
| **BadgerDB** | Embedded KV (LSM) | ~5μs | ~10μs | Unlimited | Yes | Manual replication | Go native, SSD optimized |
| **bbolt** | Embedded KV (B+tree) | ~50μs | ~5μs | Unlimited | Yes | Manual replication | Used by etcd, simple |
| **PostgreSQL** | RDBMS | ~1ms | ~500μs | 1GB (TOAST) | Separate process | Native streaming replication | Already a DIY backend; adds network hop |
| **Redis** | Network KV | ~100μs | ~100μs | 512MB | Separate process | Redis Sentinel/Cluster | Adds network hop + separate process |
| **FoundationDB** | Distributed KV | ~2ms | ~500μs | **100KB limit!** | Cluster | Native | Value size limit kills this |
| **etcd** | Distributed KV | ~2ms | ~1ms | **1.5MB limit!** | Cluster | Native Raft | Value size limit kills this |

### Recommendation: SQLite WAL (with HA path via Litestream/LiteFS)

**Primary: SQLite in WAL mode**
- Mature, battle-tested, incredibly fast for this workload
- WAL mode: concurrent readers never block, writer never blocks readers
- JSON1 extension for optional querying of state internals
- `modernc.org/sqlite` — pure Go, no CGo, compiles to single binary
- Storage is a single file — trivial to backup, snapshot, move

**Multi-user remote access**: Fully handled by the HTTP server layer. Users never touch
SQLite directly. The server is the sole accessor. This is how Litestream, Turso, Cloudflare
D1, and many production systems use SQLite successfully.

**HA / replication path** (when needed, Phase 3):
- **Litestream**: Continuous WAL streaming to S3/GCS/Azure — async replica, restore on failover
- **LiteFS**: FUSE-based distributed SQLite by Fly.io — transparent read replicas
- **Swap to PostgreSQL/CockroachDB**: Storage interface abstraction allows swapping engines

**Why NOT PostgreSQL as primary**: Adds ~1ms latency per query (network hop) vs ~10μs embedded.
For the hot path (journal entry writes — potentially hundreds per `pulumi up`), this is 100x slower.
PostgreSQL is a fine Phase 3 option behind a storage interface, but defeats the "fastest ever" goal.

**Why NOT Redis**: Same network hop problem. Also ephemeral by default (needs AOF/RDB for durability),
adds operational complexity, and is overkill when the server handles all concurrency internally.

**Why NOT FoundationDB/etcd**: Value size limits (100KB / 1.5MB) cannot hold Pulumi state files
which routinely reach 10-50MB.

---

## 7. Architecture Plan

### Design Principles
1. **Single binary** — no external dependencies (no Redis, no PostgreSQL)
2. **Implement the Pulumi Cloud API** — CLI thinks it's talking to Pulumi Cloud
3. **Journaling support** — advertise journal capability for 20x speedup
4. **Delta checkpoints** — support for non-journaling fallback
5. **In-memory hot cache** — keep active stacks in RAM
6. **Embedded storage** — SQLite WAL for persistence

### High-Level Architecture

```
┌──────────┐  ┌──────────┐  ┌──────────┐
│ Dev A    │  │ Dev B    │  │ CI/CD    │
│ (CLI)    │  │ (CLI)    │  │ (CLI)    │
└────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │              │
     └─────────────┼──────────────┘
                   │ HTTPS (remote)
┌──────────────────▼──────────────────────────────────┐
│              Fast Pulumi Backend (single binary)     │
│                                                      │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │  HTTP Router │  │  Auth/Token  │  │  Secrets   │ │
│  │  (chi/echo)  │  │  Manager     │  │  Engine    │ │
│  └──────┬──────┘  └──────┬───────┘  └─────┬──────┘ │
│         │                │                 │         │
│  ┌──────▼────────────────▼─────────────────▼──────┐ │
│  │              Core Engine                        │ │
│  │                                                 │ │
│  │  ┌─────────────┐  ┌───────────────────────┐    │ │
│  │  │  Stack Mgr   │  │  Update Session Mgr   │    │ │
│  │  │  (CRUD)      │  │  (lifecycle, leases)  │    │ │
│  │  └──────┬──────┘  └───────────┬───────────┘    │ │
│  │         │                     │                  │ │
│  │  ┌──────▼─────────────────────▼──────────────┐  │ │
│  │  │          Journal Replayer                   │  │ │
│  │  │  (reconstruct snapshots from entries)       │  │ │
│  │  └──────────────────┬────────────────────────┘  │ │
│  │                     │                            │ │
│  │  ┌──────────────────▼────────────────────────┐  │ │
│  │  │           In-Memory Cache                   │  │ │
│  │  │  (active stacks, hot snapshots, LRU)        │  │ │
│  │  └──────────────────┬────────────────────────┘  │ │
│  └─────────────────────┼────────────────────────────┘ │
│                        │                               │
│  ┌─────────────────────▼────────────────────────────┐ │
│  │            Storage Layer                          │ │
│  │                                                   │ │
│  │  ┌─────────────────┐  ┌────────────────────────┐ │ │
│  │  │   SQLite WAL    │  │   Blob Store (optional) │ │ │
│  │  │   - stacks      │  │   - large state files   │ │ │
│  │  │   - updates     │  │   - history archives    │ │ │
│  │  │   - journals    │  │   - backups             │ │ │
│  │  │   - events      │  │                          │ │ │
│  │  │   - secrets     │  │                          │ │ │
│  │  └─────────────────┘  └────────────────────────┘ │ │
│  └───────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Implementation Language: Go vs Rust

| Aspect | Go | Rust |
|--------|-----|------|
| Pulumi ecosystem compatibility | Native (same language) | FFI or reimpl |
| Reuse of Pulumi types (apitype) | Direct import | Must redefine |
| HTTP framework maturity | Excellent (chi, echo, fiber) | Excellent (axum, actix) |
| SQLite binding | modernc.org/sqlite (pure Go) | rusqlite (excellent) |
| Single binary | Yes | Yes |
| Performance ceiling | Excellent (GC pauses OK for HTTP) | Higher, no GC |
| Development speed | Faster | Slower |

**Recommendation: Go** — direct reuse of Pulumi's type definitions (`apitype` package), same ecosystem, faster development, and the performance difference vs Rust is negligible for an HTTP API server.

### SQLite Schema

```sql
-- Core tables
CREATE TABLE organizations (
    name TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);

CREATE TABLE projects (
    org_name TEXT NOT NULL REFERENCES organizations(name),
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (org_name, name)
);

CREATE TABLE stacks (
    org_name TEXT NOT NULL,
    project_name TEXT NOT NULL,
    name TEXT NOT NULL,
    tags TEXT,           -- JSON object
    current_version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (org_name, project_name, name),
    FOREIGN KEY (org_name, project_name) REFERENCES projects(org_name, name)
);

-- State storage: current deployment stored inline for small states,
-- or reference to blob for large ones
CREATE TABLE stack_state (
    org_name TEXT NOT NULL,
    project_name TEXT NOT NULL,
    stack_name TEXT NOT NULL,
    version INTEGER NOT NULL,
    deployment BLOB NOT NULL,        -- gzip-compressed JSON (full snapshot)
    deployment_hash TEXT NOT NULL,    -- SHA-256 for delta checking
    created_at INTEGER NOT NULL,
    PRIMARY KEY (org_name, project_name, stack_name, version),
    FOREIGN KEY (org_name, project_name, stack_name)
        REFERENCES stacks(org_name, project_name, name)
);

-- Active update sessions
CREATE TABLE updates (
    id TEXT PRIMARY KEY,             -- UUID
    org_name TEXT NOT NULL,
    project_name TEXT NOT NULL,
    stack_name TEXT NOT NULL,
    kind TEXT NOT NULL,              -- preview/update/refresh/destroy
    status TEXT NOT NULL DEFAULT 'not-started',  -- not-started/in-progress/succeeded/failed
    version INTEGER,                 -- stack version assigned at start
    config TEXT,                     -- JSON
    metadata TEXT,                   -- JSON (commit info, env vars, etc.)
    token TEXT NOT NULL,             -- lease token
    token_expires_at INTEGER NOT NULL,
    journal_version INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    result TEXT,                     -- JSON (resource changes summary)
    FOREIGN KEY (org_name, project_name, stack_name)
        REFERENCES stacks(org_name, project_name, name)
);

-- Journal entries (for active updates)
CREATE TABLE journal_entries (
    update_id TEXT NOT NULL REFERENCES updates(id),
    sequence_id INTEGER NOT NULL,
    entry BLOB NOT NULL,             -- gzip-compressed JSON
    PRIMARY KEY (update_id, sequence_id)
);

-- Engine events (for activity log)
CREATE TABLE engine_events (
    update_id TEXT NOT NULL REFERENCES updates(id),
    sequence INTEGER NOT NULL,
    event BLOB NOT NULL,             -- gzip-compressed JSON
    PRIMARY KEY (update_id, sequence)
);

-- Update history (materialized after update completes)
CREATE TABLE update_history (
    org_name TEXT NOT NULL,
    project_name TEXT NOT NULL,
    stack_name TEXT NOT NULL,
    version INTEGER NOT NULL,
    update_id TEXT NOT NULL REFERENCES updates(id),
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT,
    environment TEXT,                -- JSON
    config TEXT,                     -- JSON
    start_time INTEGER NOT NULL,
    end_time INTEGER,
    resource_changes TEXT,           -- JSON
    PRIMARY KEY (org_name, project_name, stack_name, version)
);

-- Secrets encryption keys (per stack)
CREATE TABLE secrets_keys (
    org_name TEXT NOT NULL,
    project_name TEXT NOT NULL,
    stack_name TEXT NOT NULL,
    encryption_key BLOB NOT NULL,    -- AES-256-GCM key, encrypted with master key
    PRIMARY KEY (org_name, project_name, stack_name)
);

-- API tokens
CREATE TABLE tokens (
    token_hash TEXT PRIMARY KEY,     -- SHA-256 of token
    user_name TEXT NOT NULL,
    description TEXT,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    expires_at INTEGER
);

-- Indexes for common queries
CREATE INDEX idx_stacks_org ON stacks(org_name);
CREATE INDEX idx_updates_stack ON updates(org_name, project_name, stack_name);
CREATE INDEX idx_updates_status ON updates(status) WHERE status = 'in-progress';
CREATE INDEX idx_history_stack ON update_history(org_name, project_name, stack_name, version DESC);
```

### Performance Optimizations

1. **In-memory snapshot cache**: Keep active stack snapshots in an LRU cache. On `GET .../export`, serve from cache. Invalidate on update completion.

2. **Journal replay in memory**: When journaling is active, maintain the base snapshot + journal entries in memory. Reconstruct full snapshot only when needed (export or update completion).

3. **Async event persistence**: Engine events are write-only during an update. Buffer in memory, flush to SQLite in batches asynchronously.

4. **Gzip compression**: Store all large blobs gzip-compressed (deployment state, journal entries, events). Decompress on read. SQLite BLOB type handles binary data efficiently.

5. **Connection pooling**: Use a single SQLite connection with WAL mode. WAL allows concurrent reads during writes. No connection pool needed (SQLite serializes writes anyway).

6. **Zero-copy export**: For `GET .../export`, if the state hasn't changed since last cache, serve the gzip-compressed bytes directly with `Content-Encoding: gzip` — no decompression/recompression.

7. **Lease tokens as in-memory state**: Don't persist lease tokens to SQLite on every renewal. Keep in memory with a sync.Map. If the server restarts, all active updates are lost (acceptable — CLI will retry).

### MVP Scope (Phase 1)

**Must implement** (what `pulumi up/preview/destroy/refresh` needs):
- `GET /api/capabilities` (advertise journaling + delta checkpoints)
- `GET /api/user` (return configured user)
- `POST /api/stacks/{org}/{project}` (create stack)
- `GET /api/stacks/{org}/{project}/{stack}` (get stack)
- `DELETE /api/stacks/{org}/{project}/{stack}` (delete stack)
- `GET /api/stacks/{org}/{project}/{stack}/export` (export state)
- `POST /api/stacks/{org}/{project}/{stack}/import` (import state)
- `POST /api/stacks/{org}/{project}/{stack}/{kind}` (create update)
- `POST /api/stacks/{org}/{project}/{stack}/{kind}/{id}` (start update)
- `PATCH .../checkpoint` (full checkpoint)
- `PATCH .../checkpointverbatim` (verbatim checkpoint)
- `PATCH .../checkpointdelta` (delta checkpoint)
- `PATCH .../journalentries` (journal entries)
- `POST .../events/batch` (engine events — can be no-op initially)
- `POST .../renew_lease` (lease renewal)
- `POST .../complete` (complete update)
- `POST .../encrypt` / `POST .../decrypt` (secrets)
- `GET /api/user/stacks` (list stacks)

**Phase 2** (nice-to-have):
- Update history (`GET .../updates`)
- Stack tags
- Policy packs (stub/no-op)
- Multiple organizations
- Web UI for viewing state

**Phase 3** (advanced):
- Horizontal scaling (replace SQLite with CockroachDB/TiKV)
- Replication / HA
- RBAC / SSO
- Drift detection
- Resource search / insights

### Project Structure

```
pulumi-backend/
├── cmd/
│   └── pulumi-backend/
│       └── main.go              # entry point, CLI flags
├── internal/
│   ├── api/
│   │   ├── router.go            # HTTP routing setup
│   │   ├── middleware.go         # auth, logging, compression
│   │   ├── capabilities.go      # GET /api/capabilities
│   │   ├── user.go              # GET /api/user, GET /api/user/stacks
│   │   ├── stacks.go            # stack CRUD endpoints
│   │   ├── state.go             # export/import endpoints
│   │   ├── updates.go           # update lifecycle endpoints
│   │   ├── checkpoints.go       # checkpoint/delta/verbatim handlers
│   │   ├── journal.go           # journal entries handler
│   │   ├── events.go            # engine events handler
│   │   ├── secrets.go           # encrypt/decrypt endpoints
│   │   └── history.go           # update history endpoints
│   ├── engine/
│   │   ├── manager.go           # core business logic
│   │   ├── stack.go             # stack operations
│   │   ├── update.go            # update session management
│   │   ├── journal_replayer.go  # reconstruct snapshot from journal
│   │   ├── delta.go             # apply delta checkpoints
│   │   ├── lease.go             # lease token management
│   │   └── secrets.go           # encryption/decryption
│   ├── storage/
│   │   ├── storage.go           # storage interface
│   │   ├── sqlite.go            # SQLite WAL implementation
│   │   ├── migrations.go        # schema migrations
│   │   └── cache.go             # LRU in-memory cache
│   └── config/
│       └── config.go            # server configuration
├── reference/                    # cloned repos for reference
│   └── pulumi/
├── go.mod
├── go.sum
├── RESEARCH.md                   # this file
└── README.md
```

### Key Dependencies

```
github.com/go-chi/chi/v5          # HTTP router (fast, stdlib compatible)
modernc.org/sqlite                 # Pure Go SQLite (no CGo!)
github.com/pulumi/pulumi/sdk/v3   # Pulumi types (apitype, resource, etc.)
github.com/google/uuid             # UUID generation
github.com/hashicorp/golang-lru/v2 # LRU cache
golang.org/x/crypto                # AES-GCM for secrets
```

---

## References

- [Pulumi Journaling Blog Post](https://www.pulumi.com/blog/journaling/) — 20x performance improvement details
- [Pulumi Performance Blog](https://www.pulumi.com/blog/amazing-performance/) — CLI boot time optimizations
- [Pulumi PostgreSQL Backend](https://www.pulumi.com/blog/postgres-diy-backend/) — existing DB backend reference
- [GitHub Issue #10057](https://github.com/pulumi/pulumi/issues/10057) — S3 backend performance analysis
- [Pulumi Cloud REST API](https://www.pulumi.com/docs/reference/cloud-rest-api/) — official API docs
- [Pulumi State & Backends](https://www.pulumi.com/docs/iac/concepts/state-and-backends/) — backend architecture
- [Pulumi CLI Source: httpstate](https://github.com/pulumi/pulumi/tree/master/pkg/backend/httpstate) — CLI HTTP client
- [Pulumi CLI Source: diy](https://github.com/pulumi/pulumi/tree/master/pkg/backend/diy) — DIY backend reference
