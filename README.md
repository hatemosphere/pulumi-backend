# pulumi-backend

A self-hosted Pulumi state backend that implements the Pulumi Cloud HTTP API. Single binary, SQLite storage, no cloud dependencies.

## Why

Pulumi's built-in DIY backends (S3, GCS, Azure Blob, local filesystem) store state as opaque JSON blobs. Every operation reads and writes the entire state file, locks are advisory filesystem locks (or missing entirely on some backends), and there's no server-side secrets management — you need `PULUMI_CONFIG_PASSPHRASE` or a KMS provider.

This backend speaks the same HTTP protocol as Pulumi Cloud, so the CLI uses its more efficient `httpstate` code path instead of the `diy` one.

## What's different from DIY blob backends

| | DIY (S3/GCS/filesystem) | This backend |
|---|---|---|
| **State storage** | Single JSON blob per stack, rewritten entirely on every operation | SQLite WAL — only changed rows are written |
| **Checkpoint updates** | Full state upload every time | Delta checkpoints (text diffs with SHA-256 verification) when state > 1MB |
| **Journaling** | Not supported | Server-side journal replay — CLI sends per-resource entries instead of full snapshots |
| **Concurrency** | Advisory file locks (missing on some backends, no TTL) | Server-side update locking with lease renewal and cancel support |
| **Secrets** | Client-side (passphrase or KMS) | Server-side AES-256-GCM, batch encrypt/decrypt |
| **State compression** | None | Gzip-compressed deployment storage in SQLite |
| **Listing/querying** | Walk the bucket listing files | SQL queries with pagination |

## Usage

```
go build -o pulumi-backend ./cmd/pulumi-backend
./pulumi-backend
```

Then point the CLI at it:

```
pulumi login http://localhost:8080
```

### Configuration

Flags and environment variables:

| Flag | Env | Default | Description |
|---|---|---|---|
| `-addr` | `PULUMI_BACKEND_ADDR` | `:8080` | Listen address |
| `-db` | `PULUMI_BACKEND_DB` | `pulumi-backend.db` | SQLite database path |
| `-master-key` | `PULUMI_BACKEND_MASTER_KEY` | (auto-generated) | Hex-encoded 32-byte key for secrets encryption |
| `-org` | `PULUMI_BACKEND_ORG` | `organization` | Default organization name |
| `-user` | `PULUMI_BACKEND_USER` | `admin` | Default user name |
| `-tls` | | `false` | Enable TLS |
| `-cert` | | | TLS certificate file |
| `-key` | | | TLS key file |
| `-lease-duration` | `PULUMI_BACKEND_LEASE_DURATION` | `5m` | Update lease TTL |
| `-cache-size` | `PULUMI_BACKEND_CACHE_SIZE` | `256` | LRU cache size for deployment snapshots |
| `-delta-cutoff` | `PULUMI_BACKEND_DELTA_CUTOFF` | `1048576` | Checkpoint size threshold for delta mode (bytes) |
| `-history-page-size` | `PULUMI_BACKEND_HISTORY_PAGE_SIZE` | `10` | Default page size for update history |
| `-max-state-versions` | `PULUMI_BACKEND_MAX_STATE_VERSIONS` | `50` | Max state versions kept per stack (0 = unlimited) |
| `-stack-list-page-size` | `PULUMI_BACKEND_STACK_LIST_PAGE_SIZE` | `100` | Page size for stack listings |
| `-event-buffer-size` | `PULUMI_BACKEND_EVENT_BUFFER_SIZE` | `1000` | Max buffered events before forced flush |
| `-event-flush-interval` | `PULUMI_BACKEND_EVENT_FLUSH_INTERVAL` | `1s` | Periodic event flush interval |
| `-backup-dir` | `PULUMI_BACKEND_BACKUP_DIR` | (disabled) | Directory for database backups |

If no master key is provided, one is auto-generated and printed to stderr. Persist it if you want secrets to survive restarts.

## API compatibility

Implements the subset of the Pulumi Cloud API that the CLI actually uses:

- Stack CRUD, tags, rename
- State export/import (full and versioned)
- Update lifecycle (create, start, checkpoint, complete, cancel)
- Delta checkpoint uploads (v2) with server-side patching
- Journal entries with server-side replay
- Batch encrypt/decrypt
- Update history
- User/org endpoints (single-tenant, accepts any token)
- Prometheus metrics (`/metrics`)
- OpenAPI 3.0 spec (`GET /api/openapi`)
- Database backup (`POST /api/admin/backup`)

## Tests

```
go test ./...
```

The test suite includes CLI integration tests (require `pulumi` binary), HTTP API contract tests, OpenAPI spec coverage validation, and a benchmark comparing against GCS. To run the spec coverage report: `curl -o pulumi-spec.json https://api.pulumi.com/api/openapi/pulumi-spec.json && go test -v -run TestAPISpecCoverage ./tests/`. To run the GCS benchmark: `RUN_GCS_BENCHMARK=1 go test -v -run TestBenchmarkBackendComparison -timeout 600s ./tests/` (requires `GOOGLE_CLOUD_PROJECT` and GCP Application Default Credentials).

## Performance optimizations status

| Optimization | Status | Notes |
|---|---|---|
| In-memory snapshot cache (LRU) | Done | Configurable LRU cache (default 256 entries), invalidated on update/delete/rename |
| Gzip-compressed state storage | Done | Transparent compress on write, decompress on read, handles legacy uncompressed rows |
| Delta checkpoint uploads | Done | Text diffs with SHA-256 verification, configurable cutoff (default 1MB) |
| Server-side journal replay | Done | CLI sends per-resource entries, server reconstructs full snapshot on completion |
| Single-connection WAL mode | Done | `MaxOpenConns=1`, WAL for concurrent reads during writes |
| In-memory stack locks | Done | `sync.Map`-based locks with expiry, lease renewal updates in-memory expiry |
| Zero-copy gzip export | Done | Serves compressed bytes directly from SQLite with `Content-Encoding: gzip` |
| Async event batching | Done | Events buffered in memory, flushed periodically or when buffer is full |

## TODO

- [ ] Dockerfile
- [ ] CI pipeline (GitHub Actions: build, test, lint)
- [ ] Health check that verifies DB connectivity (`SELECT 1` or `PRAGMA quick_check`)
- [ ] Multi-tenancy, auth, multi-user, RBAC?
- [ ] Web UI
- [ ] SQLite means single-node (no horizontal scaling, HA)

