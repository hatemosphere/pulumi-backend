# pulumi-backend

A self-hosted Pulumi state backend that implements the Pulumi Cloud HTTP API. Single binary, SQLite storage, no cloud dependencies required.

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
| **Secrets** | Client-side (passphrase or KMS) | Server-side AES-256-GCM with optional GCP KMS key wrapping |
| **State compression** | None | Gzip-compressed deployment storage in SQLite |
| **Listing/querying** | Walk the bucket listing files | SQL queries with pagination |
| **Auth** | None | Single-tenant, Google OIDC, or JWT with RBAC |

## Usage

```bash
go build -o pulumi-backend ./cmd/pulumi-backend
./pulumi-backend
```

Then point the CLI at it:

```bash
pulumi login http://localhost:8080
```

With Google OIDC auth, set `PULUMI_CONSOLE_DOMAIN` for automatic browser-based login (no token copy-paste):

```bash
export PULUMI_CONSOLE_DOMAIN=localhost:8080
pulumi login http://localhost:8080  # opens browser for Google sign-in
```

### Configuration

All flags have corresponding environment variables with the `PULUMI_BACKEND_` prefix.

#### Core

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

If no master key is provided, one is auto-generated and printed to stderr. Persist it if you want secrets to survive restarts.

#### Performance tuning

| Flag | Env | Default | Description |
|---|---|---|---|
| `-lease-duration` | `PULUMI_BACKEND_LEASE_DURATION` | `5m` | Update lease TTL |
| `-cache-size` | `PULUMI_BACKEND_CACHE_SIZE` | `256` | LRU cache size for deployment snapshots |
| `-delta-cutoff` | `PULUMI_BACKEND_DELTA_CUTOFF` | `1048576` | Checkpoint size threshold for delta mode (bytes) |
| `-history-page-size` | `PULUMI_BACKEND_HISTORY_PAGE_SIZE` | `10` | Default page size for update history |
| `-max-state-versions` | `PULUMI_BACKEND_MAX_STATE_VERSIONS` | `50` | Max state versions kept per stack (0 = unlimited) |
| `-stack-list-page-size` | `PULUMI_BACKEND_STACK_LIST_PAGE_SIZE` | `100` | Page size for stack listings |
| `-event-buffer-size` | `PULUMI_BACKEND_EVENT_BUFFER_SIZE` | `1000` | Max buffered events before forced flush |
| `-event-flush-interval` | `PULUMI_BACKEND_EVENT_FLUSH_INTERVAL` | `1s` | Periodic event flush interval |
| `-backup-dir` | `PULUMI_BACKEND_BACKUP_DIR` | (disabled) | Directory for SQLite VACUUM INTO backups |

#### Secrets provider

| Flag | Env | Default | Description |
|---|---|---|---|
| `-secrets-provider` | `PULUMI_BACKEND_SECRETS_PROVIDER` | `local` | `local` (AES-256-GCM with master key) or `gcpkms` |
| `-kms-key` | `PULUMI_BACKEND_KMS_KEY` | | GCP KMS key resource name (required for `gcpkms`) |

#### Authentication

Three auth modes: `single-tenant` (default), `google`, and `jwt`.

| Flag | Env | Default | Description |
|---|---|---|---|
| `-auth-mode` | `PULUMI_BACKEND_AUTH_MODE` | `single-tenant` | `single-tenant`, `google`, or `jwt` |
| `-rbac-config` | `PULUMI_BACKEND_RBAC_CONFIG` | | Path to RBAC config YAML (disabled if not set) |

- **[Google OIDC setup guide](docs/auth-google.md)** — OAuth2, Workspace groups, keyless DWD, GKE Workload Identity
- **[JWT setup guide](docs/auth-jwt.md)** — HMAC/RSA/ECDSA, Dex, Keycloak integration
- **[RBAC configuration](docs/rbac.md)** — Group roles, stack policies, permission levels

## API compatibility

Implements the subset of the Pulumi Cloud API that the CLI actually uses:

- Stack CRUD, tags, rename
- State export/import (full and versioned)
- Update lifecycle (create, start, checkpoint, complete, cancel)
- Delta checkpoint uploads (v2) with server-side patching
- Journal entries with server-side replay
- Batch encrypt/decrypt
- Update history with pagination
- User/org endpoints
- Authentication (single-tenant, Google OIDC, JWT)
- Browser login page (`GET /login`) and automatic CLI login (`GET /cli-login`) with Google OAuth2
- RBAC (group-based, with stack-level policy overrides)
- Admin token management (`GET/DELETE /api/admin/tokens/{userName}`)
- Google refresh token re-validation (detects deactivated users mid-session)
- Prometheus metrics (`/metrics`)
- OpenAPI 3.1 spec (`GET /api/openapi`)
- Database backup (`POST /api/admin/backup`)

## Tests

```bash
go test ./internal/...                                    # unit tests
go test -timeout 120s ./tests/ -count=1                   # API + auth tests (CLI tests auto-skip if pulumi not in PATH)
go test -v ./tests/ -run TestAPISpecSchemaCompliance       # OpenAPI spec compliance
go test -bench . -benchmem ./internal/engine               # engine benchmarks
go test -timeout 600s ./tests/ -count=1                    # full suite (with pulumi in PATH)
```

GCP-dependent tests (`TestGoogleAuthE2E`, `TestGroupsResolutionADC`) require Google credentials and auto-skip when env vars are not set.

## TODO

- [ ] Web UI
- [ ] Horizontal scaling beyond single SQLite node
