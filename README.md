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
| **Auth** | None | Single-tenant, Google OIDC, generic OIDC, or JWT with RBAC |

## Usage

```bash
go build -o pulumi-backend ./cmd/pulumi-backend
./pulumi-backend
```

Then point the CLI at it:

```bash
pulumi login http://localhost:8080
```

With OIDC auth (Google, Okta, Entra ID, Keycloak, etc.), set `PULUMI_CONSOLE_DOMAIN` for automatic browser-based login (no token copy-paste):

```bash
export PULUMI_CONSOLE_DOMAIN=localhost:8080
pulumi login http://localhost:8080  # opens browser for OIDC sign-in
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

Four auth modes: `single-tenant` (default), `google`, `oidc`, and `jwt`.

| Flag | Env | Default | Description |
|---|---|---|---|
| `-auth-mode` | `PULUMI_BACKEND_AUTH_MODE` | `single-tenant` | `single-tenant`, `google`, `oidc`, or `jwt` |
| `-rbac-config` | `PULUMI_BACKEND_RBAC_CONFIG` | | Path to RBAC config YAML (disabled if not set) |

- **[Google OIDC setup guide](docs/auth-google.md)** — OAuth2, Workspace groups, keyless DWD, GKE Workload Identity
- **[Generic OIDC setup guide](docs/auth-oidc.md)** — Okta, Entra ID, Keycloak, any OIDC provider
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
- Authentication (single-tenant, Google OIDC, generic OIDC, JWT)
- Browser login page (`GET /login`) and automatic CLI login (`GET /cli-login`) with any OIDC provider
- RBAC (group-based, with stack-level policy overrides)
- User token self-service (`GET/POST/DELETE /api/user/tokens`)
- Admin token management (`GET/DELETE /api/admin/tokens/{userName}`)
- Read-only teams and roles (`GET /api/orgs/{orgName}/teams`, `GET /api/orgs/{orgName}/roles`)
- OIDC refresh token re-validation (detects deactivated users mid-session)
- Structured audit logging (actor, action, resource, IP for all mutating operations)
- Prometheus metrics (`/metrics`)
- OpenAPI 3.1 spec (`GET /api/openapi`)
- Database backup (`POST /api/admin/backup`)

## Audit logging

All state-mutating API operations are logged as structured JSON to stdout with actor identity, action, resource, HTTP status, and client IP:

```json
{"time":"...","level":"INFO","msg":"Audit Log: API Request","audit":{"actor":"user@example.com","action":"deleteStack","method":"DELETE","resource":"myorg/myproject/dev","http_status":200,"ip_address":"10.0.0.1"}}
```

| Event | Level | Trigger |
|---|---|---|
| `Audit Log: API Request` | INFO/WARN | Every mutating auth-protected request (stack CRUD, updates, secrets, admin) |
| `Audit Log: Login Success` | INFO | Browser/CLI OIDC login |
| `Audit Log: Login Failed` | WARN | Failed OIDC login attempt |
| `Audit Log: Access Denied` | WARN | RBAC permission denied |
| `Audit Log: Token Exchange` | INFO | Successful OIDC token exchange |
| `Audit Log: Token Exchange Failed` | WARN | Failed OIDC token exchange |
| `Audit Log: Token Revocation` | INFO | Admin revokes user tokens |

High-frequency machine-generated operations (checkpoints, journal entries, events, lease renewals) are excluded to avoid log flooding during `pulumi up`.

## Tests

```bash
go test ./internal/...                                    # unit tests
go test -timeout 120s ./tests/ -count=1                   # API + auth + reliability tests (CLI tests auto-skip if pulumi not in PATH)
go test -v ./tests/ -run TestAPISpecSchemaCompliance       # OpenAPI spec compliance
go test -v ./tests/ -run TestCLIErrorSemantics             # CLI error message compatibility
go test -v ./tests/ -run TestDeclaredErrorCodes            # error code coverage + exercised
go test -v ./tests/ -run TestReliability                   # state consistency / reliability tests
go test -bench . -benchmem ./internal/engine               # engine benchmarks
go test -timeout 600s ./tests/ -count=1                    # full suite (with pulumi in PATH)
```

### Reliability tests

The `tests/reliability_test.go` suite covers state consistency edge cases:

- Partial apply / failed update recovery
- State version integrity and pruning
- Delta checkpoint correctness (patching, hash mismatch, empty state)
- Journal replay (create, update, delete, pending operations, multi-resource)
- Verbatim checkpoint mode and mixed checkpoint mode transitions (Full → Verbatim → Delta → Full)
- Locking & lease edge cases (double start, checkpoint/complete after cancel)
- Concurrent operations (parallel checkpoints, concurrent read/write, concurrent imports)
- Stack lifecycle (recreation after deletion, operations during active updates, secrets after rename)
- Secrets consistency (encrypt/decrypt roundtrip, batch operations, key preservation across rename)
- History consistency (all updates recorded, version/export alignment)
- Error response format and information leakage (no UUIDs, SQL internals, Go paths in messages)
- Declared error code coverage (meta-test verifies every `Errors: []int{...}` has a test scenario)

GCP-dependent tests (`TestGoogleAuthE2E`, `TestGroupsResolutionADC`) require Google credentials and auto-skip when env vars are not set.

## TODO

- [ ] Web UI
- [ ] Horizontal scaling beyond single SQLite node
