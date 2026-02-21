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

All flags have corresponding environment variables with the `PULUMI_BACKEND_` prefix (auto-mapped: hyphens become underscores, uppercased). Powered by [ff](https://github.com/peterbourgon/ff). Precedence: flag > env var > default.

#### Core

| Flag | Env | Default | Description |
|---|---|---|---|
| `-addr` | `PULUMI_BACKEND_ADDR` | `:8080` | Listen address |
| `-db` | `PULUMI_BACKEND_DB` | `pulumi-backend.db` | SQLite database path |
| `-master-key` | `PULUMI_BACKEND_MASTER_KEY` | (auto-generated) | Hex-encoded 32-byte key for secrets encryption |
| `-org` | `PULUMI_BACKEND_ORG` | `organization` | Default organization name |
| `-user` | `PULUMI_BACKEND_USER` | `admin` | Default user name |
| `-tls` | `PULUMI_BACKEND_TLS` | `false` | Enable TLS |
| `-cert` | `PULUMI_BACKEND_CERT` | | TLS certificate file |
| `-key` | `PULUMI_BACKEND_KEY` | | TLS key file |
| `-log-format` | `PULUMI_BACKEND_LOG_FORMAT` | `json` | Log format: `json` or `text` |
| `-audit-logs` | `PULUMI_BACKEND_AUDIT_LOGS` | `true` | Enable structured audit logging |

If no master key is provided, one is auto-generated and printed to stderr. **You must persist it** (e.g. `export PULUMI_BACKEND_MASTER_KEY=...`) — secrets will be undecryptable on restart with a different key.

On startup, the backend verifies the master key by decrypting a canary value stored in the database. If the key is wrong, the server refuses to start with a clear error message instead of silently corrupting secrets.

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

#### Backup

| Flag | Env | Default | Description |
|---|---|---|---|
| `-backup-dir` | `PULUMI_BACKEND_BACKUP_DIR` | (disabled) | Directory for local SQLite VACUUM INTO backups |
| `-backup-s3-bucket` | `PULUMI_BACKEND_BACKUP_S3_BUCKET` | (disabled) | S3 bucket for remote backups |
| `-backup-s3-region` | `PULUMI_BACKEND_BACKUP_S3_REGION` | `us-east-1` | AWS region |
| `-backup-s3-endpoint` | `PULUMI_BACKEND_BACKUP_S3_ENDPOINT` | | Custom S3 endpoint (MinIO, R2, B2) |
| `-backup-s3-prefix` | `PULUMI_BACKEND_BACKUP_S3_PREFIX` | `backups/` | Key prefix in S3 bucket |
| `-backup-s3-force-path-style` | `PULUMI_BACKEND_BACKUP_S3_FORCE_PATH_STYLE` | `false` | Path-style S3 addressing (MinIO) |
| `-backup-schedule` | `PULUMI_BACKEND_BACKUP_SCHEDULE` | `0` | Periodic backup interval (`6h`, `24h`; 0 = disabled) |
| `-backup-retention` | `PULUMI_BACKEND_BACKUP_RETENTION` | `0` | Backups to keep per destination (0 = unlimited) |

Backups use SQLite's `VACUUM INTO` which creates a consistent point-in-time snapshot under a shared read lock — concurrent writes are not blocked. Both local directory and S3 destinations can be active simultaneously. AWS credentials are resolved via the standard SDK chain (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, IAM role, instance metadata).

Trigger a manual backup: `POST /api/admin/backup`. With scheduled backups enabled, the backend also runs periodic backups automatically.

#### Secrets provider

| Flag | Env | Default | Description |
|---|---|---|---|
| `-secrets-provider` | `PULUMI_BACKEND_SECRETS_PROVIDER` | `local` | `local` (AES-256-GCM with master key) or `gcpkms` |
| `-kms-key` | `PULUMI_BACKEND_KMS_KEY` | | GCP KMS key resource name (required for `gcpkms`) |

#### Secrets key migration

Re-wrap all per-stack encryption keys from an old provider to a new one. The backend performs the migration and exits.

```bash
# Rotate local master key
./pulumi-backend --db pulumi-backend.db \
  --migrate-secrets-key \
  --master-key NEW_HEX_KEY \
  --old-secrets-provider local \
  --old-master-key OLD_HEX_KEY

# Migrate from local to GCP KMS
./pulumi-backend --db pulumi-backend.db \
  --migrate-secrets-key \
  --secrets-provider gcpkms \
  --kms-key projects/P/locations/L/keyRings/R/cryptoKeys/K \
  --old-secrets-provider local \
  --old-master-key OLD_HEX_KEY

# Migrate from GCP KMS to local
./pulumi-backend --db pulumi-backend.db \
  --migrate-secrets-key \
  --secrets-provider local \
  --master-key NEW_HEX_KEY \
  --old-secrets-provider gcpkms \
  --old-kms-key projects/P/locations/L/keyRings/R/cryptoKeys/K
```

| Flag | Env | Description |
|---|---|---|
| `--migrate-secrets-key` | `PULUMI_BACKEND_MIGRATE_SECRETS_KEY` | Run migration and exit |
| `--old-secrets-provider` | `PULUMI_BACKEND_OLD_SECRETS_PROVIDER` | Previous provider: `local` or `gcpkms` |
| `--old-master-key` | `PULUMI_BACKEND_OLD_MASTER_KEY` | Previous hex-encoded master key |
| `--old-kms-key` | `PULUMI_BACKEND_OLD_KMS_KEY` | Previous GCP KMS key resource name |

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
- Database backup (`POST /api/admin/backup`) with S3-compatible remote upload, scheduled backups, and retention management
- Secrets key migration (`--migrate-secrets-key` for local key rotation and local↔KMS migration)

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
- Backup consistency (backup during active update, backup during concurrent checkpoints, no-destination error)
- Stack lifecycle (recreation after deletion, operations during active updates, secrets after rename)
- Secrets consistency (encrypt/decrypt roundtrip, batch operations, key preservation across rename, key migration)
- Master key verification (canary persistence across restart, mismatch detection)
- History consistency (all updates recorded, version/export alignment)
- Error response format and information leakage (no UUIDs, SQL internals, Go paths in messages)
- Declared error code coverage (meta-test verifies every `Errors: []int{...}` has a test scenario)

GCP-dependent tests (`TestGoogleAuthE2E`, `TestGroupsResolutionADC`) require Google credentials and auto-skip when env vars are not set.

## TODO

- [ ] Web UI
- [ ] Horizontal scaling beyond single SQLite node
