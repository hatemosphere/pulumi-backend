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

| Flag | Env | Default | Description |
|---|---|---|---|
| `-auth-mode` | `PULUMI_BACKEND_AUTH_MODE` | `single-tenant` | `single-tenant`, `google`, or `jwt` |

**Google OIDC mode** (`-auth-mode=google`):

| Flag | Env | Description |
|---|---|---|
| `-google-client-id` | `PULUMI_BACKEND_GOOGLE_CLIENT_ID` | OAuth2 client ID (required) |
| `-google-sa-key` | `PULUMI_BACKEND_GOOGLE_SA_KEY` | Service account JSON key for Admin SDK groups |
| `-google-admin-email` | `PULUMI_BACKEND_GOOGLE_ADMIN_EMAIL` | Workspace super-admin email for groups impersonation |
| `-google-allowed-domains` | `PULUMI_BACKEND_GOOGLE_ALLOWED_DOMAINS` | Comma-separated allowed hosted domains |
| `-google-transitive-groups` | `PULUMI_BACKEND_GOOGLE_TRANSITIVE_GROUPS` | Resolve nested group memberships |
| `-token-ttl` | `PULUMI_BACKEND_TOKEN_TTL` | Backend-issued token lifetime (default `24h`) |
| `-groups-cache-ttl` | `PULUMI_BACKEND_GROUPS_CACHE_TTL` | Group membership cache TTL (default `5m`) |

**JWT mode** (`-auth-mode=jwt`):

| Flag | Env | Description |
|---|---|---|
| `-jwt-signing-key` | `PULUMI_BACKEND_JWT_SIGNING_KEY` | HMAC secret or path to PEM public key (required) |
| `-jwt-issuer` | `PULUMI_BACKEND_JWT_ISSUER` | Expected `iss` claim (optional) |
| `-jwt-audience` | `PULUMI_BACKEND_JWT_AUDIENCE` | Expected `aud` claim (optional) |
| `-jwt-groups-claim` | `PULUMI_BACKEND_JWT_GROUPS_CLAIM` | Claim name for groups (default `groups`) |
| `-jwt-username-claim` | `PULUMI_BACKEND_JWT_USERNAME_CLAIM` | Claim for username (default `sub`) |

#### RBAC

| Flag | Env | Description |
|---|---|---|
| `-rbac-config` | `PULUMI_BACKEND_RBAC_CONFIG` | Path to RBAC config YAML (disabled if not set) |

Example `rbac.yaml`:

```yaml
defaultPermission: read
groupRoles:
  - group: "engineers@example.com"
    permission: write
  - group: "ops@example.com"
    permission: admin
stackPolicies:
  - group: "engineers@example.com"
    stackPattern: "myorg/staging/*"
    permission: admin
```

Permission levels: `none < read < write < admin`. Single-tenant mode bypasses RBAC entirely.

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
- RBAC (group-based, with stack-level policy overrides)
- Prometheus metrics (`/metrics`)
- OpenAPI 3.1 spec (`GET /api/openapi`)
- Database backup (`POST /api/admin/backup`)

## Tests

```bash
go test ./internal/...                                   # unit tests
go test ./tests/ -skip '^TestCLI'                        # HTTP API + auth integration tests (no pulumi needed)
go test ./tests/ -run TestCLI                             # CLI integration tests (requires pulumi in PATH)
go test -v ./tests/ -run TestAPISpecSchemaCompliance      # OpenAPI spec compliance
go test -timeout 600s ./tests/ -count=1                   # full suite
```

## TODO

- [ ] Dockerfile
- [ ] Web UI
- [ ] Horizontal scaling beyond single SQLite node
