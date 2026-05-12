# pulumi-backend

<!-- cli-compat:start -->
## CLI Compatibility
Tested smoke suite `^TestCLICompat_` against Pulumi CLI releases. Current stable at check time: `3.228.0`.

[![Pulumi CLI full-suite 3.228.0](https://img.shields.io/badge/Pulumi_CLI_full--suite_3.228.0-verified-blue)](https://github.com/pulumi/pulumi/releases/tag/v3.228.0)

[![Pulumi CLI 3.210.0](https://img.shields.io/badge/Pulumi_CLI_3.210.0-compatible-brightgreen)](https://github.com/pulumi/pulumi/releases/tag/v3.210.0)
[![Pulumi CLI 3.220.0](https://img.shields.io/badge/Pulumi_CLI_3.220.0-compatible-brightgreen)](https://github.com/pulumi/pulumi/releases/tag/v3.220.0)
[![Pulumi CLI 3.225.1](https://img.shields.io/badge/Pulumi_CLI_3.225.1-compatible-brightgreen)](https://github.com/pulumi/pulumi/releases/tag/v3.225.1)
[![Pulumi CLI 3.228.0](https://img.shields.io/badge/Pulumi_CLI_3.228.0-compatible-brightgreen)](https://github.com/pulumi/pulumi/releases/tag/v3.228.0)

| Version | Status |
|---|---|
| `full suite` | `3.228.0` |
| `3.210.0` | `compatible` |
| `3.220.0` | `compatible` |
| `3.225.1` | `compatible` |
| `3.228.0` | `compatible` |

Source: https://www.pulumi.com/docs/get-started/download-install/versions/ (checked 2026-03-26).
<!-- cli-compat:end -->

A self-hosted Pulumi state backend implementing the Pulumi Cloud HTTP API. Single binary, SQLite storage, journaling checkpoint protocol. Deploys anywhere — laptop, VM, Cloud Run, Kubernetes.

## Performance

pulumi-backend uses the Pulumi Cloud HTTP protocol instead of the DIY blob protocol. The CLI sends incremental journal entries instead of rewriting the entire state file on every resource change. The result:

### `pulumi up` — 200 resources (create from scratch)

```
pulumi-backend   ░ 4.2s
GCS              ▓▓▓▓▓ 317s (75x slower)
CloudSQL PG 17   ▓▓▓▓▓▓▓ 449s (107x slower)
```

### `pulumi destroy` — 200 resources

```
pulumi-backend   ░ 3.8s
GCS              ▓▓▓▓▓ 326s (86x slower)
CloudSQL PG 17   ▓▓▓▓▓▓▓▓ 551s (145x slower)
```

### `pulumi up` — 600 resources (create from scratch)

```
pulumi-backend   ░ 8.3s
GCS              ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ 1274s (153x slower)
CloudSQL PG 17   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ 2614s (315x slower)
```

### `pulumi destroy` — 600 resources

```
pulumi-backend   ░ 7.2s
GCS              ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ 1370s (190x slower)
CloudSQL PG 17   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ 2444s (340x slower)
```

> All benchmarks: pulumi-backend on Cloud Run (4 vCPU, 8 GB), CloudSQL PostgreSQL 17 (4 vCPU, 8 GB), GCS bucket — same GCP region (europe-west4), client over internet. Averaged over 3 runs. Full results in [docs/benchmark-results.md](docs/benchmark-results.md).

### Why so fast?

DIY backends (S3, GCS, Azure Blob, CloudSQL via `pgstate`) use Pulumi's `diy` code path: every resource change rewrites the **entire** state file. With 600 resources, that's 600 full uploads of growing JSON — O(n²) data transfer.

This backend speaks the Pulumi Cloud HTTP protocol. The CLI uses the `httpstate` code path with `delta-checkpoint-uploads-v2`: after the initial checkpoint, only changed bytes are sent as journal entries — O(n) data transfer.

## Features vs DIY blob backends

| | DIY (S3/GCS/Azure Blob) | pulumi-backend |
|---|---|---|
| **Checkpoint protocol** | Full state rewrite per resource change | Journal entries — incremental deltas only |
| **Concurrency** | Advisory file locks (no TTL, missing on some backends) | Server-side leases with TTL, renewal, and cancel |
| **Secrets** | Client-side (`PULUMI_CONFIG_PASSPHRASE` or KMS) | Server-side AES-256-GCM, optional GCP KMS wrapping |
| **Auth & RBAC** | None | Single-tenant, Google OIDC, generic OIDC, JWT + group-based RBAC |
| **Audit logging** | None | Structured JSON audit trail (actor, action, resource, IP) |
| **State compression** | None | Gzip-compressed storage |
| **Observability** | None | Prometheus metrics, OpenTelemetry tracing, health probes |
| **Backup** | Manual bucket copies | Online SQLite backup to S3/GCS with scheduling and retention |
| **Listing/querying** | Walk bucket listing files | SQL queries with pagination |
| **State history** | Overwritten on each update | Versioned with configurable retention |

## Usage

```bash
go build -o pulumi-backend ./cmd/pulumi-backend
./pulumi-backend --single-tenant-token=YOUR_SECRET_TOKEN
```

Then point the CLI at it:

```bash
PULUMI_ACCESS_TOKEN=YOUR_SECRET_TOKEN pulumi login http://localhost:8080
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
| `-tls` | `PULUMI_BACKEND_TLS` | `false` | Enable TLS (manual cert/key) |
| `-cert` | `PULUMI_BACKEND_CERT` | | TLS certificate file |
| `-key` | `PULUMI_BACKEND_KEY` | | TLS key file |
| `-acme-domain` | `PULUMI_BACKEND_ACME_DOMAIN` | | Domain for automatic TLS via ACME/Let's Encrypt |
| `-acme-email` | `PULUMI_BACKEND_ACME_EMAIL` | | Contact email for ACME account |
| `-acme-ca` | `PULUMI_BACKEND_ACME_CA` | Let's Encrypt | ACME directory URL (for custom CAs) |
| `-single-tenant-token` | `PULUMI_BACKEND_SINGLE_TENANT_TOKEN` | | **Required.** Shared access token for single-tenant mode |
| `-public-url` | `PULUMI_BACKEND_PUBLIC_URL` | | Public base URL for redirect URIs (e.g. `https://pulumi.example.com`) |

If no master key is provided, one is auto-generated and printed to stderr. **You must persist it** (e.g. `export PULUMI_BACKEND_MASTER_KEY=...`) — secrets will be undecryptable on restart with a different key.

On startup, the backend verifies the master key by decrypting a canary value stored in the database. If the key is wrong, the server refuses to start with a clear error message instead of silently corrupting secrets.

#### Automatic TLS (ACME / Let's Encrypt)

Set `-acme-domain` to enable automatic certificate provisioning via Let's Encrypt (or any ACME CA). Certificates are stored in SQLite alongside all other data — no separate cert directory needed. Renewal is automatic (30 days before expiry).

```bash
./pulumi-backend \
  --acme-domain=pulumi.example.com \
  --acme-email=ops@example.com \
  --addr=:443 \
  --single-tenant-token=YOUR_TOKEN \
  --management-addr=:9090
```

Requirements: ports 80 (HTTP-01 challenge) and 443 must be reachable. The domain must resolve to the server's IP. Mutually exclusive with `-tls`/`-cert`/`-key`.

#### Logging

| Flag | Env | Default | Description |
|---|---|---|---|
| `-log-format` | `PULUMI_BACKEND_LOG_FORMAT` | `json` | Log format: `json` or `text` |
| `-audit-logs` | `PULUMI_BACKEND_AUDIT_LOGS` | `true` | Enable structured audit logging |
| `-access-logs` | `PULUMI_BACKEND_ACCESS_LOGS` | `true` | Enable per-request access logging |
| `-audit-log-path` | `PULUMI_BACKEND_AUDIT_LOG_PATH` | | Audit log destination: `stdout`, `stderr`, or file path (empty = same as operational logs) |

Three log categories with independent routing via `log_type` JSON field:

| Category | `log_type` field | Description |
|---|---|---|
| Operational | (absent) | Server lifecycle, errors, warnings |
| Access | `"access"` | Per-HTTP-request logs (method, path, status, latency) |
| Audit | `"audit"` | Security-relevant events (actor, action, resource, IP) |

In Kubernetes, all three go to stdout as structured JSON. Use Fluent Bit/Vector/Promtail to route based on the `log_type` field — e.g., audit entries to a compliance index, access logs to a separate index, operational to a general one.

#### Observability

| Flag | Env | Default | Description |
|---|---|---|---|
| `-pprof` | `PULUMI_BACKEND_PPROF` | `false` | Enable pprof profiling endpoints (requires `-management-addr`) |
| `-management-addr` | `PULUMI_BACKEND_MANAGEMENT_ADDR` | (disabled) | Separate listen address for `/healthz`, `/readyz`, `/metrics`, `/debug/pprof/` (e.g., `:9090`). **Required** when binding to non-loopback addresses. |
| `-otel-service-name` | `PULUMI_BACKEND_OTEL_SERVICE_NAME` | (disabled) | OpenTelemetry service name (enables OTLP tracing) |

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
| `-backup-dir` | `PULUMI_BACKEND_BACKUP_DIR` | (disabled) | Directory for local SQLite backups |
| `-backup-destination` | `PULUMI_BACKEND_BACKUP_DESTINATION` | (disabled) | Backup destination URI (see below) |
| `-backup-s3-region` | `PULUMI_BACKEND_BACKUP_S3_REGION` | `us-east-1` | AWS region (S3 only) |
| `-backup-s3-endpoint` | `PULUMI_BACKEND_BACKUP_S3_ENDPOINT` | | Custom S3 endpoint (MinIO, R2, B2) |
| `-backup-s3-force-path-style` | `PULUMI_BACKEND_BACKUP_S3_FORCE_PATH_STYLE` | `false` | Path-style S3 addressing (MinIO) |
| `-backup-schedule` | `PULUMI_BACKEND_BACKUP_SCHEDULE` | `0` | Periodic backup interval (`6h`, `24h`; 0 = disabled) |
| `-backup-retention` | `PULUMI_BACKEND_BACKUP_RETENTION` | `0` | Backups to keep per destination (0 = unlimited) |

The `-backup-destination` flag takes a URI that determines the storage backend:

| URI scheme | Backend | Credentials |
|---|---|---|
| `s3://bucket/prefix` | S3-compatible (AWS, MinIO, R2, B2) | AWS SDK chain (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, IAM role, instance metadata) |
| `gs://bucket/prefix` | Google Cloud Storage | Application Default Credentials (workload identity, SA key, `gcloud auth`, metadata server) |

If only a bucket is specified (e.g., `s3://my-bucket`), the prefix defaults to `backups/`.

Backups use SQLite's online backup API which creates a consistent point-in-time page-copy snapshot — concurrent writes are not blocked. Both local directory and remote destinations can be active simultaneously.

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
| `-single-tenant-token` | `PULUMI_BACKEND_SINGLE_TENANT_TOKEN` | | **Required** for single-tenant mode. Shared access token. |
| `-rbac-config` | `PULUMI_BACKEND_RBAC_CONFIG` | | **Required** for google/oidc/jwt modes. Path to RBAC config YAML. |
| `-trusted-proxies` | `PULUMI_BACKEND_TRUSTED_PROXIES` | (trust none) | Comma-separated CIDRs for trusted reverse proxies |

`single-tenant` requires a configured token (`-single-tenant-token`). Requests must send `Authorization: token <configured-token>`. Token comparison uses constant-time comparison to prevent timing attacks.

For `google`, `oidc`, and `jwt` modes, `-rbac-config` is required so multi-user deployments fail closed instead of granting blanket admin access.

`update-token` is different from a normal user token. It is always treated as an update-scoped capability token for a specific in-progress update, and is only accepted on update endpoints that include the matching `{updateID}`. It does not grant general API access, even in `single-tenant` mode.

- **[Google OIDC setup guide](docs/auth-google.md)** — OAuth2, Workspace groups, keyless DWD, GKE Workload Identity
- **[Generic OIDC setup guide](docs/auth-oidc.md)** — Okta, Entra ID, Keycloak, any OIDC provider
- **[JWT setup guide](docs/auth-jwt.md)** — HMAC/RSA/ECDSA, Dex, Keycloak integration
- **[RBAC configuration](docs/rbac.md)** — Group roles, stack policies, permission levels
- **[Performance testing](docs/performance.md)** — Benchmarks, pprof profiling, optimization guide

## Security

- **Token auth enforced**: Single-tenant mode requires a configured token (no open access). Constant-time comparison prevents timing attacks.
- **Refresh token encryption**: OIDC refresh tokens are encrypted at rest using the master key (AES-256-GCM) or GCP KMS.
- **Secrets at rest**: Per-stack data encryption keys (DEKs) wrapped by master key. Stack secret values encrypted client-side by the CLI.
- **Master key canary**: Wrong key = immediate startup failure, not silent corruption.
- **Trusted proxies**: `X-Forwarded-For`/`X-Real-Ip` headers only accepted from explicitly configured CIDRs (default: trust none).
- **Management port separation**: Health probes, metrics, and pprof are served on a separate port, not exposed on the public API.
- **HTTP server hardening**: Read/write/idle timeouts configured on all listeners to prevent slowloris and resource exhaustion.
- **Error sanitization**: Internal errors (SQL, file paths, UUIDs) are scrubbed before reaching clients.
- **ACME cert storage**: TLS certificates stored in SQLite (included in backups), not on the filesystem.

## API compatibility

Implements the Pulumi Cloud HTTP API subset that the CLI uses.

Compatibility is checked in three layers:

- Cross-version CLI smoke suite (`^TestCLICompat_`) against a verified Pulumi CLI matrix:
  - `3.210.0`
  - `3.220.0`
  - `3.225.1`
  - `3.228.0`
- Vendored Pulumi HTTP client contract snapshot from `reference/pulumi/pkg/backend/httpstate/client/api_endpoints.go`
- Optional comparison against the official Pulumi Cloud OpenAPI spec via `pulumi-spec.json`

- Stack CRUD, tags, rename
- State export/import (full and versioned)
- Update lifecycle (create, start, checkpoint, complete, cancel)
- Delta checkpoint uploads (v2) with server-side patching
- Journal entries with server-side replay
- Batch encrypt/decrypt
- Update history with pagination
- User/org endpoints
- User token self-service (`GET/POST/DELETE /api/user/tokens`)
- Read-only teams and roles (`GET /api/orgs/{orgName}/teams`, `GET /api/orgs/{orgName}/roles`)
- OpenAPI 3.1 spec (`GET /api/openapi`)

### pulumi-backend extensions

Endpoints and features specific to this backend (not part of Pulumi Cloud API):

- Authentication: single-tenant token, Google OIDC, generic OIDC, JWT
- Browser login (`GET /login`) and automatic CLI login (`GET /cli-login`)
- RBAC with Google Workspace groups (Groups Reader admin role or DWD)
- OIDC refresh token re-validation (detects deactivated users mid-session)
- Admin token management (`GET/DELETE /api/admin/tokens/{userName}`)
- CLI compatibility matrix tooling and generated README badges
- Groups cache invalidation (`POST /api/admin/groups-cache/invalidate`)
- Database backup (`POST /api/admin/backup`) with S3/GCS remote upload, scheduling, and retention
- Secrets key migration (`--migrate-secrets-key` for key rotation and local↔KMS migration)
- Structured audit logging (actor, action, resource, IP)
- Health probes (`GET /healthz`, `GET /readyz`) with optional management port
- Prometheus metrics (`/metrics`)
- OpenTelemetry tracing (HTTP, engine, SQL spans)
- Automatic TLS via ACME/Let's Encrypt

## Audit logging

All state-mutating API operations are logged as structured JSON with actor identity, action, resource, HTTP status, and client IP:

```json
{"time":"...","level":"INFO","msg":"Audit Log: API Request","log_type":"audit","audit":{"actor":"user@example.com","action":"deleteStack","method":"DELETE","resource":"myorg/myproject/dev","http_status":200,"ip_address":"10.0.0.1"}}
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
go test -v ./tests/ -run '^TestCLICompat_'                 # CLI smoke/compat suite
go test -v ./tests/ -run TestPulumiHTTPContractSnapshotUpToDate
                                                       # vendored Pulumi HTTP client contract snapshot freshness
go test -v ./tests/ -run TestAPISpecSchemaCompliance       # OpenAPI spec compliance
go test -v ./tests/ -run TestDeclaredErrorCodes            # error code coverage + exercised
go test -v ./tests/ -run TestReliability                   # state consistency / reliability tests
go test -bench . -benchmem -timeout 120s ./tests/          # benchmarks (engine + HTTP)
```

### CLI compatibility matrix

The smoke suite in `tests/cli_compat_test.go` is designed to run against arbitrary Pulumi CLI binaries.

```bash
PULUMI_CLI_PATH=/path/to/pulumi go test ./tests -run '^TestCLICompat_' -count=1
```

To refresh the checked-in CLI compatibility matrix and README badges:

```bash
go run ./cmd/run-cli-compat-matrix
```

To refresh the vendored Pulumi HTTP contract snapshot from `reference/pulumi`:

```bash
go run ./cmd/dump-pulumi-http-contract
```

The generated files are:

- `tests/testdata/cli_compat_matrix.json`
- `tests/testdata/pulumi_http_contract.json`
- the badge section at the top of this README

### CI

CI runs:

- `go build ./...`
- `golangci-lint`
- unit tests (`./internal/...`)
- spec/contract tests
- full integration tests with Pulumi CLI `3.228.0`
- CLI compatibility smoke tests across the verified matrix
- generated compatibility metadata checks (README badges, CLI matrix JSON, vendored contract snapshot)

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
