# Pulumi Self-Hosted Backend

Self-hosted Pulumi state backend implementing the Pulumi Cloud HTTP API contract.
SQLite-backed, multi-auth, no external Pulumi SDK dependency.

## Architecture

```
CLI -> api.Server (huma v2 + stdlib http.ServeMux) -> engine.Manager -> storage.SQLiteStore (WAL)
```

- **api/** — huma v2 typed handlers, auto-generated OpenAPI spec, auth + RBAC middleware
- **auth/** — Authentication (single-tenant, Google OIDC, generic OIDC, JWT), RBAC resolver, groups cache
- **engine/** — Business logic: stack locks, LRU cache, delta/journal replay, AES-256-GCM secrets
- **backup/** — Remote backup providers (S3, GCS), URI-based destination resolver, scheduler, retention pruning
- **storage/** — `Store` interface + SQLite impl. Deployments stored gzip-compressed.
- **gziputil/** — Shared gzip compress/decompress with `sync.Pool` and decompression bomb protection
- **audit/** — Structured audit logging (`audit.Event` struct, `slog.Group("audit", ...)` format)
- **config/** — Flag + env var parsing via [ff/v3](https://github.com/peterbourgon/ff) (`PULUMI_BACKEND_*` prefix, auto-mapped from flag names)

## Key files

| Path | Purpose |
|---|---|
| `cmd/pulumi-backend/main.go` | Entry point, wiring, OTel TracerProvider setup |
| `internal/api/router.go` | Server, huma config, all middleware (auth, RBAC, metrics, logging, audit) |
| `internal/api/types.go` | All huma request/response structs |
| `internal/api/errors.go` | Custom PulumiError overriding huma defaults + shared handler helpers (`internalError`, `conflictOrInternalError`, `requireIdentity`, `copyBody`, `ptrString`) |
| `internal/api/tokens.go` | User token self-service (GET/POST/DELETE /api/user/tokens) |
| `internal/api/org.go` | Read-only teams/roles from RBAC config |
| `internal/api/openapi.go` | OpenAPI spec builder (huma -> kin-openapi) |
| `internal/audit/audit.go` | Shared structured audit logging (`audit.Event` struct with typed fields) |
| `internal/auth/jwt.go` | JWT authenticator (HMAC/RSA/ECDSA auto-detection) |
| `internal/auth/rbac.go` | RBAC resolver (group roles + stack policies) |
| `internal/auth/rbac_config.go` | RBAC YAML config + Permission types |
| `internal/auth/identity.go` | UserIdentity type + context helpers |
| `internal/auth/groups_cache.go` | TTL + singleflight cache for group lookups |
| `internal/auth/oidc.go` | Generic OIDC authenticator (OIDCAuthenticator interface), Google specialization, test mock constructors |
| `internal/api/login.go` | Browser + CLI login (GET /login, /login/callback, /cli-login), refresh token capture |
| `internal/gziputil/gziputil.go` | Shared gzip compress/decompress pools (used by engine + storage) |
| `internal/engine/manager.go` | Core logic |
| `internal/engine/journal.go` | Journal replay algorithm |
| `internal/engine/delta.go` | Byte-offset delta application |
| `internal/engine/aesgcm.go` | Shared AES-256-GCM seal/open helpers |
| `internal/engine/secrets_provider.go` | `SecretsProvider` interface + local/KMS implementations |
| `internal/backup/backup.go` | Provider interface, BackupInfo, Prune free function |
| `internal/backup/destination.go` | URI-based destination resolver (`s3://`, `gs://`) |
| `internal/backup/s3.go` | S3Provider (S3-compatible: AWS, MinIO, R2, B2) |
| `internal/backup/gcs.go` | GCSProvider (Google Cloud Storage, ADC credentials) |
| `internal/backup/scheduler.go` | Ticker-based periodic backup scheduler |
| `internal/storage/sqlite.go` | SQLite implementation (inline schema, includes `server_config` + `secrets_keys` tables) |
| `internal/storage/storage.go` | `Store` interface + data types |
| `tests/spec_test.go` | OpenAPI spec compliance vs upstream + CLI error semantics |
| `tests/reliability_test.go` | State consistency, error format, concurrency, checkpoint modes, journal replay, secrets, error code coverage |
| `tests/auth_integration_test.go` | Auth + RBAC integration tests |
| `tests/bench_test.go` | Comprehensive benchmarks (compression, export, lifecycle, secrets, journal, HTTP) |
| `benchmarks/bench.sh` | End-to-end CLI benchmarks across backends (pulumi-backend, S3, Postgres, GCS, Cloud Run) |
| `docs/benchmark-results.md` | Compiled benchmark results and analysis |

## Reference code

- `reference/pulumi/` — Upstream Pulumi source clone (for API shape reference)
- `reference/huma/` — huma v2 framework source (adapter patterns, middleware)
- `reference/dex/` — Dex OIDC connector reference (Google connector refresh token pattern)
- `reference/ff/` — ff library source (flags-first config parsing)
- `reference/s3-mock/` — grafana/s3-mock clone (in-process S3 mock for backup tests)

## Build & test

```bash
go build -o pulumi-backend ./cmd/pulumi-backend
go test ./internal/...                                    # unit tests
go test -timeout 120s ./tests/ -count=1                   # API + auth + reliability tests (CLI/GCP tests auto-skip)
go test -v -timeout 600s ./tests/ -count=1                # all tests including CLI (needs pulumi in PATH)
go test -v -run TestAPISpecSchemaCompliance ./tests/      # spec compliance
go test -v -run TestReliability ./tests/                  # state consistency / reliability tests
go test -bench . -benchmem -timeout 120s ./tests/         # benchmarks (engine + HTTP, not in CI)
golangci-lint run ./...                                   # lint
```

## Design notes

- **Framework**: huma v2 wrapping stdlib `http.ServeMux` via `humago.New()`. No chi or other router.
- **JSON**: `github.com/segmentio/encoding/json` (drop-in stdlib replacement, 2-7x faster marshal/unmarshal, near-zero allocs).
- **OpenAPI**: auto-generated from Go struct types, no hand-built spec
- **huma config**: `AllowAdditionalPropertiesByDefault=true`, `FieldsOptionalByDefault=true`
- **RawBody caution**: huma pools request body buffers. Any `RawBody []byte` stored beyond handler lifetime must be copied (`make + copy`).
- **Middleware architecture**: HTTP-level (realIP, recoverer, requestLogger, gzipDecompressor) + huma-level (metricsHumaMiddleware, authHumaMiddleware, rbacMiddleware, auditHumaMiddleware). Two huma API instances on the same mux: publicAPI (no auth) and api (auth + RBAC).
- **Audit logging**: Shared `internal/audit` package with typed `audit.Event` struct and injectable `audit.Logger` (defaults to `slog.Default()`). huma-level `auditHumaMiddleware` emits structured JSON audit entries for all state-mutating operations (POST/PATCH/PUT/DELETE) with actor, action (operationID), resource, http_status, ip_address. High-frequency ops excluded (checkpoints, events, lease renewals). Inline audit entries for login, token exchange, and RBAC denials. All entries use `slog.Group("audit", ...)` format. `--audit-log-path` flag routes audit output to a separate destination (stdout, stderr, or file path).
- **Access logging**: `api.AccessLog` package variable (defaults to `slog.Default()`). `requestLogger` middleware uses this instead of `slog.Info` directly. Fields: method, path, status, latency, remote_ip, user_agent. `--access-logs=false` disables per-request logging by routing to `io.Discard`.
- **Log routing**: All audit entries have `"log_type":"audit"`, access logs have `"log_type":"access"`, operational logs have no `log_type` field. Single field for Fluent Bit/Vector routing in Kubernetes.
- **Client IP in context**: `auth.WithClientIP(ctx, ip)` set in auth middleware; `auth.ClientIPFromContext(ctx)` used by inline audit entries (RBAC denials, token exchange, token revocation) to consistently include IP in all audit events.
- **Shared handler helpers**: `errors.go` contains `internalError`, `conflictOrInternalError`, `requireIdentity`, `copyBody`, `ptrString` — used across all handler files to eliminate boilerplate.
- SQLite: CGo-free via `github.com/ncruces/go-sqlite3` (Wasm-compiled SQLite3), WAL mode, `MaxOpenConns=1`. DSN requires `file:` prefix for pragma query params. Per-page checksums enabled on first run via `EnableChecksums("main")` (reserves 8 bytes/page, VACUUMs once). `rawConn()` helper bypasses otelsql wrapping for operations needing `driver.Conn.Raw()`.
- Auth: four modes — `single-tenant` (any token = admin), `google` (Google OIDC via go-oidc/v3 + backend tokens + groups + browser login), `oidc` (generic OIDC provider), `jwt` (stateless, claims-based)
- OIDC architecture: `OIDCAuthenticator` interface in `oidc.go`, Google mode is a specialization (`NewGoogleOIDCAuthenticator`). `TestOIDCValidator` + `TestOIDCRefresher` interfaces for test mock injection via `NewTestOIDCAuthenticator`.
- Browser login: `GET /login` (manual), `GET /cli-login` (automatic via `PULUMI_CONSOLE_DOMAIN`). Registered when `oidcAuth != nil`. Routes on raw mux, not huma (serves HTML).
- OIDC refresh token re-validation: browser/CLI login captures provider's refresh token, stored in `tokens` table. On each auth request past half TTL, async re-validation via `oauth2.TokenSource` detects deactivated users (Dex pattern).
- OIDC groups: stored in DB for generic OIDC providers (from token claims at login), resolved live via Google Admin SDK for Google mode.
- Admin endpoints: `requireAdmin()` helper checks `IsAdmin` (single-tenant) OR RBAC admin permission (Google/JWT). Token management: `GET/DELETE /api/admin/tokens/{userName}`.
- User token endpoints: `GET/POST/DELETE /api/user/tokens` — self-service token management via `registerUserTokens`, gated on `s.tokenStore != nil`
- Teams/roles endpoints: `GET /api/orgs/{orgName}/teams`, `GET /api/orgs/{orgName}/teams/{teamName}`, `GET /api/orgs/{orgName}/roles` — read-only mapping of RBAC YAML config to upstream-shaped responses via `registerOrg`
- RBAC: group-based with stack-level policy overrides. Permission levels: `none < read < write < admin`. Admin RBAC role grants access to admin endpoints too.
- **Config parsing**: `ff/v3` wraps stdlib `flag.FlagSet` with automatic env var binding via `WithEnvVarPrefix("PULUMI_BACKEND")`. Flag `foo-bar` → env `PULUMI_BACKEND_FOO_BAR`. All flags get env overrides automatically; no manual `os.Getenv` code. Post-parse logic (master key auto-gen) runs after `ff.Parse`.
- **Secrets**: per-stack AES-256-GCM DEKs wrapped by KEK (master key for local provider, or GCP KMS). `SecretsProvider` interface: `WrapKey`, `UnwrapKey`, `ProviderName`. Canary verification on startup: encrypt known plaintext, store ciphertext in `server_config` table; on restart, decrypt to verify — wrong key/KMS = fatal error.
- **Secrets key migration**: `--migrate-secrets-key` flag re-wraps all per-stack DEKs from old provider to new provider, then exits. Supports local↔KMS and key rotation within same provider. Uses `--old-secrets-provider`, `--old-master-key`, `--old-kms-key` flags.
- **Logging architecture**: Three named loggers — operational (`slog.Default()`), access (`api.AccessLog`), audit (`audit.Logger`). Each defaults to `slog.Default()` but can be independently routed. Flags: `--audit-logs` (bool, default true), `--access-logs` (bool, default true), `--audit-log-path` (stdout/stderr/filepath, empty = same as operational), `--log-format` (json/text). `openLogDest()` helper in `main.go` creates `slog.Handler` + optional `io.Closer` for file destinations.
- **Backup**: Uses ncruces online backup API (`Conn.Backup("main", dest)`) for consistent page-copy snapshots. Bypasses otelsql via `rawConn()` helper to access `driver.Conn.Raw()`. Destination specified via URI (`--backup-destination`): `s3://bucket/prefix` (S3-compatible) or `gs://bucket/prefix` (Google Cloud Storage). `backup.ResolveDestination()` parses the URI scheme and returns the appropriate `backup.Provider`. `backup.Scheduler` runs periodic backups (ticker goroutine, same pattern as `eventFlusher`). `backup.Prune` enforces retention policy. Engine's `Backup()` returns `*BackupResult{LocalPath, RemoteKeys}`. Admin API: `POST /api/admin/backup`. S3 credentials: AWS SDK chain. GCS credentials: Application Default Credentials (workload identity, SA key, `gcloud auth`, metadata server).
- **Backup tests**: Unit tests use `grafana/s3-mock` (in-process mock S3 server that returns real `*s3.Client` — no interface mocking needed). `destination_test.go` covers URI parsing and scheme resolution. Integration tests in `reliability_test.go` verify backup during active updates, concurrent checkpoints, and no-destination error.
- **Profiling**: `--pprof` flag / `PULUMI_BACKEND_PPROF=true` enables `/debug/pprof/` endpoints (no auth, dev only). See `docs/performance.md`.
- **Health probes**: `/healthz` (liveness — always 200), `/readyz` (readiness — pings SQLite, returns 200 or 503). Both on publicAPI (no auth). Kubernetes-standard paths. When `--management-addr` is set, probes and `/metrics` are served on a separate management port (not exposed on the main API port).
- **Management port**: `--management-addr` / `PULUMI_BACKEND_MANAGEMENT_ADDR` (e.g., `:9090`) serves `/healthz`, `/readyz`, `/metrics` on a dedicated HTTP server. When set, these endpoints are removed from the main mux via `WithSkipManagementRoutes()` option.
- **OpenTelemetry tracing**: Enabled via `--otel-service-name` / `PULUMI_BACKEND_OTEL_SERVICE_NAME`. Three layers of instrumentation: (1) `otelhttp.NewHandler` wraps entire HTTP handler for per-request spans, (2) engine-level spans via `otel.Tracer("pulumi-backend/engine")` for business operations (CreateStack, ExportState, SaveCheckpoint, etc.), (3) `XSAM/otelsql` wraps `database/sql` driver for automatic SQL query spans. OTLP gRPC exporter configured via standard `OTEL_EXPORTER_OTLP_ENDPOINT` env var. TracerProvider with batch span processor and W3C TraceContext + Baggage propagators. Graceful shutdown flushes pending spans.
- **Prometheus metrics**: `http_requests_total`, `http_request_duration_seconds`, `active_updates` (existing) + `pulumi_backend_stack_operations_total{operation}` (counter), `pulumi_backend_update_duration_seconds{kind,status}` (histogram, 1-1800s buckets), `pulumi_backend_checkpoint_bytes{mode}` (histogram, 1KB-16MB exponential buckets). Registered in `internal/api/metrics.go`.
- **Compression pooling**: `gzip.Writer`, `gzip.Reader`, and `bytes.Buffer` are pooled via `sync.Pool` in `internal/gziputil/`. Each `compress/flate.NewWriter` allocates ~800KB — pooling amortizes to near-zero. Includes 512MB decompression bomb limit.
- **Resource count pre-computation**: `storage.CountResources()` uses a zero-alloc byte scanner (finds `"resources":[` and counts top-level objects by brace depth) instead of JSON unmarshal — 7x faster than stdlib, zero allocations regardless of resource count. Runs in the engine layer on uncompressed JSON before compression.
- Deployments: gzip-compressed in DB, zero-copy gzip export when client accepts it
- Leases: in-memory `sync.Map` + SQLite; lost on restart
- State versions: pruned to last N (default 50) per stack
- Capabilities: `delta-checkpoint-uploads-v2`, `batch-encrypt`
- CLI error semantics: error messages match exact patterns the upstream CLI checks (e.g., `"Bad Request: Stack still contains resources."` for deleteStack 400). Validated by `TestCLIErrorSemantics`.
- No Pulumi SDK import: all API shapes hand-coded from reference clone

## CRITICAL: Post-implementation checklist

After completing any plan or feature implementation, ALWAYS update documentation:
- **README.md** — config tables, API compatibility list, reliability test descriptions
- **CLAUDE.md** — architecture, key files, design notes, reference code
- **`docs/`** — new guide if the feature warrants one (auth modes, RBAC, etc.)
