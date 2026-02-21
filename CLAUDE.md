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
- **storage/** — `Store` interface + SQLite impl. Deployments stored gzip-compressed.
- **config/** — Flag + env var parsing (`PULUMI_BACKEND_*` prefix)

## Key files

| Path | Purpose |
|---|---|
| `cmd/pulumi-backend/main.go` | Entry point, wiring |
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
| `internal/engine/manager.go` | Core logic |
| `internal/engine/journal.go` | Journal replay algorithm |
| `internal/engine/delta.go` | Byte-offset delta application |
| `internal/engine/aesgcm.go` | Shared AES-256-GCM seal/open helpers |
| `internal/storage/sqlite.go` | SQLite implementation (inline schema) |
| `internal/storage/storage.go` | `Store` interface + data types |
| `tests/spec_test.go` | OpenAPI spec compliance vs upstream + CLI error semantics |
| `tests/reliability_test.go` | State consistency, error format, concurrency, checkpoint modes, journal replay, secrets, error code coverage |
| `tests/auth_integration_test.go` | Auth + RBAC integration tests |

## Reference code

- `reference/pulumi/` — Upstream Pulumi source clone (for API shape reference)
- `reference/dex/` — Dex OIDC connector reference (Google connector refresh token pattern)

## Build & test

```bash
go build -o pulumi-backend ./cmd/pulumi-backend
go test ./internal/...                                    # unit tests
go test -timeout 120s ./tests/ -count=1                   # API + auth + reliability tests (CLI/GCP tests auto-skip)
go test -v -timeout 600s ./tests/ -count=1                # all tests including CLI (needs pulumi in PATH)
go test -v -run TestAPISpecSchemaCompliance ./tests/      # spec compliance
go test -v -run TestReliability ./tests/                  # state consistency / reliability tests
go test -bench . -benchmem ./internal/engine              # run engine benchmarks (not in CI)
go test -timeout 600s ./tests/ -count=1                   # full suite
golangci-lint run ./...                                   # lint
```

## Design notes

- **Framework**: huma v2 wrapping stdlib `http.ServeMux` via `humago.New()`. No chi or other router.
- **JSON**: stdlib `encoding/json` everywhere
- **OpenAPI**: auto-generated from Go struct types, no hand-built spec
- **huma config**: `AllowAdditionalPropertiesByDefault=true`, `FieldsOptionalByDefault=true`
- **RawBody caution**: huma pools request body buffers. Any `RawBody []byte` stored beyond handler lifetime must be copied (`make + copy`).
- **Middleware architecture**: HTTP-level (realIP, recoverer, requestLogger, gzipDecompressor) + huma-level (metricsHumaMiddleware, authHumaMiddleware, rbacMiddleware, auditHumaMiddleware). Two huma API instances on the same mux: publicAPI (no auth) and api (auth + RBAC).
- **Audit logging**: Shared `internal/audit` package with typed `audit.Event` struct. huma-level `auditHumaMiddleware` emits structured JSON audit entries for all state-mutating operations (POST/PATCH/PUT/DELETE) with actor, action (operationID), resource, http_status, ip_address. High-frequency ops excluded (checkpoints, events, lease renewals). Inline audit entries for login, token exchange, and RBAC denials. All entries use `slog.Group("audit", ...)` format.
- **Shared handler helpers**: `errors.go` contains `internalError`, `conflictOrInternalError`, `requireIdentity`, `copyBody`, `ptrString` — used across all handler files to eliminate boilerplate.
- SQLite: pure Go via `modernc.org/sqlite`, WAL mode, `MaxOpenConns=1`
- Auth: four modes — `single-tenant` (any token = admin), `google` (Google OIDC via go-oidc/v3 + backend tokens + groups + browser login), `oidc` (generic OIDC provider), `jwt` (stateless, claims-based)
- OIDC architecture: `OIDCAuthenticator` interface in `oidc.go`, Google mode is a specialization (`NewGoogleOIDCAuthenticator`). `TestOIDCValidator` + `TestOIDCRefresher` interfaces for test mock injection via `NewTestOIDCAuthenticator`.
- Browser login: `GET /login` (manual), `GET /cli-login` (automatic via `PULUMI_CONSOLE_DOMAIN`). Registered when `oidcAuth != nil`. Routes on raw mux, not huma (serves HTML).
- OIDC refresh token re-validation: browser/CLI login captures provider's refresh token, stored in `tokens` table. On each auth request past half TTL, async re-validation via `oauth2.TokenSource` detects deactivated users (Dex pattern).
- OIDC groups: stored in DB for generic OIDC providers (from token claims at login), resolved live via Google Admin SDK for Google mode.
- Admin endpoints: `requireAdmin()` helper checks `IsAdmin` (single-tenant) OR RBAC admin permission (Google/JWT). Token management: `GET/DELETE /api/admin/tokens/{userName}`.
- User token endpoints: `GET/POST/DELETE /api/user/tokens` — self-service token management via `registerUserTokens`, gated on `s.tokenStore != nil`
- Teams/roles endpoints: `GET /api/orgs/{orgName}/teams`, `GET /api/orgs/{orgName}/teams/{teamName}`, `GET /api/orgs/{orgName}/roles` — read-only mapping of RBAC YAML config to upstream-shaped responses via `registerOrg`
- RBAC: group-based with stack-level policy overrides. Permission levels: `none < read < write < admin`. Admin RBAC role grants access to admin endpoints too.
- Secrets: per-stack AES-256-GCM keys wrapped by master key (local) or GCP KMS
- Deployments: gzip-compressed in DB, zero-copy gzip export when client accepts it
- Leases: in-memory `sync.Map` + SQLite; lost on restart
- State versions: pruned to last N (default 50) per stack
- Capabilities: `delta-checkpoint-uploads-v2`, `batch-encrypt`
- CLI error semantics: error messages match exact patterns the upstream CLI checks (e.g., `"Bad Request: Stack still contains resources."` for deleteStack 400). Validated by `TestCLIErrorSemantics`.
- No Pulumi SDK import: all API shapes hand-coded from reference clone
