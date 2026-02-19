# Pulumi Self-Hosted Backend

Self-hosted Pulumi state backend implementing the Pulumi Cloud HTTP API contract.
SQLite-backed, multi-auth, no external Pulumi SDK dependency.

## Architecture

```
CLI -> api.Server (huma v2 + stdlib http.ServeMux) -> engine.Manager -> storage.SQLiteStore (WAL)
```

- **api/** — huma v2 typed handlers, auto-generated OpenAPI spec, auth + RBAC middleware
- **auth/** — Authentication (single-tenant, Google OIDC, JWT), RBAC resolver, groups cache
- **engine/** — Business logic: stack locks, LRU cache, delta/journal replay, AES-256-GCM secrets
- **storage/** — `Store` interface + SQLite impl. Deployments stored gzip-compressed.
- **config/** — Flag + env var parsing (`PULUMI_BACKEND_*` prefix)

## Key files

| Path | Purpose |
|---|---|
| `cmd/pulumi-backend/main.go` | Entry point, wiring |
| `internal/api/router.go` | Server, huma config, all middleware (auth, RBAC, metrics, logging) |
| `internal/api/types.go` | All huma request/response structs |
| `internal/api/errors.go` | Custom PulumiError overriding huma defaults |
| `internal/api/openapi.go` | OpenAPI spec builder (huma -> kin-openapi) |
| `internal/auth/jwt.go` | JWT authenticator (HMAC/RSA/ECDSA auto-detection) |
| `internal/auth/rbac.go` | RBAC resolver (group roles + stack policies) |
| `internal/auth/rbac_config.go` | RBAC YAML config + Permission types |
| `internal/auth/identity.go` | UserIdentity type + context helpers |
| `internal/auth/groups_cache.go` | TTL + singleflight cache for group lookups |
| `internal/auth/google.go` | Google OIDC authenticator + token exchange |
| `internal/engine/manager.go` | Core logic |
| `internal/engine/journal.go` | Journal replay algorithm |
| `internal/engine/delta.go` | Byte-offset delta application |
| `internal/engine/aesgcm.go` | Shared AES-256-GCM seal/open helpers |
| `internal/storage/sqlite.go` | SQLite implementation (inline schema) |
| `internal/storage/storage.go` | `Store` interface + data types |
| `tests/spec_test.go` | OpenAPI spec compliance vs upstream |
| `tests/auth_integration_test.go` | Auth + RBAC integration tests |

## Reference code

- `reference/pulumi/` — Upstream Pulumi source clone (for API shape reference)

## Build & test

```bash
go build -o pulumi-backend ./cmd/pulumi-backend
go test ./internal/...                                    # unit tests
go test -timeout 120s ./tests/ -skip '^TestCLI'           # API + auth tests (no pulumi needed)
go test -v -timeout 120s ./tests/ -run TestCLI            # CLI integration (needs pulumi in PATH)
go test -v -run TestAPISpecSchemaCompliance ./tests/       # spec compliance
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
- **Middleware architecture**: HTTP-level (realIP, recoverer, requestLogger, gzipDecompressor) + huma-level (metricsHumaMiddleware, authHumaMiddleware, rbacMiddleware). Two huma API instances on the same mux: publicAPI (no auth) and api (auth + RBAC).
- SQLite: pure Go via `modernc.org/sqlite`, WAL mode, `MaxOpenConns=1`
- Auth: three modes — `single-tenant` (any token = admin), `google` (OIDC + backend tokens + groups), `jwt` (stateless, claims-based)
- RBAC: group-based with stack-level policy overrides. Permission levels: `none < read < write < admin`.
- Secrets: per-stack AES-256-GCM keys wrapped by master key (local) or GCP KMS
- Deployments: gzip-compressed in DB, zero-copy gzip export when client accepts it
- Leases: in-memory `sync.Map` + SQLite; lost on restart
- State versions: pruned to last N (default 50) per stack
- Capabilities: `delta-checkpoint-uploads-v2`, `batch-encrypt`
- No Pulumi SDK import: all API shapes hand-coded from reference clone
