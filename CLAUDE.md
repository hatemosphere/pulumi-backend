# Pulumi Self-Hosted Backend

Self-hosted Pulumi state backend implementing the Pulumi Cloud HTTP API contract.
Single-tenant, SQLite-backed, no external Pulumi SDK dependency.

## Architecture

```
CLI -> api.Server (huma v2 + chi v5) -> engine.Manager -> storage.SQLiteStore (WAL)
```

- **api/** — huma v2 typed handlers, auto-generated OpenAPI spec, chi router, auth middleware
- **engine/** — Business logic: stack locks, LRU cache, delta/journal replay, AES-256-GCM secrets
- **storage/** — `Store` interface + SQLite impl. Deployments stored gzip-compressed.
- **config/** — Flag + env var parsing (`PULUMI_BACKEND_*` prefix)

## Key files

| Path | Purpose |
|---|---|
| `cmd/pulumi-backend/main.go` | Entry point, wiring |
| `internal/api/router.go` | Server, huma config, chi middleware |
| `internal/api/types.go` | All huma request/response structs |
| `internal/api/errors.go` | Custom PulumiError overriding huma defaults |
| `internal/api/openapi.go` | OpenAPI spec builder (huma -> kin-openapi) |
| `internal/engine/manager.go` | Core logic |
| `internal/engine/journal.go` | Journal replay algorithm |
| `internal/engine/delta.go` | Byte-offset delta application |
| `internal/storage/sqlite.go` | SQLite implementation |
| `internal/storage/storage.go` | `Store` interface + data types |
| `tests/spec_test.go` | OpenAPI spec compliance vs upstream |

## Reference code

- `reference/pulumi/` — Upstream Pulumi source clone
- `reference/huma/` — huma v2 source (for understanding internals)

## Build & test

```bash
go build -o pulumi-backend ./cmd/pulumi-backend
go test ./internal/...                                    # unit tests
go test -timeout 120s ./tests/ -run 'Test[^C][^L][^I]'   # API tests (no pulumi needed)
go test -v -timeout 120s ./tests/ -run TestCLI            # CLI integration (needs pulumi in PATH)
go test -v -run TestAPISpecSchemaCompliance ./tests/       # spec compliance (21 diffs, all expected)
go test -timeout 600s ./tests/ -count=1                   # full suite
```

## Design notes

- **Framework**: huma v2 wrapping chi v5 via `humachi.New()`
- **JSON**: stdlib `encoding/json` everywhere
- **OpenAPI**: auto-generated from Go struct types, no hand-built spec
- **huma config**: `AllowAdditionalPropertiesByDefault=true`, `FieldsOptionalByDefault=true`
- **RawBody caution**: huma pools request body buffers. Any `RawBody []byte` stored beyond handler lifetime must be copied (`make + copy`).
- SQLite: pure Go via `modernc.org/sqlite`, WAL mode, `MaxOpenConns=1`
- Auth: single-tenant, any `token <x>` accepted
- Deployments: gzip-compressed in DB, zero-copy gzip export when client accepts it
- Leases: in-memory `sync.Map` + SQLite; lost on restart
- State versions: pruned to last N (default 50) per stack
- Capabilities: `delta-checkpoint-uploads-v2`, `batch-encrypt`
- No Pulumi SDK import: all API shapes hand-coded from reference clone
