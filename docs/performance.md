# Performance Testing & Profiling

This guide covers how to benchmark, profile, and optimize the Pulumi backend.

## Quick start

```bash
# Run all benchmarks (engine + HTTP-level)
go test -bench . -benchmem -timeout 120s ./tests/

# Run specific benchmark
go test -bench BenchmarkEngineCompression -benchmem -timeout 120s ./tests/

# Run with multiple iterations for stable results
go test -bench . -benchmem -count=3 -timeout 120s ./tests/
```

## Benchmark suite

The benchmark suite in `tests/bench_test.go` covers all performance-critical paths:

### Engine-level (no HTTP overhead)

| Benchmark | What it measures |
|---|---|
| `BenchmarkEngineCompression` | Gzip compress + decompress roundtrip at 10/100/1K/5K/10K resources |
| `BenchmarkEngineExport` | State export from LRU cache (cached path) at 10/100/1K/5K/10K resources |
| `BenchmarkUpdateLifecycle` | Full create-stack → start-update → checkpoint → complete cycle |
| `BenchmarkSecretsEngine` | AES-256-GCM encrypt + decrypt roundtrip |
| `BenchmarkJournalSave` | Journal entry write + replay at 1/10/50 entries |
| `BenchmarkEventSave` | Buffered event write throughput |
| `BenchmarkSHA256` | SHA-256 hash of deployment payloads (baseline) |

### HTTP-level (full request path)

| Benchmark | What it measures |
|---|---|
| `BenchmarkHealthCheck` | Minimal HTTP roundtrip (baseline latency) |
| `BenchmarkCreateStack` | Stack creation end-to-end |
| `BenchmarkCheckpointSave` | Full checkpoint upload path at 10/100/1K/5K/10K resources |
| `BenchmarkStateExport` | State export via HTTP (includes gzip negotiation) at 10/100/1K/5K/10K resources |
| `BenchmarkSecretsEncrypt` / `Decrypt` | Secrets API roundtrip |
| `BenchmarkListStacks` | Stack listing with pagination at 10/100 stacks |

### Concurrency & stress

| Benchmark | What it measures |
|---|---|
| `BenchmarkConcurrentUpdates` | Parallel update lifecycles at 2/4/8/16 goroutines |
| `BenchmarkConcurrentCheckpoints` | Parallel checkpoint saves at 1K/5K/10K resources |
| `BenchmarkConcurrentHTTPCheckpoints` | Parallel HTTP checkpoint saves at 1K/5K/10K resources |
| `BenchmarkConcurrentExportsWhileUpdating` | Export reads during active update writes |
| `BenchmarkRenameUnderLoad` | Stack rename during concurrent updates |
| `BenchmarkRenameHTTPUnderLoad` | Stack rename via HTTP during concurrent updates |

### Reading results

```
BenchmarkEngineCompression/resources=1000-16    822  2930614 ns/op  124.02 MB/s  554971 B/op  1134 allocs/op
```

- `822` — iterations run
- `2930614 ns/op` — ~2.9ms per operation
- `124.02 MB/s` — throughput (compression benchmarks report `SetBytes`)
- `554971 B/op` — heap bytes allocated per operation
- `1134 allocs/op` — number of heap allocations per operation

### Comparing before/after

Use `benchstat` to compare results across runs:

```bash
# Install benchstat
go install golang.org/x/perf/cmd/benchstat@latest

# Capture baseline
go test -bench . -benchmem -count=6 -timeout 120s ./tests/ > old.txt

# Make changes, then capture new results
go test -bench . -benchmem -count=6 -timeout 120s ./tests/ > new.txt

# Compare
benchstat old.txt new.txt
```

Use `-count=6` or higher for statistically meaningful comparisons.

## Runtime profiling with pprof

### Enabling pprof

Start the backend with the `--pprof` flag (or `PULUMI_BACKEND_PPROF=true`):

```bash
./pulumi-backend --pprof
```

This registers Go's standard `net/http/pprof` handlers at `/debug/pprof/`. These endpoints have no authentication — only enable in development or behind a trusted network.

### Collecting profiles

While the backend is running under load:

```bash
# CPU profile (30 seconds by default)
go tool pprof http://localhost:8080/debug/pprof/profile?seconds=30

# Heap (memory) profile — current allocations
go tool pprof http://localhost:8080/debug/pprof/heap

# Allocations profile — all allocations since start (useful for finding allocation-heavy code)
go tool pprof http://localhost:8080/debug/pprof/allocs

# Goroutine profile — check for leaks
go tool pprof http://localhost:8080/debug/pprof/goroutine

# Block profile — contention on mutexes/channels
go tool pprof http://localhost:8080/debug/pprof/block

# Mutex profile — mutex contention specifically
go tool pprof http://localhost:8080/debug/pprof/mutex
```

### Collecting profiles from benchmarks

For targeted profiling without running the full server:

```bash
# CPU profile of update lifecycle
go test -bench BenchmarkUpdateLifecycle -benchtime 10s -cpuprofile cpu.prof -timeout 120s ./tests/
go tool pprof cpu.prof

# Memory profile of export path
go test -bench BenchmarkEngineExport -benchtime 5s -memprofile mem.prof -timeout 120s ./tests/
go tool pprof mem.prof

# Memory profile of full lifecycle
go test -bench BenchmarkUpdateLifecycle -benchtime 5s -memprofile mem.prof -timeout 120s ./tests/
go tool pprof mem.prof
```

### Analyzing profiles

Inside `go tool pprof`:

```
# Top functions by CPU/memory
(pprof) top 20

# Show call graph for a specific function
(pprof) web compress       # opens in browser
(pprof) list compress      # shows annotated source

# Cumulative view (includes callees)
(pprof) top -cum 20

# Focus on a specific package
(pprof) top -cum 20 engine

# Interactive web UI (recommended)
(pprof) web
```

Or use the web UI directly:

```bash
go tool pprof -http=:6060 cpu.prof
```

This opens a browser with flame graphs, call graphs, and source annotations.

### Trace collection

For detailed execution traces (goroutine scheduling, GC events, syscalls):

```bash
# Collect trace from running server
curl -o trace.out http://localhost:8080/debug/pprof/trace?seconds=5

# Collect trace from benchmarks
go test -bench BenchmarkUpdateLifecycle -trace trace.out -timeout 120s ./tests/

# Analyze
go tool trace trace.out
```

## What to look for

### CPU hotspots

Profiled on Apple M4 Max during `BenchmarkUpdateLifecycle` (10s run). Percentages
are cumulative time relative to total benchmark time:

1. **SQLite via Wasm runtime** (~65%) — `ncruces/go-sqlite3` runs SQLite compiled
   to Wasm via `tetratelabs/wazero`. WAL operations, VFS shm locks, and file I/O
   dominate. Inherent to the Wasm-based SQLite approach — cannot be optimized at
   the application level.
2. **Gzip compression/decompression** (~5%) — mitigated by `sync.Pool` for
   `gzip.Writer`/`gzip.Reader` reuse in `internal/gziputil/`.
3. **JSON marshal/unmarshal** (~3%) — uses `segmentio/encoding/json` (2-7x faster
   than stdlib, near-zero allocs). Remaining cost is inherent to the protocol.
4. **Crypto** (~3%) — AES-256-GCM for secrets is sub-microsecond. RSA key
   generation shows up in profiles but only runs during test setup, not per-request.

### Memory hotspots

Key allocators to watch:

1. **`compress/flate.NewWriter`** — allocates ~800KB per call. Pooled via `sync.Pool` in `internal/gziputil/gziputil.go`
2. **`io.ReadAll` / buffer growth** — decompression path. Mitigated by pre-sized `bytes.Buffer` from pool
3. **`json.Unmarshal` into `map[string]any`** — minimized by using `segmentio/encoding/json` and targeted struct unmarshaling where possible

### Goroutine leaks

Check the goroutine profile for unexpected growth. Normal goroutine count:

- 1 main goroutine
- 1 event flusher goroutine
- 1 backup scheduler goroutine (if backup schedule is configured)
- 1 goroutine per active HTTP connection
- 1 per active lease renewal

### Allocation reduction checklist

When optimizing allocations:

- Use `sync.Pool` for frequently allocated large objects (gzip writers, buffers)
- Pre-size slices with `make([]T, 0, expectedCap)`
- Use `bytes.Buffer.Grow()` with estimated size before writing
- Prefer struct unmarshaling over `map[string]any` when only specific fields are needed
- Compute derived values (like resource counts) before compression to avoid decompressing later

## Implemented optimizations

### sync.Pool for gzip compression

`gzip.Writer`, `gzip.Reader`, and `bytes.Buffer` are pooled in `internal/gziputil/gziputil.go`, shared by both engine and storage layers. Each `compress/flate.NewWriter` call allocates ~800KB of internal tables — pooling amortizes this to near-zero for steady-state workloads. Includes 512MB decompression bomb limit.

### Pre-computed resource counts

Resource counts are computed in the engine layer on uncompressed JSON (via `storage.CountResources()`) before compression, and passed to storage via `StackState.ResourceCount`. Uses a zero-alloc byte scanner that finds `"resources":[` and counts top-level objects by brace depth — 7x faster than stdlib JSON unmarshal, zero allocations regardless of resource count.

### Buffer pre-sizing

Compression buffers are pre-grown to `len(data)/4` (typical gzip ratio). Decompression buffers are pre-grown to `len(data)*4`. This reduces slice growth copies.

### Fast JSON library

`segmentio/encoding/json` is used as a drop-in stdlib replacement throughout. 2-7x faster marshal/unmarshal with near-zero allocations compared to `encoding/json`.

### Benchmark results (Apple M4 Max, 16 cores)

Current numbers:

| Benchmark | Latency | Memory/op | Allocs/op |
|---|---|---|---|
| `HealthCheck` (HTTP) | 41us | 7.3 KB | 94 |
| `CreateStack` (HTTP) | 102us | 21 KB | 273 |
| `CheckpointSave/1000` (HTTP) | 5.9ms | 4.9 MB | 49K |
| `CheckpointSave/10000` (HTTP) | 52ms | 48 MB | 481K |
| `StateExport/1000` (HTTP, cached) | 66us | 18 KB | 201 |
| `StateExport/10000` (HTTP, cached) | 66us | 18 KB | 201 |
| `SecretsEncrypt` (HTTP) | 49us | 12 KB | 139 |
| `UpdateLifecycle` (engine) | 610us | 66 KB | 805 |
| `SecretsEngine/encrypt` | 0.7us | 1.9 KB | 9 |
| `SecretsEngine/decrypt` | 0.5us | 1.8 KB | 8 |
| `EngineExport/1000/cached` | 150us | 374 KB | 11 |
| `JournalSave/batch=50` | 423us | 162 KB | 2K |
| `ListStacks/100` | 250us | 605 KB | 2.4K |

Notable: `StateExport` latency is constant regardless of resource count (66us
from 10 to 10K resources) because the cached path returns pre-compressed bytes
without deserialization.

## End-to-end CLI benchmarks

For real-world wall-clock benchmarks comparing pulumi-backend against DIY backends
(CloudSQL PostgreSQL, GCS) using actual Pulumi CLI operations, see:

- **[Benchmark results](benchmark-results.md)** — full comparison with charts and analysis
- **[benchmarks/](../benchmarks/)** — scripts to reproduce (`bench.sh`, `gen-project.py`)

Key finding: at 600 resources, pulumi-backend on Cloud Run is 153-340x faster than
DIY backends for write-heavy operations (create, destroy) thanks to the journaling
checkpoint protocol (`delta-checkpoint-uploads-v2`).
