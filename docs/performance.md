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
| `BenchmarkEngineCompression` | Gzip compress + decompress roundtrip at 10/100/1000 resources |
| `BenchmarkEngineExport` | State export from LRU cache (cached path) at 10/100/1000 resources |
| `BenchmarkUpdateLifecycle` | Full create-stack → start-update → checkpoint → complete cycle |
| `BenchmarkSecretsEngine` | AES-256-GCM encrypt + decrypt roundtrip |
| `BenchmarkJournalSave` | Journal entry write + replay at 10/100/1000 entries |
| `BenchmarkEventSave` | Buffered event write throughput |
| `BenchmarkSHA256` | SHA-256 hash of deployment payloads (baseline) |

### HTTP-level (full request path)

| Benchmark | What it measures |
|---|---|
| `BenchmarkHealthCheck` | Minimal HTTP roundtrip (baseline latency) |
| `BenchmarkCreateStack` | Stack creation end-to-end |
| `BenchmarkCheckpointSave` | Full checkpoint upload path |
| `BenchmarkStateExport` | State export via HTTP (includes gzip negotiation) |
| `BenchmarkSecretsEncrypt` / `Decrypt` | Secrets API roundtrip |
| `BenchmarkListStacks` | Stack listing with pagination |

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
# CPU profile of compression path
go test -bench BenchmarkEngineCompression -benchtime 5s -cpuprofile cpu.prof -timeout 120s ./tests/
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

The backend's CPU profile is typically dominated by:

1. **SQLite WAL operations** (~55% during update lifecycle) — inherent to `modernc.org/sqlite`, cannot be optimized at the application level
2. **Gzip compression** (~14%) — mitigated by `sync.Pool` for `gzip.Writer` reuse
3. **JSON marshal/unmarshal** (~10%) — inherent to the Pulumi protocol
4. **SHA-256 hashing** (~5%) — required for checkpoint integrity

### Memory hotspots

Key allocators to watch:

1. **`compress/flate.NewWriter`** — allocates ~800KB per call. Pooled via `sync.Pool` in both `engine/manager.go` and `storage/sqlite.go`
2. **`io.ReadAll` / buffer growth** — decompression path. Mitigated by pre-sized `bytes.Buffer` from pool
3. **`json.Unmarshal` into `map[string]any`** — inherent, but minimized by using targeted struct unmarshaling where possible

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

### sync.Pool for gzip compression (engine + storage layers)

`gzip.Writer` and `bytes.Buffer` are pooled in both `internal/engine/manager.go` and `internal/storage/sqlite.go`. Each `compress/flate.NewWriter` call allocates ~800KB of internal tables — pooling amortizes this to near-zero for steady-state workloads.

### Pre-computed resource counts

Resource counts are computed in the engine layer on uncompressed JSON (via `storage.CountResources()`) before compression, and passed to storage via `StackState.ResourceCount`. This avoids decompressing deployment blobs in the storage layer just to count resources for stack listings.

### Buffer pre-sizing

Compression buffers are pre-grown to `len(data)/4` (typical gzip ratio). Decompression buffers are pre-grown to `len(data)*4`. This reduces slice growth copies.

### Benchmark results (Apple M4 Max)

After optimizations:

| Benchmark | Memory/op | Allocs/op | Latency |
|---|---|---|---|
| `EngineCompression/1000` | 553 KB (-37%) | 1134 | 2.9ms |
| `EngineExport/1000/cached` | 420 KB (-56%) | 19 (-52%) | 200us (-16%) |
| `UpdateLifecycle` | 45 KB (-94.5%) | 482 | 750us |
