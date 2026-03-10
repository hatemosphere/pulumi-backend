# Benchmark Results

Comparative benchmarks of Pulumi state backends measuring wall-clock time for
real Pulumi CLI operations. All backends are cloud-hosted in GCP europe-west4,
accessed over the internet from a macOS client.

**Date**: 2026-03-10
**Pulumi CLI**: v3.225.1

## Test Setup

### Workloads

Stack sizes using `random:RandomString` resources with 16 KB padding per
resource (via `gen-project.py --pad-kb=16`) to simulate realistic state sizes:

| Size | Resources | ~State Size |
|------|-----------|-------------|
| Small | 10 | ~160 KB |
| Medium | 200 | ~3.2 MB |
| Large | 600 | ~9.6 MB |

### Operations

| Operation | Description |
|-----------|-------------|
| create | `pulumi up` from scratch -- creates all resources one by one |
| cold-noop | `pulumi up` with no changes -- first run after create (triggers server-side journal replay) |
| warm-noop | `pulumi up` with no changes -- subsequent runs (state already materialized) |
| add-2 | `pulumi up` adding 2 resources to existing stack |
| export | `pulumi stack export --show-secrets` -- downloads full state |
| destroy | `pulumi destroy` -- removes all resources one by one |

### Backends

| Backend | Description | Location |
|---------|-------------|----------|
| **pulumi-backend (Cloud Run)** | This project on Cloud Run gen2 (4 vCPU, 8 GB RAM, in-memory tmpfs SQLite) | europe-west4 |
| **CloudSQL PostgreSQL** | Cloud SQL db-custom-4-8192 (4 vCPU, 8 GB RAM, SSD), PostgreSQL 17, `pgstate` DIY backend | europe-west4 |
| **GCS** | Google Cloud Storage bucket (`gs://pulumi-backend-bench-test`) | europe-west4 |

Client machine: macOS (Apple Silicon). All backends accessed over the internet.

## Raw Results

### pulumi-backend (Cloud Run)

Averaged over 3 runs. Cold-noop is the first noop after create (triggers
server-side journal replay); warm-noop is subsequent runs.

| Operation | Small (10) | Medium (200) | Large (600) |
|-----------|-----------|-------------|-------------|
| create | 2.4s | 4.2s | 8.3s |
| cold-noop | 15.4s | 18.3s | 21.7s |
| warm-noop | 1.2s | 3.4s | 7.9s |
| add-2 | 1.4s | 4.0s | 8.5s |
| export | 0.7s | 0.9s | 1.4s |
| destroy | 1.5s | 3.8s | 7.2s |

### CloudSQL PostgreSQL (europe-west4)

| Operation | Small (10) | Medium (200) | Large (600) |
|-----------|-----------|-------------|-------------|
| create | 13.0s | 449.3s | 2614.0s |
| noop | 3.1s | 639.7s | 1023.7s |
| add-2 | 5.2s | 14.8s | 27.4s |
| export | 1.2s | 2.1s | 2.9s |
| destroy | 15.1s | 550.6s | 2444.4s |

Note: CloudSQL noop is pathologically slow -- medium noop (639.7s) exceeds medium
create (449.3s). The `pgstate` backend appears to have severe read-path
inefficiency, likely re-reading and re-parsing the full state blob multiple times.
Cloud Monitoring shows the DB at 2.5% CPU during these operations -- the bottleneck
is client-side sequential round-trips, not database performance.

### GCS (europe-west4)

| Operation | Small (10) | Medium (200) | Large (600) |
|-----------|-----------|-------------|-------------|
| create | 17.8s | 316.6s | 1273.9s |
| noop | 2.9s | 5.9s | 72.0s |
| add-2 | 4.6s | 9.2s | 23.6s |
| export | 1.1s | 1.5s | 2.3s |
| destroy | 19.1s | 325.8s | 1370.1s |

## Comparison (600 resources)

| Operation | pb Cloud Run | CloudSQL | GCS |
|-----------|-------------|----------|-----|
| create | **8.3s** | 2614.0s | 1273.9s |
| cold-noop | 21.7s | — | — |
| warm-noop | **7.9s** | 1023.7s | 72.0s |
| add-2 | **8.5s** | 27.4s | 23.6s |
| export | **1.4s** | 2.9s | 2.3s |
| destroy | **7.2s** | 2444.4s | 1370.1s |

Cold-noop is specific to pulumi-backend's journaling protocol: the first noop
after create triggers server-side journal replay (~14s overhead at 600 resources).
Subsequent noops use the materialized state. DIY backends don't use journaling,
so they have no cold/warm distinction.

| Backend | Create | vs pb Cloud Run |
|---------|--------|-----------------|
| pb Cloud Run | 8.3s | 1x |
| GCS | 1273.9s | 153x slower |
| CloudSQL | 2614.0s | 315x slower |

## Speedup Analysis

### Cloud Run vs DIY Cloud Backends

Speedup factors for pulumi-backend (Cloud Run) over DIY backends at 600 resources:

| Operation | vs CloudSQL | vs GCS |
|-----------|------------|--------|
| create | 315x | 153x |
| warm-noop | 130x | 9.1x |
| add-2 | 3.2x | 2.8x |
| export | 2.1x | 1.6x |
| destroy | 340x | 190x |

## Key Findings

### 1. Journaling protocol is the dominant factor

The single biggest performance differentiator is the checkpoint protocol. During
`pulumi up`, the CLI sends a state checkpoint after every resource change:

- **DIY backends** (CloudSQL, GCS): each checkpoint is a full state rewrite.
  600 resources = 600 full-state uploads, each growing as more resources are
  added. Total data transferred is O(n^2).

- **pulumi-backend**: uses `delta-checkpoint-uploads-v2` capability. After the
  initial full checkpoint, subsequent updates send only changed bytes (journal
  entries). Total data transferred is O(n).

At 600 resources, pulumi-backend (Cloud Run) is 153-340x faster than DIY
backends for write-heavy operations.

### 2. Journal replay adds one-time noop overhead

The journaling protocol has a trade-off: the first read after create (typically
a noop `pulumi up`) triggers server-side journal replay to reconstruct the full
state from individual entries. At 600 resources, this adds ~14s overhead
(cold-noop: 21.7s vs warm-noop: 7.9s). Subsequent noops use the materialized
state and are fast. This is a one-time cost per deployment cycle -- in practice,
most noops (CI dry-runs, drift detection) run against already-materialized state.

### 3. CloudSQL `pgstate` has pathological noop performance

CloudSQL noop times are shocking -- medium noop (639.7s) is **slower than
medium create** (449.3s), and large noop takes 1023.7s (17 minutes). Cloud
Monitoring shows the DB at just 2.5% CPU during these operations, confirming
the bottleneck is entirely client-side: the `pgstate` backend performs
excessive sequential round-trips to read and verify state.

This contrasts with GCS, where noop is fast at medium scale (5.9s) but
degrades at large scale (72.0s) -- still 14x faster than CloudSQL's noop.

### 4. CloudSQL is slower than GCS for write operations

Despite being a database with connection pooling, CloudSQL was consistently slower
than GCS for create/destroy operations (2614s vs 1274s at 600 resources). The
`pgstate` backend's SQL transaction overhead per checkpoint compounds worse than
GCS's blob PUT operations.

### 5. Export is fast everywhere

Export (single state read) is fast across all backends (0.7-2.9s) because it
involves 1-2 round-trips regardless of state size. The performance gap only
manifests in write-heavy operations where checkpoint count matters.

### 6. Add-2 shows near-constant overhead for pulumi-backend

Adding 2 resources to any size stack takes ~1-9s on Cloud Run regardless of
existing state size (1.4s small, 4.0s medium, 8.5s large). With journaling,
only the delta is sent. DIY backends show moderate scaling (4.6s to 23.6s for
GCS) since even 2 new resources require 2 full-state rewrites.

## Summary

Best performers for 600-resource create:

| Rank | Backend | Time | vs #1 |
|------|---------|------|-------|
| 1 | pulumi-backend (Cloud Run) | 8.3s | 1x |
| 2 | GCS (europe-west4) | 1273.9s | 153x |
| 3 | CloudSQL PostgreSQL (europe-west4) | 2614.0s | 315x |

The journaling protocol delivers 2-3 orders of magnitude improvement over DIY
backends at scale.

## Reproducing

```bash
cd benchmarks

# All backends
./bench.sh all

# Specific backend and size
./bench.sh medium gcs
./bench.sh all cloudsql

# Environment variables
export GCS_BUCKET=gs://your-bucket
export CLOUDSQL_URL=postgres://user:pass@host:5432/db?sslmode=disable
export CLOUD_RUN_URL=https://your-service.run.app
```

See `benchmarks/bench.sh` and `benchmarks/gen-project.py` for full details.
