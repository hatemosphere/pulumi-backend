# Backend Comparison Benchmarks

Measures real Pulumi CLI operation times against cloud state backends:

| Backend | Type | Journaling | Delta Checkpoints | Storage |
|---|---|---|---|---|
| **cloud-run** (pulumi-backend) | HTTP state | Yes | Yes | SQLite WAL + gzip |
| **CloudSQL PostgreSQL** | Database (pgstate) | No | No | PostgreSQL rows |
| **GCS** | Blob storage | No | No | GCS objects |

Journaling (sending per-resource entries instead of full state) is the key differentiator — only available on HTTP state backends, not DIY.

## Quick start

```bash
# Run all sizes against GCS
./bench.sh all gcs

# Run medium only against CloudSQL
CLOUDSQL_URL="postgres://pulumi:pass@CLOUDSQL_IP:5432/pulumi_state?sslmode=disable" \
  ./bench.sh medium cloudsql

# Run all sizes against all backends
CLOUD_RUN_URL="https://your-service.run.app" \
CLOUDSQL_URL="postgres://..." \
GCS_BUCKET="gs://your-bucket" \
  ./bench.sh all
```

## Prerequisites

- `pulumi` CLI in PATH
- **cloud-run**: Deploy pulumi-backend to Cloud Run (see `cloudrun-bench.yaml`)
- **cloudsql**: Cloud SQL PostgreSQL instance, set `CLOUDSQL_URL`
- **gcs**: GCS bucket, set `GCS_BUCKET` (uses Application Default Credentials)

## Test scenarios

| Scenario | Description | Real-world frequency |
|---|---|---|
| **create** | Deploy N resources from scratch | Rare (new stacks) |
| **noop** | `pulumi up` with zero changes | Common (CI dry runs) |
| **add-2** | Add 2 resources to existing N | Very common (typical update) |
| **export** | `pulumi stack export` | Moderate (debugging, migration) |
| **destroy** | Destroy all resources | Rare |

Resource sizes target ~16 KB/resource (matching real infra stacks).

## Stack sizes

| Size | Resources | Estimated state |
|---|---|---|
| small | 10 | ~160 KB |
| medium | 200 | ~3.2 MB |
| large | 600 | ~9.6 MB |

## Results

Results are saved to `results/<timestamp>/`:
- `timings.csv` — wall-clock time per operation
- `*.log` — full pulumi CLI output
- `work/` — generated Pulumi projects

See [docs/benchmark-results.md](../docs/benchmark-results.md) for compiled results.

## Cleanup

```bash
rm -rf results/
```
