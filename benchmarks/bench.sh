#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Backend Comparison Benchmark
# =============================================================================
# Measures wall-clock time for real Pulumi CLI operations against cloud backends:
#   1. cloud-run (this project)  — HTTP state on Cloud Run, journaling + delta checkpoints
#   2. cloudsql                  — Cloud SQL PostgreSQL via pgstate, full checkpoint only
#   3. gcs                      — Google Cloud Storage bucket, full checkpoint only
#
# Key differentiator: journaling is ONLY available on pulumi-backend (cloud-run).
# DIY backends rewrite the entire state blob on every checkpoint.
#
# Usage:
#   ./bench.sh [small|medium|large|all] [backend]   (default: all sizes, all backends)
#   ./bench.sh all gcs          # run all sizes against GCS only
#   ./bench.sh medium cloudsql  # run medium only against CloudSQL
#
# Prerequisites:
#   pulumi CLI in PATH
#   For cloud-run: deploy pulumi-backend to Cloud Run (see benchmarks/cloudrun-bench.yaml)
#   For cloudsql: create Cloud SQL PostgreSQL instance, set CLOUDSQL_URL
#   For gcs: create GCS bucket, set GCS_BUCKET
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"

SIZES="${1:-all}"
BACKEND_FILTER="${2:-}"
CLOUDSQL_URL="${CLOUDSQL_URL:-}"  # e.g. postgres://pulumi:pass@CLOUDSQL_IP:5432/pulumi_state?sslmode=disable
GCS_BUCKET="${GCS_BUCKET:-gs://pulumi-backend-bench-test}"
CLOUD_RUN_URL="${CLOUD_RUN_URL:-}"

# --- Helpers ---

ts() { python3 -c "import time; print(f'{time.time():.3f}')"; }
log() { echo "[$(date +%H:%M:%S)] $*"; }

# Run pulumi with environment for a specific backend.
run_pulumi() {
  local backend="$1" home="$2" workdir="$3"
  shift 3

  local -a env_args=(
    "PULUMI_HOME=$home"
    "PULUMI_SKIP_UPDATE_CHECK=true"
    "PULUMI_CONFIG_PASSPHRASE=benchmark"
    "NO_COLOR=true"
  )

  case "$backend" in
    cloud-run)
      env_args+=("PULUMI_ACCESS_TOKEN=test-token")
      ;;
    cloudsql|gcs)
      # cloudsql: URL has credentials; gcs: uses application default credentials
      ;;
  esac

  env "${env_args[@]}" pulumi -C "$workdir" "$@"
}

# Time a pulumi operation. Prints and records timing.
bench_op() {
  local label="$1" backend="$2" home="$3" workdir="$4"
  shift 4

  local t0 t1 elapsed
  t0=$(ts)

  if run_pulumi "$backend" "$home" "$workdir" "$@" >> "$RESULTS_DIR/${label%%/*}.log" 2>&1; then
    t1=$(ts)
    elapsed=$(python3 -c "print(f'{$t1 - $t0:.3f}')")
    printf "  %-40s %8ss\n" "$label" "$elapsed"
    echo "$label ${elapsed}s" >> "$RESULTS_DIR/timings.csv"
  else
    t1=$(ts)
    elapsed=$(python3 -c "print(f'{$t1 - $t0:.3f}')")
    printf "  %-40s %8ss  FAILED\n" "$label" "$elapsed"
    echo "$label ${elapsed}s FAILED" >> "$RESULTS_DIR/timings.csv"
    echo "FATAL: $label failed, aborting. Check $RESULTS_DIR/${label%%/*}.log" >&2
    exit 1
  fi
}

# --- Run one full scenario ---

run_scenario() {
  local backend="$1" size="$2" count="$3"
  local tag="${backend}/${size}"
  local workdir="$RESULTS_DIR/work/${backend}_${size}"
  # Share PULUMI_HOME per backend (plugin cache shared across sizes)
  local home="$RESULTS_DIR/home/${backend}"
  mkdir -p "$workdir" "$home"

  log "--- $tag ($count resources) ---"

  # Generate project
  python3 "$SCRIPT_DIR/gen-project.py" "$workdir" "$count" --pad-kb=16

  # Login (idempotent — reuses existing session)
  case "$backend" in
    cloud-run)
      run_pulumi "$backend" "$home" "$workdir" login "$CLOUD_RUN_URL" >/dev/null 2>&1
      ;;
    cloudsql)
      run_pulumi "$backend" "$home" "$workdir" login "$CLOUDSQL_URL" >/dev/null 2>&1
      ;;
    gcs)
      run_pulumi "$backend" "$home" "$workdir" login "$GCS_BUCKET" >/dev/null 2>&1
      ;;
  esac

  # Stack name
  local stack
  case "$backend" in
    cloud-run) stack="organization/bench-project/${size}" ;;
    *)         stack="${size}" ;;
  esac

  # Clean up any leftover stack/lock from previous runs
  run_pulumi "$backend" "$home" "$workdir" cancel --yes --stack "$stack" >/dev/null 2>&1 || true
  run_pulumi "$backend" "$home" "$workdir" stack rm --yes --force --stack "$stack" >/dev/null 2>&1 || true

  # Init stack
  run_pulumi "$backend" "$home" "$workdir" stack init "$stack" >/dev/null 2>&1 || true

  # Create
  bench_op "$tag/create" "$backend" "$home" "$workdir" up --yes --stack "$stack"

  # No-op update
  bench_op "$tag/noop" "$backend" "$home" "$workdir" up --yes --stack "$stack"

  # Small update: add 2 resources
  python3 "$SCRIPT_DIR/gen-project.py" "$workdir" "$((count + 2))" --pad-kb=16
  bench_op "$tag/add-2" "$backend" "$home" "$workdir" up --yes --stack "$stack"

  # Export
  bench_op "$tag/export" "$backend" "$home" "$workdir" stack export --stack "$stack" --show-secrets

  # Destroy
  bench_op "$tag/destroy" "$backend" "$home" "$workdir" destroy --yes --stack "$stack"

  # Cleanup
  run_pulumi "$backend" "$home" "$workdir" cancel --yes --stack "$stack" >/dev/null 2>&1 || true
  run_pulumi "$backend" "$home" "$workdir" stack rm --yes --force --stack "$stack" >/dev/null 2>&1 || true
  echo ""
}

# --- Main ---

log "Results: $RESULTS_DIR"
echo "backend/size/op time" > "$RESULTS_DIR/timings.csv"

command -v pulumi >/dev/null || { echo "ERROR: pulumi CLI not in PATH"; exit 1; }
log "Pulumi CLI: $(pulumi version)"

declare -A SIZE_MAP=([small]=10 [medium]=200 [large]=600)

if [[ "$SIZES" == "all" ]]; then
  sizes=(small medium large)
else
  IFS=',' read -ra sizes <<< "$SIZES"
fi

if [[ -n "$BACKEND_FILTER" ]]; then
  IFS=',' read -ra BACKENDS <<< "$BACKEND_FILTER"
else
  BACKENDS=(cloud-run cloudsql gcs)
fi

# Pre-install the random provider plugin for each backend's PULUMI_HOME.
log "Pre-installing random provider plugin..."
for backend in "${BACKENDS[@]}"; do
  local_home="$RESULTS_DIR/home/${backend}"
  mkdir -p "$local_home"
  PULUMI_HOME="$local_home" PULUMI_SKIP_UPDATE_CHECK=true \
    pulumi plugin install resource random >/dev/null 2>&1 || true
done
log "Plugins ready"

# Run one backend at a time across all sizes to avoid resource contention.
for backend in "${BACKENDS[@]}"; do
  log "====== Backend: $backend ======"
  for size in "${sizes[@]}"; do
    count=${SIZE_MAP[$size]}
    run_scenario "$backend" "$size" "$count"
  done
  sleep 2
done

# --- Summary table ---
echo ""
log "========== SUMMARY =========="
echo ""

python3 - "$RESULTS_DIR/timings.csv" <<'PYEOF'
import sys
from collections import defaultdict

timings = defaultdict(dict)
with open(sys.argv[1]) as f:
    next(f)  # skip header
    for line in f:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        label = parts[0]
        time_s = parts[1].rstrip('s')
        failed = "FAILED" in line

        # Parse: backend/size/op
        segs = label.split("/")
        if len(segs) != 3:
            continue
        backend, size, op = segs
        key = f"{size}/{op}"
        val = f"{time_s}s" + (" FAIL" if failed else "")
        timings[key][backend] = val

if not timings:
    print("No timing data collected.")
    sys.exit(0)

backends = ["cloud-run", "cloudsql", "gcs"]
present = [b for b in backends if any(b in t for t in timings.values())]
header = f"{'Operation':<25}" + "".join(f"{b:>18}" for b in present)
print(header)
print("-" * len(header))

for key in sorted(timings.keys()):
    row = f"{key:<25}"
    for b in present:
        row += f"{timings[key].get(b, 'N/A'):>18}"
    print(row)

# Speedup comparison vs cloud-run
cr_present = any("cloud-run" in t for t in timings.values())
if cr_present:
    print()
    print("Speedup vs cloud-run (pulumi-backend):")
    print("-" * 60)
    for key in sorted(timings.keys()):
        cr_val = timings[key].get("cloud-run", "")
        if not cr_val or "FAIL" in cr_val:
            continue
        cr_time = float(cr_val.rstrip("s"))
        if cr_time == 0:
            continue
        row = f"  {key:<23}"
        for b in present:
            if b == "cloud-run":
                continue
            val = timings[key].get(b, "")
            if val and "FAIL" not in val:
                other_time = float(val.rstrip("s"))
                if other_time > 0:
                    ratio = other_time / cr_time
                    row += f"  {b}: {ratio:.1f}x slower" if ratio > 1 else f"  {b}: {1/ratio:.1f}x faster"
                else:
                    row += f"  {b}: N/A"
            else:
                row += f"  {b}: N/A"
        print(row)
PYEOF

echo ""
log "Full results: $RESULTS_DIR/"
