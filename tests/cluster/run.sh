#!/usr/bin/env bash
#
# End-to-end live-mesh telemetry harness for norn-rs.
#
# Brings up a 12-node small-world docker cluster, lets it converge for
# 2 min while a scraper collects /metrics on every node every second,
# then renders SVG plots into docs/cluster/.
#
# Usage:
#   bash tests/cluster/run.sh             # full run (build + cluster + plots)
#   bash tests/cluster/run.sh --plots-only   # re-render from existing CSV
#
# Prereqs (WSL2/Linux):
#   - docker + docker compose v2 plugin
#   - python3 with matplotlib (only required for --plots-only step;
#     auto-installed in the cluster scraper image)
#
# Exits 0 on success; non-zero if any stage failed.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/tests/cluster"
cd "$ROOT"

if [[ "${1:-}" == "--plots-only" ]]; then
    python3 "$HERE/plot.py"
    exit $?
fi

echo "=== regenerate topology + configs ==="
python3 "$HERE/topology.py"

echo "=== build test-node image ==="
# Quiet build (BuildKit gives a sane progress display by default).
DOCKER_BUILDKIT=1 docker build \
    -f "$HERE/Dockerfile.testnode" \
    -t norn-testnode:latest "$ROOT"

echo "=== teardown any previous cluster ==="
docker compose -f "$HERE/docker-compose.yml" down --remove-orphans -v >/dev/null 2>&1 || true

echo "=== bring cluster up ==="
docker compose -f "$HERE/docker-compose.yml" up -d

echo "=== scraper running for 120s; mid-run we kill+restore half the nodes ==="
# Background the scraper-tail; meanwhile inject a rolling-restart at t≈60s
# so the second half of the run exercises reconvergence (real cold-start
# dynamics that the initial t=0 sample window often misses).
docker compose -f "$HERE/docker-compose.yml" logs -f scraper > "$HERE/out/scraper.log" 2>&1 &
SCRAPER_TAIL=$!

(
    sleep 60
    echo "  [chaos] killing half the nodes at t=60s"
    for i in 0 2 4 6 8 10 12 14; do
        docker kill -s SIGTERM "norn-test-$(printf '%02d' "$i")" >/dev/null 2>&1 || true
    done
    sleep 10
    echo "  [chaos] restoring killed nodes at t=70s"
    docker compose -f "$HERE/docker-compose.yml" up -d --no-deps \
        norn-00 norn-02 norn-04 norn-06 norn-08 norn-10 norn-12 norn-14 \
        >/dev/null 2>&1 || true
) &
CHAOS_PID=$!

wait "$SCRAPER_TAIL" || true
wait "$CHAOS_PID" 2>/dev/null || true

echo "=== capture per-node tail logs for forensics ==="
mkdir -p "$HERE/out/logs"
# Auto-detect node count from the generated compose file so this scales
# with whatever topology.py wrote.
NODE_COUNT=$(grep -cE '^  norn-[0-9]+:' "$HERE/docker-compose.yml" || echo 0)
for i in $(seq 0 $((NODE_COUNT - 1))); do
    name=$(printf "norn-test-%02d" "$i")
    docker logs --tail 200 "$name" > "$HERE/out/logs/$name.log" 2>&1 || true
done

echo "=== capture aggregate hardware load snapshot ==="
docker stats --no-stream --format \
    'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}' \
    > "$HERE/out/docker-stats.txt" 2>&1 || true

echo "=== tear cluster down ==="
docker compose -f "$HERE/docker-compose.yml" down --remove-orphans -v

echo "=== render plots ==="
if ! python3 "$HERE/plot.py"; then
    echo "WARN: plot rendering failed — CSV at $HERE/out/metrics.csv is still usable"
    exit 1
fi

echo "=== OK ==="
echo "SVGs in: $ROOT/docs/cluster/"
echo "CSV in:  $HERE/out/metrics.csv"
echo "Logs in: $HERE/out/logs/"
