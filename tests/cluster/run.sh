#!/usr/bin/env bash
#
# End-to-end live-mesh telemetry harness for norn-rs.
#
# Brings up the docker cluster (size set in topology.py), lets it
# converge while a scraper collects /metrics on every node every second,
# then renders SVG plots into docs/cluster/.
#
# Usage:
#   bash tests/cluster/run.sh             # full run (build + cluster + plots)
#   bash tests/cluster/run.sh --plots-only   # re-render from existing CSV
#
# Prereqs (WSL2/Linux):
#   - docker + docker compose v2 plugin
#   - python3 with venv module (apt install python3-venv if missing)
#
# All Python deps go into tests/cluster/.venv — we never touch system
# Python. The venv is bootstrapped on first run.
#
# Exits 0 on success; non-zero if any stage failed.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/tests/cluster"
VENV="$HERE/.venv"
PYVENV="$VENV/bin/python3"
cd "$ROOT"

ensure_venv() {
    if [[ ! -x "$PYVENV" ]]; then
        echo "=== bootstrap python venv at $VENV ==="
        python3 -m venv "$VENV"
        "$VENV/bin/pip" install --quiet --upgrade pip
        "$VENV/bin/pip" install --quiet matplotlib networkx cryptography
    fi
}

ensure_venv

if [[ "${1:-}" == "--plots-only" ]]; then
    "$PYVENV" "$HERE/plot.py"
    "$PYVENV" "$HERE/plot_graph.py" || true
    exit $?
fi

echo "=== regenerate topology + configs ==="
"$PYVENV" "$HERE/topology.py"

echo "=== build test-node image ==="
DOCKER_BUILDKIT=1 docker build \
    -f "$HERE/Dockerfile.testnode" \
    -t norn-testnode:latest "$ROOT"

echo "=== teardown any previous cluster ==="
docker compose -f "$HERE/docker-compose.yml" down --remove-orphans -v >/dev/null 2>&1 || true

echo "=== bring cluster up ==="
docker compose -f "$HERE/docker-compose.yml" up -d

echo "=== scraper running for 120s; mid-run we kill+restore ~10% of nodes ==="
docker compose -f "$HERE/docker-compose.yml" logs -f scraper > "$HERE/out/scraper.log" 2>&1 &
SCRAPER_TAIL=$!

(
    NODE_COUNT=$(grep -cE '^  norn-[0-9]+:' "$HERE/docker-compose.yml" || echo 0)
    KILL_COUNT=$(( (NODE_COUNT + 9) / 10 ))
    [ "$KILL_COUNT" -lt 4 ] && KILL_COUNT=4

    sleep 60
    echo "  [chaos] killing $KILL_COUNT of $NODE_COUNT nodes at t=60s"
    KILLED=""
    for k in $(seq 0 $((KILL_COUNT - 1))); do
        i=$((k * NODE_COUNT / KILL_COUNT))
        name=$(printf "norn-test-%02d" "$i")
        svc=$(printf "norn-%02d" "$i")
        KILLED="$KILLED $svc"
        docker kill -s SIGTERM "$name" >/dev/null 2>&1 || true
    done
    sleep 10
    echo "  [chaos] restoring at t=70s:$KILLED"
    # shellcheck disable=SC2086
    docker compose -f "$HERE/docker-compose.yml" up -d --no-deps $KILLED \
        >/dev/null 2>&1 || true
) &
CHAOS_PID=$!

wait "$SCRAPER_TAIL" || true
wait "$CHAOS_PID" 2>/dev/null || true

echo "=== snapshot tree state (per-node /metrics → tree_snapshot.json) ==="
"$PYVENV" "$HERE/snapshot_trees.py" \
    --nodes "$(grep -cE '^  norn-[0-9]+:' "$HERE/docker-compose.yml")" \
    --out "$HERE/out/tree_snapshot.json" || true

echo "=== capture per-node tail logs for forensics ==="
mkdir -p "$HERE/out/logs"
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
if ! "$PYVENV" "$HERE/plot.py"; then
    echo "WARN: plot.py failed — CSV at $HERE/out/metrics.csv is still usable"
    exit 1
fi
"$PYVENV" "$HERE/plot_graph.py" || \
    echo "WARN: plot_graph.py failed — tree snapshot may be empty"

echo "=== OK ==="
echo "SVGs in: $ROOT/docs/cluster/"
echo "CSV in:  $HERE/out/metrics.csv"
echo "Logs in: $HERE/out/logs/"
