#!/usr/bin/env bash
#
# End-to-end test in two Linux network namespaces.
#
# Spins up two `nornd` processes in `ns_a` / `ns_b` linked by a veth pair,
# verifies that their 200::/7 TUN addresses are reachable from each other
# via an actual IPv6 ping over the overlay. This is the closest thing to a
# real deployment: real TUN device, real kernel routing, real handshake.
#
# Requirements:
#   - Linux with netns + tun support
#   - root (or unshare-ns capable; CI runs this in a privileged container)
#   - cargo build --release --features tun-support
#
# Usage:
#   sudo tests/netns/run.sh
#
# Designed for CI; exits 0 on success, non-zero on any failure. Cleans up
# namespaces on exit (including on errors).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NORND="${NORND:-$ROOT/target/release/nornd}"

if [[ $EUID -ne 0 ]]; then
    echo "FATAL: must run as root (or via sudo)" >&2
    exit 1
fi

if [[ ! -x "$NORND" ]]; then
    echo "FATAL: $NORND not found or not executable." >&2
    echo "Build with:  cargo build --release --features tun-support" >&2
    exit 1
fi

# ── topology ──────────────────────────────────────────────────────────────
NS_A=norn-test-a
NS_B=norn-test-b
VETH_A=veth-a
VETH_B=veth-b
IP_A=10.99.0.1/24
IP_B=10.99.0.2/24
PORT=19090

WORK=$(mktemp -d)
PID_A=
PID_B=

cleanup() {
    set +e
    echo "── cleanup ──"
    [[ -n "$PID_A" ]] && kill "$PID_A" 2>/dev/null
    [[ -n "$PID_B" ]] && kill "$PID_B" 2>/dev/null
    sleep 0.3
    ip netns del "$NS_A" 2>/dev/null
    ip netns del "$NS_B" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

# ── netns + veth setup ────────────────────────────────────────────────────
echo "── setting up netns ──"
ip netns add "$NS_A"
ip netns add "$NS_B"

ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"

ip -n "$NS_A" addr add "$IP_A" dev "$VETH_A"
ip -n "$NS_B" addr add "$IP_B" dev "$VETH_B"
ip -n "$NS_A" link set "$VETH_A" up
ip -n "$NS_B" link set "$VETH_B" up
ip -n "$NS_A" link set lo up
ip -n "$NS_B" link set lo up

# ── configs ───────────────────────────────────────────────────────────────
# Build the configs from scratch (instead of appending to `genconfig` output,
# which would duplicate keys and fail TOML parsing). We still call genconfig
# once just to harvest a fresh private_key.
echo "── generating configs ──"
mkdir -p "$WORK/a" "$WORK/b"

generate_key() {
    "$NORND" genconfig | awk -F'"' '/^private_key/ {print $2; exit}'
}

write_config() {
    local dir=$1 me_addr=$2 peer_uri=$3 sock=$4 priv_hex=$5
    cat >"$dir/norn.toml" <<EOF
private_key = "${priv_hex}"
listen      = ["tcp://${me_addr%/*}:${PORT}"]
peers       = ["${peer_uri}"]
tun_name    = "norn0"
admin_socket    = "${sock}"
peer_cache_path = ""
multicast_enabled = false
mdns_enabled      = false
metrics_addr      = ""
min_peer_difficulty_bits = 0
log_level        = "warn"
EOF
    chmod 600 "$dir/norn.toml"
}

KEY_A=$(generate_key)
KEY_B=$(generate_key)
write_config "$WORK/a" "${IP_A%/*}" "tcp://${IP_B%/*}:${PORT}" "$WORK/a/admin.sock" "$KEY_A"
write_config "$WORK/b" "${IP_B%/*}" "tcp://${IP_A%/*}:${PORT}" "$WORK/b/admin.sock" "$KEY_B"

# ── start daemons ─────────────────────────────────────────────────────────
echo "── starting daemons ──"
# RUST_LOG=info so the captured log shows handshake / session establishment
# milestones — vital when the test fails in CI.
ip netns exec "$NS_A" env RUST_LOG=norn_rs=info "$NORND" -c "$WORK/a/norn.toml" >"$WORK/a/log" 2>&1 &
PID_A=$!
ip netns exec "$NS_B" env RUST_LOG=norn_rs=info "$NORND" -c "$WORK/b/norn.toml" >"$WORK/b/log" 2>&1 &
PID_B=$!

echo "PID_A=$PID_A  PID_B=$PID_B"

# Wait for handshake + peer establishment.
# PQ-hybrid handshake adds ~80μs but the bigger cost is the cuckoo-filter
# gossip propagation (needs ≥ 2 maintenance ticks @ 1 Hz) before write_to
# can resolve the destination's routing tag. 15s gives comfortable margin.
sleep 15

# ── verify ────────────────────────────────────────────────────────────────
get_addr() {
    "$NORND" -c "$1" showaddr | awk '/^address:/ {print $2}'
}

ADDR_A=$(get_addr "$WORK/a/norn.toml")
ADDR_B=$(get_addr "$WORK/b/norn.toml")
echo "ADDR_A=$ADDR_A"
echo "ADDR_B=$ADDR_B"

# Check that nornd is still alive in each ns.
if ! kill -0 "$PID_A"; then
    echo "FAIL: nornd in $NS_A exited; log:"; cat "$WORK/a/log"; exit 1
fi
if ! kill -0 "$PID_B"; then
    echo "FAIL: nornd in $NS_B exited; log:"; cat "$WORK/b/log"; exit 1
fi

# Verify the TUN device exists in each namespace.
ip netns exec "$NS_A" ip link show norn0 >/dev/null \
    || { echo "FAIL: norn0 missing in $NS_A"; cat "$WORK/a/log"; exit 1; }
ip netns exec "$NS_B" ip link show norn0 >/dev/null \
    || { echo "FAIL: norn0 missing in $NS_B"; cat "$WORK/b/log"; exit 1; }

# Ping from A's TUN address to B's TUN address over the overlay.
# This exercises: TUN read → session encrypt → TCP send → underlay route →
# remote TCP recv → session decrypt → TUN write → kernel ICMPv6.
echo "── ping A -> B over overlay ──"
if ! ip netns exec "$NS_A" ping6 -c 3 -W 5 "$ADDR_B"; then
    echo "FAIL: overlay ping A→B failed"
    echo "── log A ──"; cat "$WORK/a/log"
    echo "── log B ──"; cat "$WORK/b/log"
    exit 1
fi

echo "── ping B -> A over overlay ──"
if ! ip netns exec "$NS_B" ping6 -c 3 -W 5 "$ADDR_A"; then
    echo "FAIL: overlay ping B→A failed"
    echo "── log A ──"; cat "$WORK/a/log"
    echo "── log B ──"; cat "$WORK/b/log"
    exit 1
fi

echo "── OK ──"
exit 0
