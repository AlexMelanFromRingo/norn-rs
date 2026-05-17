#!/bin/sh
#
# Test-node entrypoint. Sets up a NetEm qdisc on eth0 to imitate WAN
# physics, then execs nornd. NetEm requires CAP_NET_ADMIN — the compose
# file is expected to grant it.
#
# Env knobs (with sensible defaults):
#   NETEM_DELAY_MS   — base delay in ms (default: 50)
#   NETEM_JITTER_MS  — ± jitter around delay in ms (default: 10)
#   NETEM_LOSS_PCT   — uniform random loss in % (default: 2)
#   NETEM_DISABLE=1  — skip NetEm setup entirely (clean baseline runs)

set -e

if [ -z "${NETEM_DISABLE:-}" ]; then
    DELAY="${NETEM_DELAY_MS:-50}ms"
    JITTER="${NETEM_JITTER_MS:-10}ms"
    LOSS="${NETEM_LOSS_PCT:-2}%"
    # Apply on the docker-injected eth0. `add` fails idempotency-wise if a
    # qdisc already exists; we try `change` first, fall back to `add`.
    if ! tc qdisc change dev eth0 root netem \
            delay "$DELAY" "$JITTER" loss "$LOSS" 2>/dev/null; then
        if ! tc qdisc add dev eth0 root netem \
                delay "$DELAY" "$JITTER" loss "$LOSS" 2>/dev/null; then
            echo "WARN: failed to install NetEm qdisc — running without (no NET_ADMIN?)" >&2
        fi
    fi
    echo "NetEm: delay=$DELAY jitter=$JITTER loss=$LOSS" >&2
fi

exec /usr/local/bin/nornd "$@"
