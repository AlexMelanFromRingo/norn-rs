#!/usr/bin/env python3
"""
Small-world topology generator for the test cluster.

Watts-Strogatz: each of N nodes has 2 ring-adjacent peers + 2 random
long-distance shortcut peers. Result: average path length ≈ log(N), with
plenty of FP-cuckoo and trust-ranking scenarios for the new architectural
hardening to exercise.

Outputs one TOML config per node into ./configs/n{i:02}.toml plus a
docker-compose.yml that wires them together on a single bridge network.

Run: python3 tests/cluster/topology.py
"""

from __future__ import annotations
import hashlib
import json
import os
import random
import secrets
import sys
from pathlib import Path

# We need ed25519 pub_key derivation in the topology generator so the
# test-traffic env var on each node can list every other node's pub_key
# by hex. Use cryptography lib if present; fall back to a tiny pure-Python
# Ed25519 SLOWLY (only 100×30 = 3000 derivations max, < 1 s on any CPU).
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives import serialization as _ser

    def derive_pub_hex(priv_hex: str) -> str:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
        raw = sk.public_key().public_bytes(
            encoding=_ser.Encoding.Raw,
            format=_ser.PublicFormat.Raw,
        )
        return raw.hex()
except ImportError:
    # Minimal fall-back: shell out to `nornctl showaddr`. Requires the
    # binary to be on PATH; emits a clearer error than the cryptography
    # ImportError if it's missing.
    import subprocess

    def derive_pub_hex(priv_hex: str) -> str:
        # We can ask nornd directly via genconfig + a tiny showaddr probe,
        # but the easiest path is `nornd showaddr -c <tmp>`. The build
        # script puts a fresh nornd binary at target/release/nornd.
        bin_path = Path(__file__).resolve().parents[2] / "target" / "release" / "nornd"
        if not bin_path.exists():
            raise SystemExit(
                "topology.py: no `cryptography` Python module and no "
                f"{bin_path}. Install cryptography or `cargo build --release`."
            )
        tmp = Path(__file__).resolve().parent / ".probe.toml"
        tmp.write_text(f'private_key = "{priv_hex}"\n')
        os.chmod(tmp, 0o600)
        out = subprocess.check_output([str(bin_path), "-c", str(tmp), "showaddr"], text=True)
        tmp.unlink(missing_ok=True)
        for line in out.splitlines():
            if line.startswith("pub_key:"):
                return line.split()[1]
        raise SystemExit("topology.py: failed to derive pub_key via nornd showaddr")

N_NODES = 100
# Indices that should run with NORN_MALICIOUS_MODE=cuckoo_poison.
# Set via env so a single topology.py can produce either an all-honest
# cluster (default) or one with planted attackers for the trust-ejection
# experiment.
MALICIOUS_NODES: set[int] = set(
    int(x) for x in os.environ.get("MALICIOUS_NODES", "").split(",") if x.strip().isdigit()
)
# Aim for a low-degree mesh that still routes interestingly.
# RING_DEGREE = 1 → 2 ring-adjacent peers per node (forward + back).
# SHORTCUT_DEGREE = 1 → 1 random long-distance peer per node (one direction;
# symmetry from other nodes' shortcuts adds ~1 more on average).
# Expected average degree ≈ 4, expected diameter ≈ log2(N) ≈ 4 hops.
RING_DEGREE = 1
SHORTCUT_DEGREE = 1
RNG_SEED = 0xC0FFEE      # deterministic for reproducible plots
BASE_TCP_PORT = 19001
METRICS_PORT = 9090

HERE = Path(__file__).resolve().parent
CONFIGS = HERE / "configs"
COMPOSE_PATH = HERE / "docker-compose.yml"


def gen_ed25519_priv_hex() -> str:
    """A 32-byte random seed; ed25519-dalek's SigningKey::from_bytes accepts this."""
    return secrets.token_hex(32)


def small_world_peers(n: int, ring: int, shortcuts: int, rng: random.Random) -> list[set[int]]:
    """Return adj[i] = set of node-indices i is wired to."""
    adj: list[set[int]] = [set() for _ in range(n)]
    # Ring
    for i in range(n):
        for k in range(1, ring + 1):
            j = (i + k) % n
            adj[i].add(j)
            adj[j].add(i)
    # Shortcuts (only added on the smaller-index side to avoid duplicates;
    # asymmetric wiring is fine because our transport's lex-dial guard makes
    # the smaller-pub side the canonical dialer anyway).
    for i in range(n):
        candidates = [j for j in range(n) if j != i and j not in adj[i]]
        rng.shuffle(candidates)
        for j in candidates[:shortcuts]:
            adj[i].add(j)
            adj[j].add(i)
    return adj


def write_configs(adj: list[set[int]], keys: list[str]) -> None:
    CONFIGS.mkdir(parents=True, exist_ok=True)
    for old in CONFIGS.glob("n*.toml"):
        old.unlink()
    for i in range(len(adj)):
        # A node dials only neighbours with HIGHER index — pairs with the
        # transport's lex-dial-priority tiebreak, gives deterministic
        # one-side-only dials, eliminates the simultaneous-dial race.
        dials = sorted(j for j in adj[i] if j > i)
        peers_lines = ", ".join(
            f'"tcp://norn-{j:02d}:{BASE_TCP_PORT}"' for j in dials
        )
        # In compose we expose nornd's TCP on a per-node host port
        # BASE_TCP_PORT+i so a host-side scraper can also poke if needed.
        cfg = f"""# Generated by tests/cluster/topology.py
private_key = "{keys[i]}"
listen      = ["tcp://0.0.0.0:{BASE_TCP_PORT}"]
peers       = [{peers_lines}]

# Test cluster runs overlay-only — no TUN, no kernel routing.
# All traffic flows through nornd's own session layer.
tun_name    = ""

admin_socket    = "/var/run/norn.sock"
peer_cache_path = ""

multicast_enabled = false
mdns_enabled      = false

# Bind the Prometheus /metrics endpoint on every interface so the
# scraper container can hit it.
metrics_addr      = "0.0.0.0:{METRICS_PORT}"

# Zero PoW: the test cluster is short-lived, every node is honest;
# Sybil resistance is exercised by dedicated unit tests.
min_peer_difficulty_bits = 0

log_level = "norn_rs=debug,info"
"""
        (CONFIGS / f"n{i:02d}.toml").write_text(cfg)


def write_compose(n: int, pubs: list[str]) -> None:
    """Emit docker-compose.yml: N nornd services + 1 scraper service.
    `pubs[i]` is node-i's ed25519 public key in hex; we inject it into
    each peer's traffic-generator env var so the routing layer actually
    sees overlay traffic (and hence exercises PathNegative + trust)."""
    services = []
    # Above ~64 nodes the per-service host port-map becomes noisy in `ss`
    # output and starts eating into the ephemeral-port pool. We expose
    # ports only for the FIRST 16 nodes so ad-hoc `curl 127.0.0.1:9090`
    # debugging still works from the host without flooding the host's
    # NAT table on big runs.
    expose_host_ports = n <= 32
    for i in range(n):
        # Pick a small set of distant traffic destinations so packets
        # have to multi-hop through the mesh. Picking far-away ring
        # indices guarantees the traffic crosses several intermediates.
        dest_idx = [(i + n // 3) % n, (i + 2 * n // 3) % n]
        dest_hex = ",".join(pubs[j] for j in dest_idx if j != i)
        ports_block = (
            f'    ports:\n      - "{METRICS_PORT + i}:{METRICS_PORT}"\n'
            if expose_host_ports else ""
        )
        # Conditional malicious-mode env. The honest path keeps env list
        # short so a quick grep over the compose file tells operators
        # exactly which nodes are planted attackers.
        malicious_env = ""
        if i in MALICIOUS_NODES:
            malicious_env = (
                "      - NORN_MALICIOUS_MODE=cuckoo_poison\n"
                "      - NORN_MALICIOUS_POISON_TAGS=64\n"
            )
        services.append(
            f"""  norn-{i:02d}:
    image: norn-testnode:latest
    container_name: norn-test-{i:02d}
    hostname: norn-{i:02d}
    networks:
      - mesh
    volumes:
      - ./configs/n{i:02d}.toml:/etc/norn/norn.toml:ro
{ports_block}
    # NET_ADMIN lets the entrypoint install a NetEm qdisc on eth0 so the
    # routing layer experiences realistic wide-area delay/jitter/loss
    # instead of docker bridge's idealised 0ms / 0% link.
    cap_add:
      - NET_ADMIN
    environment:
      # Each node sends a tiny payload to two distant peers every 500 ms
      # so the routing layer actually exercises forward + lookup_by_tag
      # + PathNegative backtrack + trust evolution. With overlay-only
      # nornd (TUN off) this is the ONLY traffic source available.
      - NORN_TEST_TRAFFIC_TO_HEX={dest_hex}
      - NORN_TEST_TRAFFIC_RATE_MS=500
      - NORN_TEST_TRAFFIC_PAYLOAD=64
{malicious_env}
    restart: "no"
    tmpfs:
      - /var/run:size=4M"""
        )
    services.append(
        f"""  scraper:
    image: python:3.12-slim
    container_name: norn-test-scraper
    networks:
      - mesh
    volumes:
      - ./scraper.py:/scraper.py:ro
      - ./out:/out
    # coldstart-interval+interval picked so a 64-thread pool comfortably
    # finishes a full N-node scrape inside the budget, even at N=300.
    command: ["python3", "/scraper.py", "--nodes", "{n}",
              "--coldstart-interval", "0.5", "--coldstart-secs", "20",
              "--interval", "2", "--duration", "120",
              "--metrics-port", "{METRICS_PORT}", "--out-dir", "/out"]
    depends_on: [{', '.join(f'norn-{i:02d}' for i in range(n))}]"""
    )
    compose = (
        "# Generated by tests/cluster/topology.py — DO NOT EDIT.\n"
        "services:\n"
        + "\n\n".join(services)
        + "\n\nnetworks:\n  mesh:\n    driver: bridge\n"
    )
    COMPOSE_PATH.write_text(compose)


def main() -> int:
    rng = random.Random(RNG_SEED)
    adj = small_world_peers(N_NODES, RING_DEGREE, SHORTCUT_DEGREE, rng)
    keys = [gen_ed25519_priv_hex() for _ in range(N_NODES)]
    pubs = [derive_pub_hex(k) for k in keys]
    # Persist pub_keys + malicious node list for postmortem analysis
    # tools (e.g. plot.py uses them to render the "trust against attacker"
    # plot).
    (HERE / "pub_keys.json").write_text(
        json.dumps(
            {
                "pub_keys": {f"n{i:02d}": pubs[i] for i in range(N_NODES)},
                "malicious": sorted(MALICIOUS_NODES),
            },
            indent=2,
        )
    )
    write_configs(adj, keys)
    write_compose(N_NODES, pubs)
    (HERE / "out").mkdir(exist_ok=True)
    # Lock down config perms (nornd refuses world-readable configs).
    for f in CONFIGS.glob("*.toml"):
        os.chmod(f, 0o600)
    print(f"OK: wrote {N_NODES} configs to {CONFIGS}/")
    print(f"OK: wrote {COMPOSE_PATH}")
    print(f"    average degree = {sum(len(a) for a in adj) / N_NODES:.1f}")
    print(f"    diameter:")
    # Quick BFS for diameter, just to give the operator a sanity number.
    from collections import deque
    longest = 0
    for src in range(N_NODES):
        dist = [-1] * N_NODES
        dist[src] = 0
        q = deque([src])
        while q:
            u = q.popleft()
            for v in adj[u]:
                if dist[v] < 0:
                    dist[v] = dist[u] + 1
                    q.append(v)
        longest = max(longest, max(dist))
    print(f"      {longest} hops (max shortest-path across all pairs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
