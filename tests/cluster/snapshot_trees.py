#!/usr/bin/env python3
"""
One-shot scraper that pulls per-tree state from every node's /metrics
endpoint and writes a JSON suitable for plot_graph.py.

Runs from the HOST (not inside the docker network) — uses container
IPs resolved via getaddrinfo against the docker bridge. Since we drop
ports: blocks past 32 nodes, the host can't reach metrics by 127.0.0.1
port mapping on big runs — we hit container IPs directly through the
docker bridge gateway.

Output JSON:
  {
    "norn-00": {
      "0": {"root": "<hex>", "parent": "<hex>|null", "depth": N, "is_root": bool},
      "1": {...},
      "2": {...}
    },
    ...
  }

Run from inside run.sh; the venv at tests/cluster/.venv supplies
matplotlib + networkx for downstream plot_graph.py.
"""

from __future__ import annotations
import argparse
import json
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

LINE_RE = re.compile(
    r"^(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)"
    r"(?:\{(?P<labels>[^}]*)\})?"
    r"\s+(?P<value>[+-]?[0-9.eE+-]+)\s*$"
)
LABEL_RE = re.compile(r'(\w+)="([^"]*)"')


def parse_samples(body: str):
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            continue
        labels = {}
        if m.group("labels"):
            for lm in LABEL_RE.finditer(m.group("labels")):
                labels[lm.group(1)] = lm.group(2)
        try:
            value = float(m.group("value"))
        except ValueError:
            continue
        yield m.group("name"), labels, value


def discover_container_ips(prefix: str = "norn-test-") -> dict[str, str]:
    """Map host name → bridge-network IP via `docker inspect`. Used so
    snapshot_trees can hit every container even when host port-mapping
    is disabled past 32 nodes."""
    try:
        out = subprocess.check_output(
            ["docker", "ps", "--format", "{{.Names}}"], text=True
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return {}
    ips: dict[str, str] = {}
    for name in out.strip().splitlines():
        if not name.startswith(prefix):
            continue
        try:
            ip = subprocess.check_output(
                ["docker", "inspect", "-f",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                 name],
                text=True,
            ).strip()
            if ip:
                # Convert "norn-test-NN" → "norn-NN" so the JSON keys match
                # the host names every other tool uses.
                short = name.replace("norn-test-", "norn-")
                ips[short] = ip
        except subprocess.CalledProcessError:
            continue
    return ips


def scrape_one(ip: str, port: int, timeout: float = 3.0) -> dict | None:
    """Pull /metrics from one container and extract this node's tree state.
    Returns {"0": {root, parent, depth, is_root}, "1": ..., "2": ...}
    or None on transport error."""
    try:
        with urllib.request.urlopen(f"http://{ip}:{port}/metrics", timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
        return None
    trees: dict[str, dict] = {"0": {}, "1": {}, "2": {}}
    for name, labels, value in parse_samples(body):
        tree = labels.get("tree")
        if name == "norn_tree_root" and tree in trees and labels.get("root"):
            trees[tree]["root"] = labels["root"]
        elif name == "norn_tree_parent" and tree in trees and labels.get("parent"):
            trees[tree]["parent"] = labels["parent"]
        elif name == "norn_tree_depth" and tree in trees:
            trees[tree]["depth"] = int(value)
        elif name == "norn_tree_is_root" and tree in trees:
            trees[tree]["is_root"] = bool(value)
    # Backfill defaults so downstream code can assume the keys exist.
    for t in trees.values():
        t.setdefault("parent", None)
        t.setdefault("root", None)
        t.setdefault("depth", 0)
        t.setdefault("is_root", False)
    return trees


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", type=int, required=True)
    ap.add_argument("--port", type=int, default=9090)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    print(f"[snapshot] discovering container IPs...", flush=True)
    ips = discover_container_ips()
    if not ips:
        print(f"[snapshot] no running 'norn-test-NN' containers — exiting", file=sys.stderr)
        return 1
    print(f"[snapshot] found {len(ips)} containers, scraping...", flush=True)

    snapshot: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=min(128, len(ips))) as pool:
        futs = {pool.submit(scrape_one, ip, args.port): host
                for host, ip in ips.items()}
        for fut in as_completed(futs):
            host = futs[fut]
            data = fut.result()
            if data is not None:
                snapshot[host] = data

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(snapshot, indent=2, sort_keys=True))
    print(f"[snapshot] wrote {len(snapshot)} node snapshots → {args.out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
