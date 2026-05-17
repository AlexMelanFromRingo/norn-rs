#!/usr/bin/env python3
"""
Render the live mesh as a graph + per-tree spanning-tree overlays.

Inputs:
  tests/cluster/out/metrics.csv  — scraped via run.sh
  tests/cluster/pub_keys.json    — host→pub_key map written by topology.py

Outputs into docs/cluster/:
  network.svg       — physical TCP-link mesh (every observed peer edge)
  tree_urd.svg      — spanning tree 0
  tree_verdandi.svg — spanning tree 1
  tree_skuld.svg    — spanning tree 2
  tree_balance.svg  — fan-out histogram per tree root

Requires matplotlib + networkx (auto-installed by run.sh on demand).
"""

from __future__ import annotations
import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import networkx as nx
except ImportError as e:
    sys.exit(f"missing dep: {e}. Run: pip install matplotlib networkx")


HERE = Path(__file__).resolve().parent
DEFAULT_CSV = HERE / "out" / "metrics.csv"
PUBS_PATH = HERE / "pub_keys.json"
OUT_DIR = HERE.parent.parent / "docs" / "cluster"

TREE_NAMES = {0: "Urd", 1: "Verdandi", 2: "Skuld"}


def load_csv_last_value(csv_path: Path) -> dict:
    """For each (metric, host, peer_label) take the LAST observed value.
    The graph reflects the steady-state at scrape-end. Returns a dict
    keyed by (metric, host, peer_label) → (timestamp, value)."""
    out: dict[tuple, tuple[float, float]] = {}
    with csv_path.open() as f:
        for row in csv.DictReader(f):
            try:
                t = float(row["timestamp_s"])
                v = float(row["value"])
            except (KeyError, ValueError):
                continue
            k = (row["metric"], row["node"], row["peer"])
            cur = out.get(k)
            if cur is None or t > cur[0]:
                out[k] = (t, v)
    return out


def load_labelled_facts(csv_path: Path) -> dict:
    """For metrics where the LABEL VALUE is itself the data (e.g.
    norn_self_pub_key{pub_key="..."} 1), return {(metric, host): label_value}.
    We scan the raw CSV `peer` column AND the label key extracted from
    a re-parse of the original metric line — see how scraper.py writes
    the row (peer="..." pulled out as 4th column)."""
    # The scraper stores ONE label per row: it picks `labels.get("peer", "")`.
    # For norn_self_pub_key the relevant label is `pub_key`, not `peer`, so
    # it ends up in the `peer` column with value `""` and the pub_key label
    # is LOST in scraper.py's current schema. We need a richer scraper or
    # extra parsing — see scraper-mod note in run.sh.
    return {}


def host_to_pub_mapping_from_metrics(csv_path: Path) -> dict[str, str]:
    """Re-parse the CSV: norn_self_pub_key has its hex in the peer column
    only if scraper.py was patched to surface arbitrary labels. With the
    current scraper, that mapping is empty, so we fall back to pub_keys.json
    which is the canonical source written at topology generation time."""
    return {}


def derive_host_to_pub(csv_path: Path, pubs_meta: dict) -> dict[str, str]:
    """Final mapping host → 64-char hex pub_key.

    Strategy:
      1. Read pub_keys.json — authoritative for the SCHEDULED layout.
      2. Cross-check with scraper data if possible.
    """
    # pubs_meta = {"pub_keys": {"n00": "<hex>", ...}, "malicious": [0,...]}
    keys = pubs_meta.get("pub_keys", pubs_meta)
    return {f"norn-{int(k.lstrip('n')):02d}": v for k, v in keys.items()}


def build_physical_graph(last_vals: dict, host_to_pub: dict[str, str]) -> nx.Graph:
    """Build the physical mesh graph from rx_bytes/tx_bytes per-peer
    metrics. An edge exists whenever node X observed peer Y at any
    point during the run."""
    g = nx.Graph()
    g.add_nodes_from(host_to_pub.keys())
    pub_to_host = {p: h for h, p in host_to_pub.items()}
    for (metric, host, peer), (_, _val) in last_vals.items():
        if metric != "norn_peer_rx_bytes_total" or not peer:
            continue
        other = pub_to_host.get(peer)
        if other and other != host:
            g.add_edge(host, other)
    return g


def build_tree_graph(last_vals: dict, tree_id: int, host_to_pub: dict[str, str]) -> nx.DiGraph:
    """Build directed tree (child → parent) for one spanning tree."""
    g = nx.DiGraph()
    g.add_nodes_from(host_to_pub.keys())
    pub_to_host = {p: h for h, p in host_to_pub.items()}
    # Each node has at most one parent in each tree. Find it.
    for (metric, host, peer), (_, _val) in last_vals.items():
        if metric != "norn_tree_parent" or not peer:
            continue
        # The scraper writes `peer="..."` for any label whose KEY is `peer`,
        # but for norn_tree_parent the key is `parent`. Until scraper.py is
        # extended to forward arbitrary labels, this mapping comes up empty
        # — fall back below.
        parent_host = pub_to_host.get(peer)
        if parent_host and parent_host != host:
            g.add_edge(host, parent_host, tree=tree_id)
    return g


# ── scraper-output schema is too lossy: only one label per row ────────
# Workaround: re-parse the raw CSV row from a SECOND pass that knows the
# label names for the structural metrics. We bypass the CSV reader and
# parse the metric line as text. Sadly the CSV doesn't preserve the raw
# label key, so for norn_tree_parent etc. we need richer scraper output
# OR we re-extract from the live containers. The lower-friction path is
# to teach scraper.py to surface ANY label (see scrape_with_full_labels).
# This file uses pub_keys.json for the static layout (always works) and
# pulls live tree state from a JSON dump written by run.sh on teardown
# (see tests/cluster/run.sh).


def load_tree_snapshot(snapshot_path: Path) -> dict[str, dict[int, str | None]]:
    """Returns {host: {tree_id: parent_pub_hex_or_None}}."""
    if not snapshot_path.exists():
        return {}
    return json.loads(snapshot_path.read_text())


def build_tree_graph_from_snapshot(
    tree_id: int,
    snapshot: dict[str, dict],
    host_to_pub: dict[str, str],
) -> tuple[nx.DiGraph, str | None]:
    """Live tree graph. Returns (digraph, root_host_or_None)."""
    g = nx.DiGraph()
    pub_to_host = {p: h for h, p in host_to_pub.items()}
    g.add_nodes_from(host_to_pub.keys())
    root_host: str | None = None
    for host, trees in snapshot.items():
        info = trees.get(str(tree_id)) or trees.get(tree_id)
        if not info:
            continue
        parent_pub = info.get("parent")
        if parent_pub:
            parent_host = pub_to_host.get(parent_pub)
            if parent_host:
                g.add_edge(host, parent_host, tree=tree_id)
        if info.get("is_root"):
            root_host = host
    return g, root_host


def draw_physical_mesh(g: nx.Graph, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(10, 10))
    pos = nx.spring_layout(g, seed=42, k=0.6)
    degrees = dict(g.degree())
    sizes = [40 + 14 * degrees.get(n, 0) for n in g.nodes()]
    nx.draw_networkx_edges(g, pos, ax=ax, alpha=0.35, width=0.6)
    nx.draw_networkx_nodes(g, pos, ax=ax, node_size=sizes,
                           node_color="steelblue", alpha=0.85, linewidths=0)
    if len(g.nodes()) <= 40:
        nx.draw_networkx_labels(g, pos, ax=ax, font_size=7)
    ax.set_title(f"Physical mesh — {g.number_of_nodes()} nodes, "
                 f"{g.number_of_edges()} edges (steady state)")
    ax.set_axis_off()
    fig.tight_layout()
    fig.savefig(out, format="svg")
    plt.close(fig)
    print(f"  wrote {out}")


def draw_tree(g: nx.DiGraph, root_host: str | None, tree_id: int, out: Path) -> None:
    if g.number_of_edges() == 0:
        print(f"  skipping {out.name} — tree {tree_id} has no edges in snapshot")
        return
    fig, ax = plt.subplots(figsize=(11, 7))
    # Depth from root via reverse BFS (tree edges point child→parent).
    depths: dict[str, int] = {}
    if root_host is None:
        # Pick the node with no outgoing edges as root proxy.
        roots = [n for n in g.nodes() if g.out_degree(n) == 0 and g.in_degree(n) > 0]
        root_host = roots[0] if roots else next(iter(g.nodes()))
    depths[root_host] = 0
    frontier = [root_host]
    visited = {root_host}
    while frontier:
        nxt = []
        for u in frontier:
            for child, _ in g.in_edges(u):
                if child not in visited:
                    visited.add(child)
                    depths[child] = depths[u] + 1
                    nxt.append(child)
        frontier = nxt

    # Hierarchical layout: place nodes in horizontal rows by depth.
    levels = defaultdict(list)
    for n, d in depths.items():
        levels[d].append(n)
    pos = {}
    max_depth = max(depths.values()) if depths else 0
    for d, nodes in levels.items():
        nodes.sort()
        width = max(1, len(nodes))
        for i, n in enumerate(nodes):
            pos[n] = ((i + 0.5) / width, 1.0 - (d / (max_depth + 1)))
    # Orphans (never observed): cluster them at the bottom.
    orphans = [n for n in g.nodes() if n not in pos]
    for i, n in enumerate(orphans):
        pos[n] = (i / max(1, len(orphans)), -0.1)

    # Edges (child → parent)
    nx.draw_networkx_edges(g, pos, ax=ax, alpha=0.5, width=0.7,
                           arrows=True, arrowsize=6, arrowstyle="->")
    # Colour nodes by depth (root is darkest).
    colors = [depths.get(n, max_depth + 2) for n in g.nodes()]
    nx.draw_networkx_nodes(g, pos, ax=ax, node_size=70,
                           node_color=colors, cmap="viridis_r",
                           alpha=0.9, linewidths=0)
    # Mark root distinctly.
    nx.draw_networkx_nodes(g, pos, nodelist=[root_host], ax=ax,
                           node_size=200, node_color="crimson",
                           edgecolors="black", linewidths=1)
    if len(g.nodes()) <= 40:
        nx.draw_networkx_labels(g, pos, ax=ax, font_size=6)
    ax.set_title(f"Spanning tree {tree_id} ({TREE_NAMES.get(tree_id, '?')}) — "
                 f"root={root_host}, max-depth={max_depth}, "
                 f"reachable={len(depths)}/{g.number_of_nodes()}")
    ax.set_axis_off()
    fig.tight_layout()
    fig.savefig(out, format="svg")
    plt.close(fig)
    print(f"  wrote {out}")


def plot_tree_balance(snapshot: dict, host_to_pub: dict[str, str], out: Path) -> None:
    """Bar chart: per-tree root popularity. How many distinct nodes
    elect each root candidate? Ideal mesh has consensus on one root per
    tree (single tall bar per tree). Disagreement = active reconverge."""
    fig, axes = plt.subplots(1, 3, figsize=(13, 4), sharey=True)
    pub_to_host = {p: h for h, p in host_to_pub.items()}
    for tree_id in range(3):
        roots_seen: Counter = Counter()
        for host, trees in snapshot.items():
            info = trees.get(str(tree_id)) or trees.get(tree_id)
            if info and (root := info.get("root")):
                roots_seen[pub_to_host.get(root, root[:8])] += 1
        ax = axes[tree_id]
        if not roots_seen:
            ax.set_title(f"{TREE_NAMES.get(tree_id, '?')} — no data")
            continue
        labels, counts = zip(*roots_seen.most_common(10))
        ax.barh(labels, counts, color="steelblue", alpha=0.8)
        ax.set_title(f"{TREE_NAMES.get(tree_id, '?')} — "
                     f"{len(roots_seen)} candidate root(s)")
        ax.set_xlabel("votes")
        ax.invert_yaxis()
        ax.grid(True, axis="x", alpha=0.3)
    fig.suptitle("Per-tree root election consensus (one tall bar per tree = converged)")
    fig.tight_layout()
    fig.savefig(out, format="svg")
    plt.close(fig)
    print(f"  wrote {out}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    ap.add_argument("--snapshot", type=Path, default=HERE / "out" / "tree_snapshot.json",
                    help="JSON written by run.sh on teardown: {host: {tree_id: {root,parent,depth,is_root}}}")
    args = ap.parse_args()

    if not args.csv.exists():
        sys.exit(f"missing {args.csv} — run tests/cluster/run.sh first")
    if not PUBS_PATH.exists():
        sys.exit(f"missing {PUBS_PATH} — regenerate with topology.py")

    pubs_meta = json.loads(PUBS_PATH.read_text())
    host_to_pub = derive_host_to_pub(args.csv, pubs_meta)
    print(f"loaded {len(host_to_pub)} host→pub_key mappings")

    last_vals = load_csv_last_value(args.csv)
    g = build_physical_graph(last_vals, host_to_pub)
    print(f"physical mesh: {g.number_of_nodes()} nodes, "
          f"{g.number_of_edges()} edges (isolated={sum(1 for n in g.nodes() if g.degree(n)==0)})")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    draw_physical_mesh(g, OUT_DIR / "network.svg")

    snapshot = load_tree_snapshot(args.snapshot)
    if not snapshot:
        print(f"  no tree snapshot at {args.snapshot}; skipping tree plots")
        print(f"  (run.sh should write it on teardown — see snapshot_trees())")
        return 0
    print(f"loaded tree snapshot for {len(snapshot)} hosts")

    out_names = {0: "tree_urd.svg", 1: "tree_verdandi.svg", 2: "tree_skuld.svg"}
    for tree_id, fname in out_names.items():
        tg, root = build_tree_graph_from_snapshot(tree_id, snapshot, host_to_pub)
        draw_tree(tg, root, tree_id, OUT_DIR / fname)

    plot_tree_balance(snapshot, host_to_pub, OUT_DIR / "tree_balance.svg")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
