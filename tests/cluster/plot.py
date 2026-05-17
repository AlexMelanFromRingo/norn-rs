#!/usr/bin/env python3
"""
Build SVG plots from tests/cluster/out/metrics.csv.

Produces four artefacts in docs/cluster/:
  - convergence.svg    — peer-count per node over time
  - latency.svg        — per-peer EWMA lag over time
  - loss.svg           — per-peer loss-rate over time
  - trust.svg          — per-peer trust evolution

Uses matplotlib only (no networkx / pandas dep). If matplotlib is missing
the script tells you `pip install matplotlib` and exits 1.

Run: python3 tests/cluster/plot.py [--csv tests/cluster/out/metrics.csv]
"""

from __future__ import annotations
import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")  # no display required
    import matplotlib.pyplot as plt
except ImportError:
    print("matplotlib not installed. Run: pip install matplotlib", file=sys.stderr)
    sys.exit(1)


HERE = Path(__file__).resolve().parent
DEFAULT_CSV = HERE / "out" / "metrics.csv"
OUT_DIR = HERE.parent.parent / "docs" / "cluster"


def load(csv_path: Path) -> dict:
    """series[(metric, node, peer)] -> list[(t, value)]"""
    series: dict[tuple, list] = defaultdict(list)
    with csv_path.open() as f:
        for row in csv.DictReader(f):
            try:
                t = float(row["timestamp_s"])
                v = float(row["value"])
            except (KeyError, ValueError):
                continue
            series[(row["metric"], row["node"], row["peer"])].append((t, v))
    for k in series:
        series[k].sort(key=lambda p: p[0])
    return series


def plot_convergence(series: dict, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(9, 5))
    nodes = sorted({k[1] for k in series if k[0] == "norn_peers_total"})
    for node in nodes:
        pts = series.get(("norn_peers_total", node, ""), [])
        if not pts:
            continue
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        ax.plot(xs, ys, alpha=0.6, linewidth=1.2, label=node)
    ax.set_xlabel("time since cluster start (s)")
    ax.set_ylabel("connected peers")
    ax.set_title("Mesh convergence — peer count per node over time")
    ax.grid(True, alpha=0.3)
    if len(nodes) <= 12:
        ax.legend(loc="lower right", fontsize=7, ncol=2)
    fig.tight_layout()
    fig.savefig(out, format="svg")
    plt.close(fig)
    print(f"  wrote {out}")


def plot_per_peer(series: dict, metric: str, ylabel: str, title: str, out: Path) -> None:
    """Generic per-peer time-series renderer used by lag/loss/trust."""
    fig, ax = plt.subplots(figsize=(9, 5))
    # Group by (node, peer) — one line per link.
    keys = sorted(k for k in series if k[0] == metric and k[2])
    if not keys:
        print(f"  skipping {out.name} — no samples for {metric}")
        plt.close(fig)
        return
    for k in keys:
        pts = series[k]
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        ax.plot(xs, ys, alpha=0.25, linewidth=0.6, color="steelblue")
    ax.set_xlabel("time since cluster start (s)")
    ax.set_ylabel(ylabel)
    ax.set_title(f"{title} ({len(keys)} per-link series)")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out, format="svg")
    plt.close(fig)
    print(f"  wrote {out}")


def plot_cuckoo_storm(series: dict, out: Path) -> None:
    """Per-node TX-bytes rate over time. Spikes in the first ~minute
    reveal the cuckoo-filter gossip storm cost."""
    fig, ax = plt.subplots(figsize=(9, 5))
    nodes = sorted({k[1] for k in series if k[0] == "norn_peer_tx_bytes_total"})
    plotted = 0
    for node in nodes:
        # Sum tx_bytes across peers for this node over time.
        per_time: dict[float, float] = {}
        for k in series:
            if k[0] != "norn_peer_tx_bytes_total" or k[1] != node:
                continue
            for t, v in series[k]:
                per_time[t] = per_time.get(t, 0.0) + v
        if len(per_time) < 2:
            continue
        ts = sorted(per_time)
        # Per-second rate via finite difference on cumulative counter.
        xs, ys = [], []
        for i in range(1, len(ts)):
            dt = ts[i] - ts[i - 1]
            if dt <= 0:
                continue
            xs.append(ts[i])
            ys.append((per_time[ts[i]] - per_time[ts[i - 1]]) / dt)
        if xs:
            ax.plot(xs, ys, alpha=0.5, linewidth=0.8, label=node)
            plotted += 1
    ax.set_xlabel("time since cluster start (s)")
    ax.set_ylabel("TX bytes / s (sum over peers)")
    ax.set_title(f"Cuckoo / control-traffic storm — per-node egress rate ({plotted} nodes)")
    ax.grid(True, alpha=0.3)
    if plotted <= 12:
        ax.legend(loc="upper right", fontsize=7, ncol=2)
    fig.tight_layout()
    fig.savefig(out, format="svg")
    plt.close(fig)
    print(f"  wrote {out}")


def plot_convergence_time(series: dict, out: Path) -> None:
    """How long each node takes to reach its steady-state peer count.
    Convergence = time of FIRST sample at the final peer-count value."""
    fig, ax = plt.subplots(figsize=(9, 5))
    nodes = sorted({k[1] for k in series if k[0] == "norn_peers_total"})
    convergence: dict[str, float] = {}
    for node in nodes:
        pts = series.get(("norn_peers_total", node, ""), [])
        if not pts:
            continue
        final = pts[-1][1]
        # First time this node reached its final value.
        first_at_final = next((t for t, v in pts if v >= final), None)
        if first_at_final is not None:
            convergence[node] = first_at_final
    if not convergence:
        print(f"  skipping {out.name} — no peers data")
        plt.close(fig)
        return
    items = sorted(convergence.items(), key=lambda kv: kv[1])
    names = [k for k, _ in items]
    times = [v for _, v in items]
    ax.barh(names, times, color="seagreen", alpha=0.8)
    ax.set_xlabel("time to reach steady-state peer count (s)")
    ax.set_title(f"Tree convergence time — {len(items)} nodes, "
                 f"median {sorted(times)[len(times)//2]:.2f}s")
    ax.grid(True, axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out, format="svg")
    plt.close(fig)
    print(f"  wrote {out}")


def plot_malicious_trust(series: dict, out: Path, pubs_path: Path) -> None:
    """How fast did the mesh's trust score for the planted attacker(s) decay?
    One line per (observer, malicious_peer) — should collapse toward
    TRUST_MIN=0.01 within minutes if the system works."""
    if not pubs_path.exists():
        print(f"  skipping {out.name} — no {pubs_path.name}")
        return
    meta = __import__("json").loads(pubs_path.read_text())
    pubs = meta.get("pub_keys", meta)  # back-compat
    malicious = meta.get("malicious", [])
    if not malicious:
        print(f"  skipping {out.name} — no malicious nodes recorded")
        return
    mal_hex = {pubs[f"n{i:02d}"] for i in malicious}

    fig, ax = plt.subplots(figsize=(9, 5))
    # Find every trust series where the peer label IS a malicious pub.
    keys = [k for k in series
            if k[0] == "norn_peer_trust" and k[2] in mal_hex]
    if not keys:
        print(f"  skipping {out.name} — no trust observations of attacker yet")
        plt.close(fig)
        return
    for k in keys:
        pts = series[k]
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        ax.plot(xs, ys, alpha=0.45, linewidth=0.9, color="crimson")
    ax.axhline(0.01, color="black", linestyle=":", alpha=0.5,
               label="TRUST_MIN (0.01)")
    ax.axhline(1.0, color="black", linestyle="--", alpha=0.5,
               label="initial baseline (1.0)")
    ax.set_xlabel("time since cluster start (s)")
    ax.set_ylabel("trust score from observer → attacker")
    ax.set_title(f"Trust collapse against {len(malicious)} planted "
                 f"cuckoo-poisoner(s) — {len(keys)} observer/attacker pairs")
    ax.set_yscale("log")  # log y makes the collapse legible
    ax.legend(loc="lower left", fontsize=8)
    ax.grid(True, which="both", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out, format="svg")
    plt.close(fig)
    print(f"  wrote {out}")


def plot_poison(series: dict, out: Path) -> None:
    """Global mutex_poison_total per node over time — should be flat 0.
    Any nonzero value flags a panic-while-holding-lock incident."""
    fig, ax = plt.subplots(figsize=(9, 4))
    nodes = sorted({k[1] for k in series if k[0] == "norn_mutex_poison_total"})
    saw_nonzero = False
    for node in nodes:
        pts = series.get(("norn_mutex_poison_total", node, ""), [])
        if not pts:
            continue
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        if any(y > 0 for y in ys):
            saw_nonzero = True
        ax.plot(xs, ys, alpha=0.5, linewidth=0.8, label=node)
    ax.set_xlabel("time since cluster start (s)")
    ax.set_ylabel("norn_mutex_poison_total")
    suffix = " ⚠ NONZERO" if saw_nonzero else " (flat-0 = healthy)"
    ax.set_title(f"Mutex-poison recovery counter{suffix}")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out, format="svg")
    plt.close(fig)
    print(f"  wrote {out}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    args = ap.parse_args()

    if not args.csv.exists():
        print(f"missing {args.csv} — run tests/cluster/run.sh first", file=sys.stderr)
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    series = load(args.csv)
    if not series:
        print(f"{args.csv} parsed empty — scraper hit no metrics?", file=sys.stderr)
        return 1
    print(f"loaded {sum(len(v) for v in series.values())} samples "
          f"from {len(series)} distinct series")

    plot_convergence(series, OUT_DIR / "convergence.svg")
    plot_convergence_time(series, OUT_DIR / "convergence_time.svg")
    plot_per_peer(series, "norn_peer_lag_seconds",
                  "lag (s, EWMA)", "Per-peer latency over time",
                  OUT_DIR / "latency.svg")
    plot_per_peer(series, "norn_peer_loss_rate",
                  "loss rate (0..1)", "Per-peer estimated loss rate",
                  OUT_DIR / "loss.svg")
    plot_per_peer(series, "norn_peer_trust",
                  "trust score (0.01..4.0)", "Per-peer trust evolution",
                  OUT_DIR / "trust.svg")
    plot_cuckoo_storm(series, OUT_DIR / "cuckoo_storm.svg")
    plot_poison(series, OUT_DIR / "mutex_poison.svg")
    plot_malicious_trust(series, OUT_DIR / "malicious_trust.svg",
                         HERE / "pub_keys.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
