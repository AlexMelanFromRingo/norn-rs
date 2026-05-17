#!/usr/bin/env python3
"""
Metrics scraper for the test cluster.

Runs INSIDE the cluster's docker network as a sidecar. Every --interval
seconds it hits http://norn-NN:9090/metrics on every node, parses the
Prometheus exposition, and appends one row per node per metric to a CSV
in --out-dir.

Output: out/metrics.csv with columns:
    timestamp_s, node, metric_name, peer_label, value

Where `peer_label` is the value of the `peer="..."` label (empty for
global metrics like norn_peers_total).

Pure stdlib — no extra Python deps to install inside the scraper image.
"""

from __future__ import annotations
import argparse
import csv
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

# Match Prometheus sample lines:  metric_name{labels} value
LINE_RE = re.compile(
    r"^(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)"
    r"(?:\{(?P<labels>[^}]*)\})?"
    r"\s+(?P<value>[+-]?[0-9.eE+-]+)\s*$"
)
LABEL_RE = re.compile(r'(\w+)="([^"]*)"')


def parse_exposition(body: str):
    """Yield (metric, labels_dict, value) for every sample line."""
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


def scrape_one(host: str, port: int, timeout: float = 2.0) -> str | None:
    url = f"http://{host}:{port}/metrics"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", type=int, required=True)
    ap.add_argument("--metrics-port", type=int, default=9090)
    ap.add_argument("--interval", type=float, default=1.0,
                    help="post-coldstart sample interval (s)")
    ap.add_argument("--coldstart-interval", type=float, default=0.2,
                    help="sample interval (s) for the first --coldstart-secs")
    ap.add_argument("--coldstart-secs", type=float, default=20.0,
                    help="duration of the high-rate coldstart window")
    ap.add_argument("--duration", type=float, default=120.0)
    ap.add_argument("--out-dir", default="./out")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "metrics.csv"

    # No initial wait: we want the cold-start dynamics (peer-discovery
    # storm, ML-KEM handshake load, cuckoo gossip bandwidth) on record.
    # Failed scrapes during the first second or two are fine — they just
    # produce no rows.
    print(f"[scraper] scraping {args.nodes} nodes — coldstart {args.coldstart_secs}s "
          f"@ {args.coldstart_interval}s, then {args.interval}s "
          f"for total {args.duration}s -> {csv_path}", flush=True)

    started = time.monotonic()
    with csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp_s", "node", "metric", "peer", "value"])
        next_tick = started
        last_log_sec = -1
        while True:
            now_mono = time.monotonic()
            elapsed = now_mono - started
            if elapsed >= args.duration:
                break
            wrote = 0
            for i in range(args.nodes):
                host = f"norn-{i:02d}"
                body = scrape_one(host, args.metrics_port)
                if body is None:
                    continue
                for name, labels, value in parse_exposition(body):
                    if not name.startswith("norn_"):
                        continue
                    w.writerow([
                        f"{elapsed:.3f}", host, name,
                        labels.get("peer", ""), value,
                    ])
                    wrote += 1
            f.flush()
            cur_sec = int(elapsed)
            if cur_sec != last_log_sec and cur_sec % 5 == 0:
                print(f"[scraper] t={elapsed:6.1f}s wrote={wrote}", flush=True)
                last_log_sec = cur_sec
            interval = (args.coldstart_interval
                        if elapsed < args.coldstart_secs
                        else args.interval)
            next_tick += interval
            sleep_for = max(0.0, next_tick - time.monotonic())
            time.sleep(sleep_for)
    print(f"[scraper] done -> {csv_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
