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
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def scrape_one(host: str, port: int, timeout: float = 1.5) -> str | None:
    # Host is already an IP at this point — see resolve_hosts() — so this
    # is a pure connect+GET with no DNS lookup in the hot path. At 300
    # nodes Docker's embedded DNS becomes the dominant cost otherwise.
    url = f"http://{host}:{port}/metrics"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
        return None


def resolve_hosts(names: list[str], retries: int = 30, delay: float = 1.0) -> dict[str, str]:
    """Resolve each name to an IP via getaddrinfo. Retries until every
    name resolves (docker bridge sometimes lags by a few seconds during
    cluster start). Returns name -> ip."""
    import socket
    ips: dict[str, str] = {}
    pending = list(names)
    for _ in range(retries):
        still: list[str] = []
        for n in pending:
            try:
                ip = socket.getaddrinfo(n, None)[0][4][0]
                ips[n] = ip
            except (socket.gaierror, OSError):
                still.append(n)
        pending = still
        if not pending:
            return ips
        time.sleep(delay)
    print(f"[scraper] WARN {len(pending)} hosts never resolved; proceeding with rest",
          flush=True)
    return ips


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

    # Parallel scraping: on a 300-node cluster sequential urlopen() takes
    # 15-30 s per cycle. We pre-resolve every hostname to its IP via
    # getaddrinfo (one-time cost) so the hot loop has no DNS overhead —
    # docker's embedded DNS becomes the bottleneck otherwise.
    names = [f"norn-{i:02d}" for i in range(args.nodes)]
    print(f"[scraper] resolving {args.nodes} hostnames...", flush=True)
    name_to_ip = resolve_hosts(names)
    hosts = list(name_to_ip.values())  # IPs only
    host_to_name = {ip: name for name, ip in name_to_ip.items()}
    print(f"[scraper] resolved {len(hosts)}/{args.nodes} hosts", flush=True)
    pool = ThreadPoolExecutor(max_workers=min(128, max(16, args.nodes)))

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
            futs = {
                pool.submit(scrape_one, h, args.metrics_port): h
                for h in hosts
            }
            for fut in as_completed(futs):
                body = fut.result()
                # Write the user-visible HOSTNAME, not the IP — plots
                # group by name and 172.18.0.NN doesn't sort intuitively.
                host = host_to_name.get(futs[fut], futs[fut])
                if body is None:
                    continue
                for name, labels, value in parse_exposition(body):
                    if not name.startswith("norn_"):
                        continue
                    w.writerow([
                        f"{elapsed:.3f}", host, name,
                        # The single distinguishing label: `peer=` for per-peer
                        # metrics, `type=` for norn_tx_bytes_by_type, etc.
                        labels.get("peer") or labels.get("type") or "", value,
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
    pool.shutdown(wait=False)
    print(f"[scraper] done -> {csv_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
