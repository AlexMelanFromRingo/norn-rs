//! Prometheus-format /metrics HTTP endpoint.
//!
//! A deliberately minimal HTTP/1.1 responder (no axum/hyper) bound to a
//! configurable address. On any GET it returns the Prometheus text
//! exposition format with our peer / session / queue metrics. Scrape with
//! a standard Prometheus server.
//!
//! Privacy: peer pub_keys are exposed as labels. Scrapers and the metrics
//! port itself should therefore be considered as-sensitive-as the admin
//! socket. Default bind is loopback only.

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::router::PacketConn;

/// Start the metrics HTTP server. Binds to `addr` (e.g. "127.0.0.1:9090")
/// and serves Prometheus exposition on every GET (regardless of path).
pub async fn listen(addr: &str, conn: Arc<PacketConn>) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding metrics HTTP on {}", addr))?;
    info!("metrics endpoint on http://{}/metrics", addr);
    let started = Instant::now();

    loop {
        let (mut sock, _peer) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => { warn!("metrics accept: {}", e); continue; }
        };
        let conn = conn.clone();
        tokio::spawn(async move {
            // Read at most a small fixed amount of request bytes — we don't
            // parse beyond the first line, we just want to drain a typical
            // GET request header before writing the body.
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let body = render(&conn, started);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body,
            );
            if let Err(e) = sock.write_all(resp.as_bytes()).await {
                debug!("metrics write: {}", e);
            }
            let _ = sock.shutdown().await;
        });
    }
}

/// Render the Prometheus exposition body. Public so the binary, tests, and
/// alternative transports can reuse it.
pub fn render(conn: &PacketConn, started: Instant) -> String {
    let uptime = started.elapsed().as_secs_f64();
    let peers = conn.get_peer_stats();
    let mut out = String::with_capacity(1024 + peers.len() * 256);

    // # HELP and # TYPE per metric (Prometheus requires these only once
    // per metric name across the exposition).
    // Self-identification: a single label-only sample so a scraper can
    // map (host: norn-NN) → ed25519 pub_key without an extra admin call.
    // Critical for the network-graph renderer that has to join per-node
    // metric labels (peer="hex...") back to a host name.
    out.push_str("# HELP norn_self_pub_key This node's ed25519 public key (label only).\n");
    out.push_str("# TYPE norn_self_pub_key gauge\n");
    out.push_str(&format!(
        "norn_self_pub_key{{pub_key=\"{}\"}} 1\n",
        hex::encode(conn.pub_key),
    ));

    out.push_str("# HELP norn_uptime_seconds Time since the daemon started.\n");
    out.push_str("# TYPE norn_uptime_seconds gauge\n");
    out.push_str(&format!("norn_uptime_seconds {:.3}\n", uptime));

    out.push_str("# HELP norn_peers_total Number of currently-connected peers.\n");
    out.push_str("# TYPE norn_peers_total gauge\n");
    out.push_str(&format!("norn_peers_total {}\n", peers.len()));

    out.push_str("# HELP norn_peer_rx_bytes_total Cumulative bytes received from this peer.\n");
    out.push_str("# TYPE norn_peer_rx_bytes_total counter\n");
    for p in &peers {
        let pk = hex::encode(p.key);
        out.push_str(&format!("norn_peer_rx_bytes_total{{peer=\"{}\"}} {}\n", pk, p.rx_bytes));
    }

    out.push_str("# HELP norn_peer_tx_bytes_total Cumulative bytes sent to this peer.\n");
    out.push_str("# TYPE norn_peer_tx_bytes_total counter\n");
    for p in &peers {
        let pk = hex::encode(p.key);
        out.push_str(&format!("norn_peer_tx_bytes_total{{peer=\"{}\"}} {}\n", pk, p.tx_bytes));
    }

    out.push_str("# HELP norn_peer_lag_seconds EWMA round-trip lag to this peer.\n");
    out.push_str("# TYPE norn_peer_lag_seconds gauge\n");
    for p in &peers {
        let pk = hex::encode(p.key);
        out.push_str(&format!(
            "norn_peer_lag_seconds{{peer=\"{}\"}} {:.6}\n", pk, p.lag.as_secs_f64()));
    }

    out.push_str("# HELP norn_peer_jitter_seconds EWMA jitter of the RTT to this peer.\n");
    out.push_str("# TYPE norn_peer_jitter_seconds gauge\n");
    for p in &peers {
        let pk = hex::encode(p.key);
        out.push_str(&format!(
            "norn_peer_jitter_seconds{{peer=\"{}\"}} {:.6}\n", pk, p.jitter.as_secs_f64()));
    }

    out.push_str("# HELP norn_peer_loss_rate Estimated packet loss rate (0..1) to this peer.\n");
    out.push_str("# TYPE norn_peer_loss_rate gauge\n");
    for p in &peers {
        let pk = hex::encode(p.key);
        out.push_str(&format!("norn_peer_loss_rate{{peer=\"{}\"}} {:.4}\n", pk, p.loss_rate));
    }

    out.push_str("# HELP norn_peer_trust Per-peer trust score; lower = de-prioritised in routing.\n");
    out.push_str("# TYPE norn_peer_trust gauge\n");
    for p in &peers {
        let pk = hex::encode(p.key);
        out.push_str(&format!("norn_peer_trust{{peer=\"{}\"}} {:.4}\n", pk, p.trust));
    }

    out.push_str("# HELP norn_peer_uptime_seconds How long this peer has been connected.\n");
    out.push_str("# TYPE norn_peer_uptime_seconds gauge\n");
    for p in &peers {
        let pk = hex::encode(p.key);
        out.push_str(&format!(
            "norn_peer_uptime_seconds{{peer=\"{}\"}} {:.3}\n", pk, p.uptime.as_secs_f64()));
    }

    // Observability for the mutex-poison recovery path. Any non-zero value
    // here means a thread panicked while holding a router lock and we
    // recovered into possibly-inconsistent state — operators should alert.
    out.push_str("# HELP norn_mutex_poison_total \
                  Times a poisoned router/session mutex was silently recovered. \
                  Non-zero values indicate a panic-while-holding-lock incident; \
                  protected state may be inconsistent and should be investigated.\n");
    out.push_str("# TYPE norn_mutex_poison_total counter\n");
    out.push_str(&format!("norn_mutex_poison_total {}\n", crate::router::mutex_poison_count()));

    // ── Roadmap #9: adaptive control-plane cadence ────────────────────────
    // broadcasts = ANNOUNCE+CoordAnnounce floods actually sent; suppressed =
    // maintenance ticks the adaptive cadence skipped because the topology
    // was unchanged. A high suppressed:broadcasts ratio is the chatter the
    // adaptive cadence saved versus the old send-every-tick behaviour.
    let (ctrl_sent, ctrl_suppressed) = crate::router::control_broadcast_counts();
    out.push_str("# HELP norn_control_broadcasts_total \
                  Periodic control broadcasts (ANNOUNCE + CoordAnnounce) actually sent.\n");
    out.push_str("# TYPE norn_control_broadcasts_total counter\n");
    out.push_str(&format!("norn_control_broadcasts_total {ctrl_sent}\n"));
    out.push_str("# HELP norn_control_suppressed_total \
                  Maintenance ticks where the control broadcast was skipped \
                  by the adaptive cadence (roadmap #9).\n");
    out.push_str("# TYPE norn_control_suppressed_total counter\n");
    out.push_str(&format!("norn_control_suppressed_total {ctrl_suppressed}\n"));

    // Convergence instrumentation (B-step-3 §5). On a SETTLED topology
    // parent-changes must stop climbing — continued growth = parent flapping.
    let (parent_changes, no_route) = crate::router::convergence_counts();
    out.push_str("# HELP norn_tree_parent_changes_total \
                  Spanning-tree parent-pointer switches in fix_tree. Continued \
                  growth on a settled topology indicates parent flapping.\n");
    out.push_str("# TYPE norn_tree_parent_changes_total counter\n");
    out.push_str(&format!("norn_tree_parent_changes_total {parent_changes}\n"));
    out.push_str("# HELP norn_cuckoo_no_route_total \
                  Transit packets with no route (cuckoo miss / transient hole).\n");
    out.push_str("# TYPE norn_cuckoo_no_route_total counter\n");
    out.push_str(&format!("norn_cuckoo_no_route_total {no_route}\n"));

    // Phase 1/2: how load-bearing hyperbolic greedy actually is for transit —
    // greedy (by stamped dest_coord) vs cuckoo fallback (no coord / local min).
    let (transit_greedy, transit_cuckoo) = crate::router::transit_path_counts();
    out.push_str("# HELP norn_transit_greedy_total \
                  Transit packets forwarded by hyperbolic greedy (dest_coord).\n");
    out.push_str("# TYPE norn_transit_greedy_total counter\n");
    out.push_str(&format!("norn_transit_greedy_total {transit_greedy}\n"));
    out.push_str("# HELP norn_transit_cuckoo_total \
                  Transit packets forwarded by cuckoo fallback (no coord / local min).\n");
    out.push_str("# TYPE norn_transit_cuckoo_total counter\n");
    out.push_str(&format!("norn_transit_cuckoo_total {transit_cuckoo}\n"));

    // Per-message-type egress byte accounting — answers "where does the
    // gossip bandwidth go?" (cuckoo vs reputation vs pathfind vs coord …).
    out.push_str("# HELP norn_tx_bytes_by_type Bytes sent to peers, by frame type.\n");
    out.push_str("# TYPE norn_tx_bytes_by_type counter\n");
    for (ty, bytes) in crate::router::tx_bytes_by_type() {
        out.push_str(&format!("norn_tx_bytes_by_type{{type=\"{ty}\"}} {bytes}\n"));
    }

    // ── Per-tree spanning-tree state ──────────────────────────────────────
    // Three labelled gauges per K=3 trees — enough for a cluster-wide
    // scraper to reconstruct each tree:
    //   norn_tree_root{tree, root}     1   — this node currently has `root`
    //                                         as the candidate root of tree.
    //   norn_tree_parent{tree, parent} 1   — direct parent edge; absent
    //                                         when we ARE the root.
    //   norn_tree_depth{tree}          N   — hop count to root (tree 0 only;
    //                                         other trees report 0 today).
    let trees = conn.get_tree_state();
    out.push_str("# HELP norn_tree_root Current root pub_key for this tree (1 = this node's view).\n");
    out.push_str("# TYPE norn_tree_root gauge\n");
    for t in &trees {
        out.push_str(&format!(
            "norn_tree_root{{tree=\"{}\",root=\"{}\"}} 1\n",
            t.tree_id, hex::encode(t.root),
        ));
    }
    out.push_str("# HELP norn_tree_parent Direct parent pub_key in this tree (1 sample = one outgoing edge).\n");
    out.push_str("# TYPE norn_tree_parent gauge\n");
    for t in &trees {
        if let Some(parent) = t.parent {
            out.push_str(&format!(
                "norn_tree_parent{{tree=\"{}\",parent=\"{}\"}} 1\n",
                t.tree_id, hex::encode(parent),
            ));
        }
    }
    out.push_str("# HELP norn_tree_depth Hop count from this node to its tree's root.\n");
    out.push_str("# TYPE norn_tree_depth gauge\n");
    for t in &trees {
        out.push_str(&format!(
            "norn_tree_depth{{tree=\"{}\"}} {}\n",
            t.tree_id, t.depth,
        ));
    }
    out.push_str("# HELP norn_tree_parent_cost Loss-adjusted cost of the parent edge.\n");
    out.push_str("# TYPE norn_tree_parent_cost gauge\n");
    for t in &trees {
        out.push_str(&format!(
            "norn_tree_parent_cost{{tree=\"{}\"}} {}\n",
            t.tree_id, t.parent_cost,
        ));
    }
    out.push_str("# HELP norn_tree_is_root 1 if this node is the current root of the tree.\n");
    out.push_str("# TYPE norn_tree_is_root gauge\n");
    for t in &trees {
        out.push_str(&format!(
            "norn_tree_is_root{{tree=\"{}\"}} {}\n",
            t.tree_id, if t.is_root { 1 } else { 0 },
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn render_contains_required_help_and_type() {
        let sk = SigningKey::generate(&mut OsRng);
        let conn = Arc::new(PacketConn::new(sk));
        let started = Instant::now();
        let body = render(&conn, started);
        // Prometheus parsers require HELP and TYPE before the first sample of
        // any metric name. Pin a couple to catch accidental removal.
        assert!(body.contains("# HELP norn_uptime_seconds"),
            "exposition must include HELP for norn_uptime_seconds");
        assert!(body.contains("# TYPE norn_uptime_seconds gauge"));
        assert!(body.contains("# HELP norn_peers_total"));
        assert!(body.contains("# TYPE norn_peers_total gauge"));
    }

    #[tokio::test]
    async fn render_uptime_is_nonnegative_and_grows() {
        let sk = SigningKey::generate(&mut OsRng);
        let conn = Arc::new(PacketConn::new(sk));
        let started = Instant::now()
            .checked_sub(std::time::Duration::from_secs(60))
            .expect("subtract 60s from now must succeed");
        let body = render(&conn, started);
        // norn_uptime_seconds X — extract X.
        let line = body.lines()
            .find(|l| l.starts_with("norn_uptime_seconds "))
            .expect("uptime line present");
        let val: f64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
        assert!(val >= 60.0, "uptime must reflect started=Instant 60s ago; got {}", val);
    }

    #[tokio::test]
    async fn http_endpoint_serves_exposition() {
        // End-to-end smoke test: bind on a free port, GET /, parse the response.
        let sk = SigningKey::generate(&mut OsRng);
        let conn = Arc::new(PacketConn::new(sk));
        // Bind to 127.0.0.1:0 — kernel picks a free port. We then need to
        // discover that port; the simplest path is to bind ourselves
        // (instead of via `listen()`), get the local_addr, and accept once.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let started = Instant::now();
        let conn_for_server = conn.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let body = render(&conn_for_server, started);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body,
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.shutdown().await.ok();
        });

        // Client: connect and read full response.
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf);

        assert!(resp.starts_with("HTTP/1.1 200"),
            "expected 200 OK response; got: {}", &resp[..resp.len().min(80)]);
        assert!(resp.contains("# TYPE norn_uptime_seconds gauge"),
            "expected Prometheus type header in body");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn render_exposes_tree_state_for_all_k_trees() {
        // K=3 spanning trees → every tree-state metric should appear with
        // tree="0", tree="1", tree="2". Critical for the cluster-graph
        // visualiser that reconstructs the global topology from /metrics.
        let sk = SigningKey::generate(&mut OsRng);
        let conn = Arc::new(PacketConn::new(sk));
        let body = render(&conn, Instant::now());
        assert!(body.contains("# TYPE norn_tree_root gauge"));
        assert!(body.contains("# TYPE norn_tree_depth gauge"));
        for t in 0..3 {
            assert!(
                body.contains(&format!("norn_tree_depth{{tree=\"{}\"}}", t)),
                "must expose depth for tree {}", t,
            );
            assert!(
                body.contains(&format!("norn_tree_root{{tree=\"{}\",root=", t)),
                "must expose root for tree {}", t,
            );
        }
    }

    #[tokio::test]
    async fn render_exposes_self_pub_key() {
        // The graph renderer joins (host → pub_key) on this label.
        let sk = SigningKey::generate(&mut OsRng);
        let conn = Arc::new(PacketConn::new(sk));
        let body = render(&conn, Instant::now());
        assert!(body.contains("# TYPE norn_self_pub_key gauge"));
        assert!(body.contains("norn_self_pub_key{pub_key=\""));
    }

    #[tokio::test]
    async fn render_exposes_mutex_poison_counter() {
        // The exposition MUST include the counter — operators rely on it to
        // alert on inconsistent router state after a panic-while-holding-lock.
        let sk = SigningKey::generate(&mut OsRng);
        let conn = Arc::new(PacketConn::new(sk));
        let body = render(&conn, Instant::now());
        assert!(body.contains("# TYPE norn_mutex_poison_total counter"),
            "mutex poison counter must be exposed as a Prometheus counter");
        assert!(body.contains("norn_mutex_poison_total "),
            "counter sample line must be present");
    }

    #[tokio::test]
    async fn render_no_peers_is_well_formed() {
        let sk = SigningKey::generate(&mut OsRng);
        let conn = Arc::new(PacketConn::new(sk));
        let started = Instant::now();
        let body = render(&conn, started);
        // With no peers, per-peer metrics should have HELP/TYPE headers but
        // no sample lines — that's still valid exposition format.
        assert!(body.contains("norn_peers_total 0"),
            "0 peers must render as norn_peers_total 0");
        // The HELP/TYPE for per-peer metrics should still be present even
        // with zero samples.
        assert!(body.contains("# TYPE norn_peer_rx_bytes_total counter"));
    }
}
