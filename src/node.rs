// Top-level Node — wires together PacketConn, transport, discovery, TUN, admin.

use anyhow::Result;
use std::sync::Arc;
use tracing::info;

use crate::config::NodeConfig;
use crate::router::PacketConn;
use crate::transport::ConnectedPeers;
use crate::tun::{new_key_store, SharedKeyStore};

pub struct Node {
    pub conn: Arc<PacketConn>,
    pub config: NodeConfig,
    pub key_store: SharedKeyStore,
    connected: ConnectedPeers,
}

impl Node {
    /// Create a new Node from config. Does NOT start any background tasks yet.
    // Skip mutations: spawns PacketConn (async runtime required), registers keys,
    // calls address_from_key — verifying these side effects requires a full async test.
    #[mutants::skip]
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let signing_key = config.signing_key()?;
        let conn = Arc::new(PacketConn::new(signing_key));

        // Apply Sybil-resistance threshold from config.
        conn.set_min_peer_difficulty_bits(config.min_peer_difficulty_bits);

        let key_store = new_key_store();
        // Register our own key so TUN knows our address
        key_store.lock().unwrap().register(conn.pub_key);

        let connected = Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));

        let addr = crate::address::address_from_key(&conn.pub_key);
        info!(
            "node started: pub_key={} address={}",
            hex::encode(conn.pub_key),
            ipv6_string(&addr)
        );

        Ok(Node { conn, config, key_store, connected })
    }

    /// Start all subsystems. Returns after spawning background tasks.
    // Skip mutations: spawns multiple tokio tasks (listener, discovery, admin, TUN) —
    // all mutations require a full integration test to observe.
    #[mutants::skip]
    pub async fn start(&self) -> Result<()> {
        let tcp_port = self.config.tcp_listen_port();

        // ── TCP listeners ────────────────────────────────────────────────
        for uri in &self.config.listen {
            let conn = self.conn.clone();
            let connected = self.connected.clone();
            let uri = uri.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::transport::listen(&uri, conn, connected).await {
                    tracing::error!("TCP listener {}: {}", uri, e);
                }
            });
        }

        // ── Static peers ─────────────────────────────────────────────────
        for uri in &self.config.peers {
            let conn = self.conn.clone();
            let connected = self.connected.clone();
            let uri = uri.clone();
            tokio::spawn(async move {
                crate::transport::dial(&uri, conn, connected).await;
            });
        }

        // ── Persistent known-peers cache ─────────────────────────────────
        // Read at startup, dial each URI alongside the static peers, and
        // dedupe naturally via the `connected` set inside transport::dial.
        // The cache is rewritten on a maintenance cadence by a background
        // task that observes get_peer_stats(). On restart the daemon picks
        // up where it left off, surviving DNS churn and accidental config
        // drift.
        if !self.config.peer_cache_path.is_empty() {
            let cache = crate::peercache::PeerCache::load(&self.config.peer_cache_path);
            let cached_count = cache.len();
            if cached_count > 0 {
                info!("seeded {} dial(s) from peer cache {:?}", cached_count, self.config.peer_cache_path);
            }
            for uri in cache.uris() {
                let conn = self.conn.clone();
                let connected = self.connected.clone();
                let uri = uri.to_string();
                tokio::spawn(async move {
                    crate::transport::dial(&uri, conn, connected).await;
                });
            }
        }

        // ── Multicast discovery ──────────────────────────────────────────
        if self.config.multicast_enabled {
            let conn = self.conn.clone();
            let connected = self.connected.clone();
            let port = self.config.multicast_port;
            tokio::spawn(async move {
                if let Err(e) = crate::discovery::start(conn, port, tcp_port, connected).await {
                    tracing::warn!("multicast discovery: {}", e);
                }
            });
        }

        // ── Admin socket ─────────────────────────────────────────────────
        {
            let conn = self.conn.clone();
            let connected = self.connected.clone();
            let path = self.config.admin_socket.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::admin::listen(&path, conn, connected).await {
                    tracing::warn!("admin socket: {}", e);
                }
            });
        }

        // ── Prometheus /metrics endpoint ─────────────────────────────────
        if !self.config.metrics_addr.is_empty() {
            let conn = self.conn.clone();
            let addr = self.config.metrics_addr.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::metrics::listen(&addr, conn).await {
                    tracing::warn!("metrics endpoint: {}", e);
                }
            });
        }

        // ── TUN adapter ──────────────────────────────────────────────────
        if let Some(ref tun_name) = self.config.tun_name {
            let conn = self.conn.clone();
            let ks = self.key_store.clone();
            let tun_name = tun_name.clone();
            if let Err(e) = crate::tun::start(&tun_name, conn, ks).await {
                tracing::warn!("TUN adapter not started: {}", e);
                tracing::warn!("Running without TUN — use addPeer via admin socket to route traffic.");
            }
        }

        Ok(())
    }

    /// Register a peer's pub key in the TUN key store (called by transport on connect).
    // Skip mutations: delegates to key_store.register — tested via KeyStore tests in tun.rs.
    #[mutants::skip]
    pub fn register_peer(&self, pub_key: [u8; 32]) {
        self.key_store.lock().unwrap().register(pub_key);
    }
}

fn ipv6_string(bytes: &[u8; 16]) -> String {
    use std::net::Ipv6Addr;
    let mut groups = [0u16; 8];
    for (i, chunk) in bytes.chunks(2).enumerate() {
        groups[i] = u16::from_be_bytes([chunk[0], chunk[1]]);
    }
    Ipv6Addr::new(
        groups[0], groups[1], groups[2], groups[3],
        groups[4], groups[5], groups[6], groups[7],
    ).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ipv6_string ───────────────────────────────────────────────────────────

    #[test]
    fn ipv6_string_loopback() {
        let mut bytes = [0u8; 16];
        bytes[15] = 1;
        assert_eq!(ipv6_string(&bytes), "::1",
            "loopback must format as ::1");
    }

    #[test]
    fn ipv6_string_all_zeros() {
        let bytes = [0u8; 16];
        assert_eq!(ipv6_string(&bytes), "::",
            "all-zero address must format as '::'");
    }

    #[test]
    fn ipv6_string_known_address() {
        // 0200::1
        let bytes: [u8; 16] = [
            0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        assert_eq!(ipv6_string(&bytes), "200::1",
            "known address must format as 200::1");
    }

    #[test]
    fn ipv6_string_non_empty_and_not_placeholder() {
        // Catches function-replacement mutations returning "" or "xyzzy"
        let bytes: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let s = ipv6_string(&bytes);
        assert!(!s.is_empty(), "must not return empty string");
        assert_ne!(s, "xyzzy", "must not return placeholder string");
        assert!(s.contains("2001"), "must contain address prefix; got {:?}", s);
    }
}
