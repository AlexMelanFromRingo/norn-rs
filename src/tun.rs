// TUN network interface adapter for norn-rs.
//
// Creates a TUN device (e.g. "norn0"), assigns the node's 0x02.../7 IPv6
// address, then bridges IPv6 packets between the kernel and PacketConn:
//
//   TUN → norn: read IPv6 packet, look up dest pub key, conn.write_to()
//   norn → TUN: conn.read_from(), write IPv6 packet to TUN
//
// Key store: maps 0x02.../7 IPv6 addresses to ed25519 pub keys.
// Populated automatically when peers connect (their address is derived
// deterministically from their pub key).
//
// Requires: Linux TUN/TAP support (CONFIG_TUN), root or CAP_NET_ADMIN.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

use crate::address::address_from_key;
use crate::router::PacketConn;

// ── KeyStore ─────────────────────────────────────────────────────────────

/// Maps 0x02.../7 IPv6 address → ed25519 pub key.
/// The reverse direction is always computable via address_from_key().
pub struct KeyStore {
    addr_to_key: HashMap<[u8; 16], [u8; 32]>,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore {
    pub fn new() -> Self {
        KeyStore { addr_to_key: HashMap::new() }
    }

    /// Register a pub key and its derived IPv6 address.
    pub fn register(&mut self, pub_key: [u8; 32]) -> [u8; 16] {
        let addr = address_from_key(&pub_key);
        self.addr_to_key.insert(addr, pub_key);
        addr
    }

    /// Look up the pub key for a given 0x02.../7 IPv6 address.
    pub fn key_for_addr(&self, addr: &[u8; 16]) -> Option<[u8; 32]> {
        self.addr_to_key.get(addr).copied()
    }
}

pub type SharedKeyStore = Arc<Mutex<KeyStore>>;

// Skip mutations: Default::default() for Arc<Mutex<KeyStore>> is equivalent
// (KeyStore::default() delegates to Self::new() which also returns an empty HashMap).
#[mutants::skip]
pub fn new_key_store() -> SharedKeyStore {
    Arc::new(Mutex::new(KeyStore::new()))
}

// ── TUN adapter ───────────────────────────────────────────────────────────

// Skip mutations: creates a real TUN device (requires CAP_NET_ADMIN), configures
// the interface, and runs an indefinite read/write loop — untestable in unit tests.
#[mutants::skip]
#[cfg(feature = "tun-support")]
pub async fn start(
    tun_name: &str,
    conn: Arc<PacketConn>,
    key_store: SharedKeyStore,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Register our own key so we know our own address
    let our_addr = key_store.lock().unwrap().register(conn.pub_key);
    let our_addr_str = ipv6_string(&our_addr);

    // Create TUN device
    let mut tun_config = tun2::Configuration::default();
    tun_config.tun_name(tun_name).mtu(65535_u16);
    let dev = tun2::create_as_async(&tun_config)
        .with_context(|| format!("creating TUN device '{}' (need CAP_NET_ADMIN or root)", tun_name))?;

    // Assign IPv6 address via `ip` command
    configure_interface(tun_name, &our_addr_str)?;
    info!("TUN interface {} up, address {}/7", tun_name, our_addr_str);

    let (mut tun_reader, mut tun_writer) = tokio::io::split(dev);

    // ── TUN → norn (outbound) ────────────────────────────────────────────
    let conn_out = conn.clone();
    let ks_out = key_store.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536 + 4]; // +4 for tun2 header on some platforms
        loop {
            let n = match tun_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };

            // tun2 may prepend a 4-byte PI header on Linux — detect and skip it.
            // If byte 0 is 0x60 (IPv6 version nibble = 6), no header. Otherwise skip 4.
            let pkt = if buf[0] >> 4 == 6 {
                &buf[..n]
            } else if n > 4 && buf[4] >> 4 == 6 {
                &buf[4..n]
            } else {
                continue; // not IPv6, skip (e.g. IPv4 or ARP)
            };

            if pkt.len() < 40 {
                continue; // IPv6 header is 40 bytes
            }

            let mut dest_addr = [0u8; 16];
            dest_addr.copy_from_slice(&pkt[24..40]);

            // Only route 0x02.../7 addresses (our address space)
            if dest_addr[0] != 0x02 {
                debug!("TUN: non-norn dest {:?}, dropping", &dest_addr[..2]);
                continue;
            }

            // Look up dest pub key. If not in the store yet, scan connected peers
            // (peers are registered lazily on first inbound packet; this fallback
            // covers the outgoing direction before any inbound packet has arrived).
            let pub_key = {
                let cached = ks_out.lock().unwrap().key_for_addr(&dest_addr);
                if cached.is_some() {
                    cached
                } else {
                    conn_out.get_peer_stats().into_iter().find_map(|p| {
                        let addr = address_from_key(&p.key);
                        if addr == dest_addr {
                            ks_out.lock().unwrap().register(p.key);
                            Some(p.key)
                        } else {
                            None
                        }
                    })
                }
            };
            match pub_key {
                Some(key) => {
                    if let Err(e) = conn_out.write_to(pkt, &key).await {
                        debug!("TUN write_to: {}", e);
                    }
                }
                None => {
                    debug!("TUN: unknown dest {:?}, no key registered", &dest_addr[..4]);
                }
            }
        }
        warn!("TUN reader exited");
    });

    // ── norn → TUN (inbound) ────────────────────────────────────────────
    tokio::spawn(async move {
        loop {
            let pkt = match conn.read_from().await {
                Ok(p) => p,
                Err(_) => break,
            };

            // Auto-register sender's pub key so we can route back to them
            key_store.lock().unwrap().register(pkt.from);

            // Write the raw IPv6 packet to TUN
            if let Err(e) = tun_writer.write_all(&pkt.payload).await {
                warn!("TUN write: {}", e);
            }
        }
        warn!("norn→TUN reader exited");
    });

    Ok(())
}

#[mutants::skip]
#[cfg(not(feature = "tun-support"))]
pub async fn start(
    tun_name: &str,
    _conn: Arc<PacketConn>,
    _key_store: SharedKeyStore,
) -> Result<()> {
    anyhow::bail!(
        "TUN support not compiled in (feature 'tun-support' required). \
         Rebuild with: cargo build --features tun-support"
    )
}

// ── Helpers ───────────────────────────────────────────────────────────────

// Skip mutations: invokes `ip` system command — requires a real network
// interface and root/CAP_NET_ADMIN to observe any effect.
#[mutants::skip]
#[cfg(feature = "tun-support")]
fn configure_interface(name: &str, ipv6_addr: &str) -> Result<()> {
    use std::process::Command;

    // Bring the interface up
    let status = Command::new("ip")
        .args(["link", "set", name, "up"])
        .status()
        .context("running 'ip link set up'")?;
    if !status.success() {
        warn!("'ip link set {} up' exited with {:?}", name, status.code());
    }

    // Assign IPv6 address with /7 prefix (same as Yggdrasil's 0200::/7 range)
    let cidr = format!("{}/7", ipv6_addr);
    let status = Command::new("ip")
        .args(["addr", "add", &cidr, "dev", name])
        .status()
        .context("running 'ip addr add'")?;
    if !status.success() {
        // May already be set — not fatal
        debug!("'ip addr add {}' exited with {:?}", cidr, status.code());
    }

    // Add a route for the whole 0200::/7 range via this interface
    let status = Command::new("ip")
        .args(["route", "add", "200::/7", "dev", name])
        .status()
        .context("running 'ip route add'")?;
    if !status.success() {
        debug!("'ip route add 200::/7' exited with {:?}", status.code());
    }

    Ok(())
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
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use crate::address::address_from_key;

    // ── KeyStore ──────────────────────────────────────────────────────────────

    #[test]
    fn keystore_register_returns_correct_address() {
        let sk = SigningKey::generate(&mut OsRng);
        let pub_key = sk.verifying_key().to_bytes();
        let expected_addr = address_from_key(&pub_key);

        let mut ks = KeyStore::new();
        let addr = ks.register(pub_key);
        assert_eq!(addr, expected_addr,
            "register must return the address derived from the pub key");
    }

    #[test]
    fn keystore_key_for_addr_returns_none_before_register() {
        let ks = KeyStore::new();
        let addr = [0u8; 16];
        assert_eq!(ks.key_for_addr(&addr), None,
            "unregistered address must return None");
    }

    #[test]
    fn keystore_key_for_addr_returns_key_after_register() {
        let sk = SigningKey::generate(&mut OsRng);
        let pub_key = sk.verifying_key().to_bytes();

        let mut ks = KeyStore::new();
        let addr = ks.register(pub_key);
        let retrieved = ks.key_for_addr(&addr);
        assert_eq!(retrieved, Some(pub_key),
            "key_for_addr must return the registered key");
    }

    #[test]
    fn keystore_different_keys_different_addresses() {
        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);
        let pk1 = sk1.verifying_key().to_bytes();
        let pk2 = sk2.verifying_key().to_bytes();

        let mut ks = KeyStore::new();
        let addr1 = ks.register(pk1);
        let addr2 = ks.register(pk2);
        assert_ne!(addr1, addr2, "different keys must register different addresses");
        assert_eq!(ks.key_for_addr(&addr1), Some(pk1));
        assert_eq!(ks.key_for_addr(&addr2), Some(pk2));
    }

    #[test]
    fn new_key_store_starts_empty() {
        let ks = new_key_store();
        let addr = [0u8; 16];
        assert_eq!(ks.lock().unwrap().key_for_addr(&addr), None,
            "new_key_store must start empty");
    }

    // ── ipv6_string ───────────────────────────────────────────────────────────

    #[test]
    fn ipv6_string_known_vector() {
        // All-zero address: ::
        let zero = [0u8; 16];
        let s = ipv6_string(&zero);
        assert_eq!(s, "::", "all-zero address must format as '::'");
    }

    #[test]
    fn ipv6_string_loopback() {
        // ::1 → last byte is 1
        let mut addr = [0u8; 16];
        addr[15] = 1;
        let s = ipv6_string(&addr);
        assert_eq!(s, "::1");
    }

    #[test]
    fn ipv6_string_deterministic() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let s1 = ipv6_string(&addr);
        let s2 = ipv6_string(&addr);
        assert_eq!(s1, s2);
        assert!(!s1.is_empty(), "ipv6_string must not return empty string");
    }
}
