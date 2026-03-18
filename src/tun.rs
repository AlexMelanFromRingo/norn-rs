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

// ── ICMPv6 helper ─────────────────────────────────────────────────────────

/// Build an ICMPv6 Destination Unreachable (type 1, code 0 — no route) packet
/// to send back via TUN when a norn destination address cannot be resolved.
///
/// Structure (RFC 4443):
///   IPv6 header (40 bytes): src=our_addr, dst=orig_src, next_hdr=58, hop_limit=64
///   ICMPv6 body: type(1) + code(1) + checksum(2) + unused(4) + original_pkt (truncated)
///
/// Total size is capped at 1280 bytes (IPv6 minimum MTU) per RFC 4443 §2.4.
pub fn icmpv6_dest_unreachable(our_addr: &[u8; 16], orig_pkt: &[u8]) -> Option<Vec<u8>> {
    if orig_pkt.len() < 40 {
        return None; // cannot extract src address from a malformed packet
    }
    let orig_src = &orig_pkt[8..24]; // bytes 8-23 of IPv6 header = source address

    // ICMPv6 payload = 4 bytes type/code/checksum + 4 bytes unused + original packet
    // Total IPv6 packet capped at 1280 bytes (IPv6 min MTU).
    const MAX_TOTAL: usize = 1280;
    const IPV6_HDR: usize = 40;
    const ICMP_OVERHEAD: usize = 8; // type(1)+code(1)+checksum(2)+unused(4)
    let max_orig = MAX_TOTAL - IPV6_HDR - ICMP_OVERHEAD;
    let orig_len = orig_pkt.len().min(max_orig);

    let icmpv6_len = ICMP_OVERHEAD + orig_len;
    let mut pkt = Vec::with_capacity(IPV6_HDR + icmpv6_len);

    // ── IPv6 header ────────────────────────────────────────────────────────
    pkt.push(0x60); // version=6, traffic class high nibble=0
    pkt.extend_from_slice(&[0u8; 3]); // traffic class low + flow label
    pkt.extend_from_slice(&(icmpv6_len as u16).to_be_bytes()); // payload length
    pkt.push(58); // next header = ICMPv6
    pkt.push(64); // hop limit
    pkt.extend_from_slice(our_addr); // source
    pkt.extend_from_slice(orig_src); // destination (original sender)

    // ── ICMPv6 body (checksum = 0 placeholder) ────────────────────────────
    let icmp_start = pkt.len();
    pkt.push(1);   // type: Destination Unreachable
    pkt.push(0);   // code: No route to destination
    pkt.extend_from_slice(&[0u8; 2]); // checksum placeholder
    pkt.extend_from_slice(&[0u8; 4]); // unused
    pkt.extend_from_slice(&orig_pkt[..orig_len]);

    // ── ICMPv6 checksum (RFC 4443 §2.3 — IPv6 pseudo-header) ──────────────
    // Pseudo-header: src(16) + dst(16) + length(4) + zeros(3) + next_hdr(1)
    let mut csum_buf = Vec::with_capacity(40 + icmpv6_len);
    csum_buf.extend_from_slice(our_addr);
    csum_buf.extend_from_slice(orig_src);
    csum_buf.extend_from_slice(&(icmpv6_len as u32).to_be_bytes());
    csum_buf.extend_from_slice(&[0u8, 0, 0, 58]); // zeros(3) + next_hdr=58
    csum_buf.extend_from_slice(&pkt[icmp_start..]);

    let checksum = internet_checksum(&csum_buf);
    pkt[icmp_start + 2] = (checksum >> 8) as u8;
    pkt[icmp_start + 3] = (checksum & 0xFF) as u8;

    Some(pkt)
}

/// Internet checksum (RFC 1071): one's complement sum of 16-bit words.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in chunks.by_ref() {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += (byte as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
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
    use tokio::io::AsyncReadExt;

    // Register our own key so we know our own address
    let our_addr = key_store.lock().unwrap().register(conn.pub_key);
    let our_addr_str = ipv6_string(&our_addr);

    // TUN MTU: norn payload minus session overhead (ChaCha20 tag=16, length=2,
    // padding up to 255 bytes worst-case). 65200 fits comfortably.
    let tun_mtu = (conn.mtu() as u64).saturating_sub(300).max(1280) as u16;

    // Create TUN device
    let mut tun_config = tun2::Configuration::default();
    tun_config.tun_name(tun_name).mtu(tun_mtu);
    let dev = tun2::create_as_async(&tun_config)
        .with_context(|| format!("creating TUN device '{}' (need CAP_NET_ADMIN or root)", tun_name))?;

    // Assign IPv6 address via `ip` command
    configure_interface(tun_name, &our_addr_str)?;
    info!("TUN interface {} up, address {}/7", tun_name, our_addr_str);

    // (split happens inside the outbound task setup above)

    // ── TUN → norn (outbound) ────────────────────────────────────────────
    let conn_out = conn.clone();
    let ks_out = key_store.clone();
    // Clone writer half for ICMPv6 unreachable replies (shared via Arc<Mutex<>>)
    let (tun_reader, tun_writer_raw) = tokio::io::split(dev);
    let tun_writer = std::sync::Arc::new(tokio::sync::Mutex::new(tun_writer_raw));
    let tun_writer_icmp = tun_writer.clone();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536 + 4]; // +4 for tun2 header on some platforms
        let mut tun_reader = tun_reader;
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
                    debug!("TUN: unknown dest {:?}, sending ICMPv6 unreachable", &dest_addr[..4]);
                    if let Some(icmp) = icmpv6_dest_unreachable(&our_addr, pkt) {
                        let mut w = tun_writer_icmp.lock().await;
                        let _ = tokio::io::AsyncWriteExt::write_all(&mut *w, &icmp).await;
                    }
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
            let mut w = tun_writer.lock().await;
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut *w, &pkt.payload).await {
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
