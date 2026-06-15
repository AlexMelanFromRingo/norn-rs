//! mDNS / DNS-SD peer discovery.
//!
//! Advertises this node as `_norn._tcp.local` and watches for other
//! `_norn._tcp.local` services on the link. Standard zeroconf — works
//! out of the box with Avahi (Linux), Bonjour (macOS), and any other
//! RFC 6762 / 6763 stack on the local network.
//!
//! Coexists with the legacy raw-UDP-multicast discovery in `discovery.rs`;
//! both can be enabled at once, both are equally optional. mDNS is more
//! firewall-friendly (uses the standard mDNS port 5353) and interoperable
//! with off-the-shelf service browsers.
//!
//! Service TXT records:
//!   - `pub_key` = 64-char hex Ed25519 pub_key
//!   - `version` = our protocol version string
//!
//! The peer's actual transport URI is reconstructed from the advertised
//! IP + port (TCP-only for now; QUIC support could add a separate
//! `_norn._udp.local` service).

use anyhow::Result;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::router::PacketConn;
use crate::transport::{dial_discovered, ConnectedPeers};

const SERVICE_TYPE: &str = "_norn._tcp.local.";
const TXT_PUB_KEY: &str = "pub_key";
const TXT_VERSION: &str = "version";

/// Start the mDNS responder + browser.
///
/// `tcp_port` is the port we advertise (None = browse-only, useful when
/// we're behind NAT and only want to discover other LAN nodes).
#[mutants::skip]
pub async fn start(
    conn: Arc<PacketConn>,
    tcp_port: Option<u16>,
    connected: ConnectedPeers,
) -> Result<()> {
    let daemon = ServiceDaemon::new()?;

    let host_label = hostname_label();
    let our_pub_hex = hex::encode(conn.pub_key);

    // ── Announce ───────────────────────────────────────────────────────────
    if let Some(port) = tcp_port {
        let mut props: HashMap<String, String> = HashMap::new();
        props.insert(TXT_PUB_KEY.to_string(), our_pub_hex.clone());
        props.insert(TXT_VERSION.to_string(), env!("CARGO_PKG_VERSION").to_string());

        // ServiceInfo wants instance_name, service_type, host, ip, port, txt.
        // Using local-link IPv4/IPv6 — mdns-sd auto-detects when ip is "" or
        // uses the supplied iface address.
        let instance_name = format!("norn-{}", &our_pub_hex[..8]);
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &format!("{}.local.", host_label),
            "",  // empty addrs → mdns-sd uses local interfaces
            port,
            Some(props),
        )?;
        let info = info.enable_addr_auto();
        daemon.register(info)?;
        info!("mDNS service advertised as {}._norn._tcp.local on port {}", instance_name, port);
    } else {
        info!("mDNS browse-only mode (no service advertised)");
    }

    // ── Browse ─────────────────────────────────────────────────────────────
    let receiver = daemon.browse(SERVICE_TYPE)?;

    loop {
        match receiver.recv_async().await {
            Ok(event) => handle_event(event, &conn, &connected, &our_pub_hex),
            Err(e) => {
                warn!("mDNS browse channel closed: {}", e);
                break;
            }
        }
    }
    Ok(())
}

#[mutants::skip]
fn handle_event(
    event: ServiceEvent,
    conn: &Arc<PacketConn>,
    connected: &ConnectedPeers,
    our_pub_hex: &str,
) {
    if let ServiceEvent::ServiceResolved(info) = event {
        let props = info.get_properties();
        let pub_hex = match props.get_property_val_str(TXT_PUB_KEY) {
            Some(s) => s,
            None => {
                debug!("mDNS resolution missing pub_key TXT, skipping");
                return;
            }
        };
        if pub_hex == our_pub_hex {
            return; // ourselves
        }
        // Skip if we're already connected to that pub_key (uses the dedup
        // semantics built into transport::dial via ConnectedPeers).
        let mut pub_bytes = [0u8; 32];
        match hex::decode_to_slice(pub_hex, &mut pub_bytes) {
            Ok(()) => {}
            Err(_) => { debug!("mDNS pub_key not valid hex, skipping"); return; }
        }
        // mDNS only dials peers we haven't seen at all yet. With
        // multi-TCP bonding, an existing link count > 0 is still
        // enough to skip the rediscover dial here; the multi-link
        // pathway is driven from the static peer list in NodeConfig
        // (where the user explicitly lists the URI N times), not
        // from mDNS auto-discovery.
        if connected.lock().unwrap().contains_key(&pub_bytes) {
            return;
        }

        // Prefer the first IPv6 address we find; fall back to IPv4.
        // Reconstruct a tcp://[host]:port URI for transport::dial.
        let port = info.get_port();
        let addrs = info.get_addresses();
        if addrs.is_empty() {
            debug!("mDNS resolution has no addresses, skipping");
            return;
        }
        let addr_choice = addrs.iter()
            .find(|a| a.is_ipv6())
            .or_else(|| addrs.iter().next())
            .expect("addrs non-empty");
        let uri = match addr_choice.to_ip_addr() {
            std::net::IpAddr::V4(v4) => format!("tcp://{}:{}", v4, port),
            std::net::IpAddr::V6(v6) => format!("tcp://[{}]:{}", v6, port),
        };
        info!("mDNS discovered peer {:?} at {}", &pub_bytes[..4], uri);

        let conn_clone = conn.clone();
        let connected_clone = connected.clone();
        tokio::spawn(async move {
            dial_discovered(&uri, conn_clone, connected_clone).await;
        });
    }
}

/// Sanitize the system hostname for use in an mDNS service name. mDNS
/// requires hostnames to be DNS-label-compatible (no spaces, dots, etc.).
fn hostname_label() -> String {
    // Try the system hostname; fall back to "norn" if unavailable or weird.
    let raw = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            #[cfg(unix)]
            unsafe {
                // c_char is i8 on x86_64-linux-gnu but u8 on aarch64-linux-gnu
                // (and on musl). Use the std alias so the buffer type matches
                // gethostname()'s actual signature on every Unix target.
                let mut buf: [std::ffi::c_char; 256] = [0; 256];
                if libc_gethostname_compat(buf.as_mut_ptr(), buf.len()) == 0 {
                    let s = std::ffi::CStr::from_ptr(buf.as_ptr())
                        .to_string_lossy()
                        .into_owned();
                    return Some(s);
                }
                None
            }
            #[cfg(not(unix))]
            None
        })
        .unwrap_or_default();
    let cleaned: String = raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if cleaned.is_empty() { "norn".to_string() } else { cleaned }
}

// Shim that calls libc::gethostname without pulling in the `libc` crate
// just for this. Safe wrapper around the C signature. `c_char` is the std
// alias for whatever C's `char` is on this target (i8 on x86_64-linux-gnu;
// u8 on aarch64-linux-gnu, musl, etc.).
#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "gethostname"]
    fn libc_gethostname_compat(name: *mut std::ffi::c_char, len: usize) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_label_is_dns_safe() {
        let h = hostname_label();
        assert!(!h.is_empty(), "must return a non-empty label");
        assert!(h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "every char must be alphanumeric or '-': {h}");
    }

    #[test]
    fn service_type_is_well_formed() {
        assert!(SERVICE_TYPE.starts_with('_'));
        assert!(SERVICE_TYPE.contains("._tcp."));
        assert!(SERVICE_TYPE.ends_with('.'));
    }

    #[test]
    fn txt_keys_are_short_ascii() {
        // mDNS TXT keys should be <= 9 chars (BIND convention) and ASCII.
        for k in [TXT_PUB_KEY, TXT_VERSION] {
            assert!(k.is_ascii());
            assert!(k.len() <= 9, "TXT key '{}' too long ({})", k, k.len());
        }
    }
}
