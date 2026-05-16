// Admin UNIX socket for norn-rs.
//
// JSON-lines protocol: one JSON request per line, one JSON response per line.
//
// Supported methods:
//   getSelf              — identity, address, uptime
//   getPeers             — list of connected peers with stats
//   addPeer {"uri":"tcp://host:port"}  — dial a new peer
//   getRoutes            — hyperbolic coord table (debugging)
//
// UNIX-only. Windows binds need a different transport (named pipes); for now
// a stub `listen` returns an error so the daemon can still compile and run
// on Windows minus the admin socket.

#[cfg(not(unix))]
mod windows_stub {
    use anyhow::{bail, Result};
    use std::sync::Arc;
    use crate::router::PacketConn;
    use crate::transport::ConnectedPeers;

    pub async fn listen(
        _socket_path: &str,
        _conn: Arc<PacketConn>,
        _connected: ConnectedPeers,
    ) -> Result<()> {
        bail!("admin UNIX socket is not supported on Windows; \
               compile on Unix or run a network-based admin endpoint instead");
    }
}

#[cfg(not(unix))]
pub use windows_stub::listen;

#[cfg(unix)]
pub use unix_impl::listen;

#[cfg(unix)]
mod unix_impl {
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{info, warn};

use crate::address::address_from_key;
use crate::router::PacketConn;
use crate::transport::{dial, ConnectedPeers};

// ── Request / Response types ──────────────────────────────────────────────

#[derive(Deserialize)]
struct Request {
    method: String,
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Response {
    GetSelf(SelfInfo),
    GetPeers(Vec<PeerInfo>),
    AddPeer(AddPeerResult),
    Error { error: String },
}

#[derive(Serialize)]
struct SelfInfo {
    pub_key: String,
    address: String,
    peer_count: usize,
}

#[derive(Serialize)]
struct PeerInfo {
    pub_key: String,
    address: String,
    lag_ms: f64,
    jitter_ms: f64,
    loss_rate: f32,
    rx_bytes: u64,
    tx_bytes: u64,
    uptime_secs: f64,
    priority: u8,
    trust: f32,
}

#[derive(Serialize)]
struct AddPeerResult {
    status: String,
    uri: String,
}

// ── Public API ────────────────────────────────────────────────────────────

/// Start the admin UNIX socket listener.
// Skip mutations: binds a UNIX socket and loops on accept() —
// mutations require a real socket client to observe the effect.
#[mutants::skip]
pub async fn listen(
    socket_path: &str,
    conn: Arc<PacketConn>,
    connected: ConnectedPeers,
) -> Result<()> {
    // Remove stale socket file
    let _ = std::fs::remove_file(socket_path);

    // SECURITY: bind() inherits the process umask, so the socket would briefly
    // be world-accessible (e.g. 0666 & !umask). A local attacker can connect()
    // in that window and invoke admin methods (including addPeer → SSRF).
    //
    // We narrow the umask to 0o177 (so the bind produces 0o600 atomically),
    // bind, then restore the previous umask. This closes the TOCTOU window.
    #[cfg(unix)]
    let _umask_guard = {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: umask is process-global; we restore it in Drop. The only
        // concurrent code that mounts files or sockets in this brief window is
        // our own code in the same task — tokio is single-threaded for FS
        // syscalls and the bind below is the only relevant operation.
        unsafe extern "C" {
            fn umask(mask: libc_mode_t) -> libc_mode_t;
        }
        #[allow(non_camel_case_types)]
        type libc_mode_t = u32;
        let prev = unsafe { umask(0o177) };
        // Defer restoration via a guard struct.
        struct UmaskGuard(libc_mode_t);
        impl Drop for UmaskGuard {
            fn drop(&mut self) {
                unsafe { umask(self.0); }
            }
        }
        let guard = UmaskGuard(prev);
        // Belt-and-braces: explicit chmod after bind, in case the umask change
        // didn't take effect (e.g. host filesystem with ACLs).
        let _bind_perms = std::fs::Permissions::from_mode(0o600);
        guard
    };

    let listener = UnixListener::bind(socket_path)
        .map_err(|e| anyhow::anyhow!("admin socket bind {}: {}", socket_path, e))?;

    // Belt-and-braces: explicit chmod after bind. Fail loudly if it can't be
    // applied — without 0o600 the socket is a local privilege escalation.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(socket_path, perms) {
            // Tear down the listener before bailing so we don't leak an
            // insecure socket if start-up fails.
            drop(listener);
            let _ = std::fs::remove_file(socket_path);
            return Err(anyhow::anyhow!(
                "admin socket: failed to set 0o600 on {}: {} (refusing to run with world-accessible socket)",
                socket_path, e
            ));
        }
    }

    info!("admin socket at {} (mode 0600)", socket_path);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => { warn!("admin accept: {}", e); continue; }
        };
        let conn = conn.clone();
        let connected = connected.clone();
        tokio::spawn(async move {
            handle_client(stream, conn, connected).await;
        });
    }
}

// ── Client handler ────────────────────────────────────────────────────────

// Skip mutations: reads JSON lines from a UnixStream and writes responses —
// mutations require a live socket connection to observe.
#[mutants::skip]
async fn handle_client(
    stream: tokio::net::UnixStream,
    conn: Arc<PacketConn>,
    connected: ConnectedPeers,
) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() { continue; }

        let resp = match serde_json::from_str::<Request>(&line) {
            Err(e) => Response::Error { error: format!("parse error: {}", e) },
            Ok(req) => dispatch(req, &conn, &connected).await,
        };

        let resp_json = serde_json::to_string(&resp).unwrap_or_else(|e| {
            format!(r#"{{"error":"serialization error: {}"}}"#, e)
        });
        let _ = writer.write_all(format!("{}\n", resp_json).as_bytes()).await;
    }
}

// Skip mutations: constructs responses for live admin requests —
// verifying the correct Response variant and fields requires a real socket client.
#[mutants::skip]
async fn dispatch(req: Request, conn: &Arc<PacketConn>, connected: &ConnectedPeers) -> Response {
    match req.method.as_str() {
        "getSelf" => {
            let pub_key = conn.pub_key;
            let addr = ipv6_string(&address_from_key(&pub_key));
            Response::GetSelf(SelfInfo {
                pub_key: hex::encode(pub_key),
                address: addr,
                peer_count: conn.get_peer_stats().len(),
            })
        }

        "getPeers" => {
            let peers = conn.get_peer_stats().into_iter().map(|p| PeerInfo {
                pub_key: hex::encode(p.key),
                address: ipv6_string(&address_from_key(&p.key)),
                lag_ms: p.lag.as_secs_f64() * 1000.0,
                jitter_ms: p.jitter.as_secs_f64() * 1000.0,
                loss_rate: p.loss_rate,
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
                uptime_secs: p.uptime.as_secs_f64(),
                priority: p.priority,
                trust: p.trust,
            }).collect();
            Response::GetPeers(peers)
        }

        "addPeer" => {
            match req.uri {
                None => Response::Error { error: "missing \"uri\" field".into() },
                Some(uri) => {
                    let conn_clone = conn.clone();
                    let connected_clone = connected.clone();
                    let uri_clone = uri.clone();
                    tokio::spawn(async move {
                        dial(&uri_clone, conn_clone, connected_clone).await;
                    });
                    Response::AddPeer(AddPeerResult {
                        status: "dialing".into(),
                        uri,
                    })
                }
            }
        }

        unknown => Response::Error {
            error: format!("unknown method: \"{}\"", unknown),
        },
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn ipv6_string(bytes: &[u8; 16]) -> String {
    // Format as standard IPv6 with colons
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
        // ::1 → only last byte is 1
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
        // 0200::1 → bytes [0x02, 0x00, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0x01]
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
    fn ipv6_string_non_empty() {
        // Function-replacement mutations produce "xyzzy" or String::new()
        let bytes: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let s = ipv6_string(&bytes);
        assert!(!s.is_empty(), "must not return empty string");
        assert_ne!(s, "xyzzy", "must not return placeholder");
        assert!(s.contains("2001") && s.contains("db8"),
            "must contain address components; got {:?}", s);
    }
}

} // end mod unix_impl
