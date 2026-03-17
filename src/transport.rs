// TCP transport layer for norn-rs peer connections.
//
// Handshake: each side sends its 32-byte ed25519 pub key, then the
// connection is handed to PacketConn::handle_conn. All further security
// (authenticity, confidentiality, forward secrecy) is handled by the
// session layer — TCP is just a reliable byte pipe.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::router::PacketConn;

/// Shared set of currently-connected peer pub keys (for dedup).
pub type ConnectedPeers = Arc<Mutex<HashSet<[u8; 32]>>>;

/// Parse a peer URI and return the raw host:port string.
/// Supported format: "tcp://host:port"
pub fn parse_tcp_uri(uri: &str) -> Result<String> {
    uri.strip_prefix("tcp://")
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("unsupported URI scheme (expected tcp://): {}", uri))
}

/// Exchange ed25519 pub keys — simple 32+32 byte framed handshake.
async fn handshake(stream: &mut TcpStream, our_pub: &[u8; 32]) -> Result<[u8; 32]> {
    // Send ours first, then read theirs (simultaneous send avoids deadlock).
    let (mut reader, mut writer) = stream.split();
    let (send_res, recv_res) = tokio::join!(
        writer.write_all(our_pub),
        async {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf).await?;
            Ok::<[u8; 32], std::io::Error>(buf)
        }
    );
    send_res.context("handshake send")?;
    recv_res.context("handshake recv")
}

/// Start a TCP listener. Accepts peers, performs handshake, calls handle_conn.
pub async fn listen(
    uri: &str,
    conn: Arc<PacketConn>,
    connected: ConnectedPeers,
) -> Result<()> {
    let addr = parse_tcp_uri(uri)?;
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding TCP listener on {}", addr))?;
    info!("TCP listener on {}", addr);

    loop {
        let (mut stream, peer_addr) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => { warn!("accept error: {}", e); continue; }
        };

        let conn = conn.clone();
        let connected = connected.clone();
        tokio::spawn(async move {
            let our_pub = conn.pub_key;
            match handshake(&mut stream, &our_pub).await {
                Ok(remote_pub) => {
                    // Dedup: skip if already connected
                    {
                        let mut set = connected.lock().unwrap();
                        if set.contains(&remote_pub) {
                            debug!("duplicate inbound from {:?}, dropping", &remote_pub[..4]);
                            return;
                        }
                        set.insert(remote_pub);
                    }
                    info!("accepted peer {:?} from {}", &remote_pub[..4], peer_addr);
                    let (reader, writer) = stream.into_split();
                    conn.handle_conn(remote_pub, reader, writer, 0).await;
                    connected.lock().unwrap().remove(&remote_pub);
                }
                Err(e) => warn!("handshake failed from {}: {}", peer_addr, e),
            }
        });
    }
}

/// Dial a peer by URI with automatic reconnection (exponential backoff).
pub async fn dial(uri: &str, conn: Arc<PacketConn>, connected: ConnectedPeers) {
    let addr = match parse_tcp_uri(uri) {
        Ok(a) => a,
        Err(e) => { warn!("bad peer URI {}: {}", uri, e); return; }
    };

    let mut delay = std::time::Duration::from_secs(1);
    loop {
        match TcpStream::connect(&addr).await {
            Ok(mut stream) => {
                let our_pub = conn.pub_key;
                match handshake(&mut stream, &our_pub).await {
                    Ok(remote_pub) => {
                        // Dedup: drop the guard before any await
                        let already = connected.lock().unwrap().contains(&remote_pub);
                        if already {
                            debug!("already connected to {:?}, not adding duplicate", &remote_pub[..4]);
                            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                            continue;
                        }
                        {
                            connected.lock().unwrap().insert(remote_pub);
                        }
                        info!("connected to peer {:?} at {}", &remote_pub[..4], addr);
                        let (reader, writer) = stream.into_split();
                        conn.handle_conn(remote_pub, reader, writer, 0).await;
                        // handle_conn spawns reader/writer tasks and returns.
                        // The reader task calls remove_peer on disconnect.
                        connected.lock().unwrap().remove(&remote_pub);
                        // Reset backoff on successful connect
                        delay = std::time::Duration::from_secs(5);
                    }
                    Err(e) => warn!("handshake with {} failed: {}", addr, e),
                }
            }
            Err(e) => {
                debug!("connect to {} failed: {} (retry in {:?})", addr, e, delay);
            }
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(std::time::Duration::from_secs(60));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_tcp_uri ─────────────────────────────────────────────────────────

    #[test]
    fn parse_tcp_uri_valid() {
        let addr = parse_tcp_uri("tcp://1.2.3.4:9001").unwrap();
        assert_eq!(addr, "1.2.3.4:9001", "must strip tcp:// prefix");
    }

    #[test]
    fn parse_tcp_uri_ipv6() {
        let addr = parse_tcp_uri("tcp://[::1]:9001").unwrap();
        assert_eq!(addr, "[::1]:9001");
    }

    #[test]
    fn parse_tcp_uri_wrong_scheme_fails() {
        assert!(parse_tcp_uri("udp://1.2.3.4:9001").is_err(),
            "non-tcp URI must fail");
    }

    #[test]
    fn parse_tcp_uri_empty_fails() {
        assert!(parse_tcp_uri("").is_err());
    }

    #[test]
    fn parse_tcp_uri_no_scheme_fails() {
        assert!(parse_tcp_uri("1.2.3.4:9001").is_err());
    }

    #[test]
    fn parse_tcp_uri_preserves_hostname() {
        let addr = parse_tcp_uri("tcp://peer.example.com:9001").unwrap();
        assert_eq!(addr, "peer.example.com:9001");
    }
}
