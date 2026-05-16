// TCP transport layer for norn-rs peer connections.
//
// Handshake: each side sends its 32-byte ed25519 pub key, then the
// connection is handed to PacketConn::handle_conn. All further security
// (authenticity, confidentiality, forward secrecy) is handled by the
// session layer — TCP is just a reliable byte pipe.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::router::PacketConn;

/// Handshake protocol version. Bump on incompatible wire changes.
const HANDSHAKE_MAGIC: [u8; 4] = *b"NRN1";
/// Domain-separation tag for the handshake signature.
/// Signed payload: HANDSHAKE_SIG_TAG || our_nonce || their_nonce || our_pub || their_pub.
const HANDSHAKE_SIG_TAG: &[u8] = b"norn:handshake:v1";
/// Maximum time allowed for handshake completion (prevents slowloris-style holds).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum simultaneous unauthenticated handshakes in-flight per process.
/// Bounds memory/FD exhaustion from accept floods.
const MAX_PENDING_HANDSHAKES: usize = 256;

/// Shared set of currently-connected peer pub keys (for dedup).
pub type ConnectedPeers = Arc<Mutex<HashSet<[u8; 32]>>>;

/// Apply TCP_NODELAY and SO_KEEPALIVE to a connected TcpStream.
///
/// Keepalive settings: first probe after 10s idle, retries every 3s, 3 retries.
/// This detects silent peer failures (e.g. network partition, crashed process)
/// within ~19 seconds without waiting for TCP's default 2-hour timeout.
fn configure_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(3))
        .with_retries(3);
    if let Err(e) = sock.set_tcp_keepalive(&ka) {
        debug!("set_tcp_keepalive failed (non-fatal): {}", e);
    }
}

/// Parse a peer URI and return the raw host:port string.
/// Supported format: "tcp://host:port"
pub fn parse_tcp_uri(uri: &str) -> Result<String> {
    uri.strip_prefix("tcp://")
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("unsupported URI scheme (expected tcp://): {}", uri))
}

/// Authenticated handshake.
///
/// Wire (each side sends in parallel, then sigs are exchanged):
///   1. [magic:4][our_pub:32][our_nonce:32]                 — 68 bytes
///   2. [sig:64] over (TAG || our_nonce || their_nonce || our_pub || their_pub)
///
/// Proves possession of the ed25519 private key for the claimed pub_key and
/// binds the proof to *this* TCP session via fresh per-side nonces. Without
/// this, a LAN attacker can claim any pub_key in the first 32 bytes and impersonate
/// a peer at the routing layer (cuckoo state, peer dedup, RTT tracking).
#[cfg_attr(not(test), mutants::skip)]
pub(crate) fn build_handshake_sig(
    signing_key: &SigningKey,
    our_nonce: &[u8; 32],
    their_nonce: &[u8; 32],
    our_pub: &[u8; 32],
    their_pub: &[u8; 32],
) -> [u8; 64] {
    let mut buf = Vec::with_capacity(HANDSHAKE_SIG_TAG.len() + 32 * 4);
    buf.extend_from_slice(HANDSHAKE_SIG_TAG);
    buf.extend_from_slice(our_nonce);
    buf.extend_from_slice(their_nonce);
    buf.extend_from_slice(our_pub);
    buf.extend_from_slice(their_pub);
    signing_key.sign(&buf).to_bytes()
}

#[cfg_attr(not(test), mutants::skip)]
pub(crate) fn verify_handshake_sig(
    their_pub: &[u8; 32],
    sig: &[u8; 64],
    their_nonce: &[u8; 32],
    our_nonce: &[u8; 32],
    their_pub_for_msg: &[u8; 32],
    our_pub_for_msg: &[u8; 32],
) -> Result<()> {
    let vk = VerifyingKey::from_bytes(their_pub).context("handshake: invalid remote pub_key")?;
    let mut buf = Vec::with_capacity(HANDSHAKE_SIG_TAG.len() + 32 * 4);
    buf.extend_from_slice(HANDSHAKE_SIG_TAG);
    // Remote signed: their_nonce || our_nonce || their_pub || our_pub
    buf.extend_from_slice(their_nonce);
    buf.extend_from_slice(our_nonce);
    buf.extend_from_slice(their_pub_for_msg);
    buf.extend_from_slice(our_pub_for_msg);
    vk.verify(&buf, &Signature::from_bytes(sig))
        .context("handshake: signature verification failed")
}

#[mutants::skip]
async fn handshake(stream: &mut TcpStream, signing_key: &SigningKey) -> Result<[u8; 32]> {
    let our_pub = signing_key.verifying_key().to_bytes();
    let mut our_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut our_nonce);

    let mut hello = Vec::with_capacity(4 + 32 + 32);
    hello.extend_from_slice(&HANDSHAKE_MAGIC);
    hello.extend_from_slice(&our_pub);
    hello.extend_from_slice(&our_nonce);

    let (mut reader, mut writer) = stream.split();

    // Phase 1: exchange (magic, pub, nonce).
    let (send_res, recv_res) = tokio::join!(
        writer.write_all(&hello),
        async {
            let mut buf = [0u8; 4 + 32 + 32];
            reader.read_exact(&mut buf).await?;
            Ok::<[u8; 68], std::io::Error>(buf)
        }
    );
    send_res.context("handshake hello send")?;
    let hello_in = recv_res.context("handshake hello recv")?;

    if hello_in[..4] != HANDSHAKE_MAGIC {
        bail!("handshake: bad magic (peer using incompatible protocol?)");
    }
    let mut their_pub = [0u8; 32];
    their_pub.copy_from_slice(&hello_in[4..36]);
    let mut their_nonce = [0u8; 32];
    their_nonce.copy_from_slice(&hello_in[36..68]);

    // Refuse self-loops.
    if their_pub == our_pub {
        bail!("handshake: peer announced our own pub_key (self-loop)");
    }
    // Sanity-check the remote pub_key is a valid ed25519 point before signing.
    VerifyingKey::from_bytes(&their_pub).context("handshake: malformed remote pub_key")?;

    // Phase 2: exchange signatures binding both nonces and identities.
    let sig_out = build_handshake_sig(signing_key, &our_nonce, &their_nonce, &our_pub, &their_pub);
    let (send_res, recv_res) = tokio::join!(
        writer.write_all(&sig_out),
        async {
            let mut sig = [0u8; 64];
            reader.read_exact(&mut sig).await?;
            Ok::<[u8; 64], std::io::Error>(sig)
        }
    );
    send_res.context("handshake sig send")?;
    let sig_in = recv_res.context("handshake sig recv")?;

    verify_handshake_sig(
        &their_pub, &sig_in,
        &their_nonce, &our_nonce,
        &their_pub, &our_pub,
    )?;

    Ok(their_pub)
}

/// Start a TCP listener. Accepts peers, performs handshake, calls handle_conn.
#[mutants::skip]
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

    // Cap the number of *unauthenticated* in-flight handshakes. Each accepted
    // socket holds an FD + a tokio task until handshake completes; without a
    // bound a TCP SYN/connect flood can exhaust both. Authenticated peers move
    // out of this cap as soon as the handshake completes (semaphore permit dropped).
    let handshake_sem = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_HANDSHAKES));

    loop {
        let (mut stream, peer_addr) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => { warn!("accept error: {}", e); continue; }
        };

        // try_acquire — if all permits are used, drop the connection rather
        // than queuing indefinitely. The remote will reconnect with backoff.
        let permit = match handshake_sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("handshake limit reached, dropping inbound from {}", peer_addr);
                drop(stream);
                continue;
            }
        };

        let conn = conn.clone();
        let connected = connected.clone();
        tokio::spawn(async move {
            configure_socket(&stream);
            let hs_result = timeout(
                HANDSHAKE_TIMEOUT,
                handshake(&mut stream, conn.signing_key()),
            ).await;

            // Release the handshake permit before the long-lived read loop.
            drop(permit);

            let remote_pub = match hs_result {
                Err(_) => { warn!("handshake timed out from {}", peer_addr); return; }
                Ok(Err(e)) => { warn!("handshake failed from {}: {:#}", peer_addr, e); return; }
                Ok(Ok(p)) => p,
            };

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
        });
    }
}

/// Dial a peer by URI with automatic reconnection (exponential backoff).
// Skip mutations: retry loop with real TcpStream connect and backoff —
// mutations to connection logic, dedup, and backoff require a live network.
#[mutants::skip]
pub async fn dial(uri: &str, conn: Arc<PacketConn>, connected: ConnectedPeers) {
    let addr = match parse_tcp_uri(uri) {
        Ok(a) => a,
        Err(e) => { warn!("bad peer URI {}: {}", uri, e); return; }
    };

    let mut delay = Duration::from_secs(1);
    loop {
        match TcpStream::connect(&addr).await {
            Ok(mut stream) => {
                configure_socket(&stream);
                let hs = timeout(
                    HANDSHAKE_TIMEOUT,
                    handshake(&mut stream, conn.signing_key()),
                ).await;
                let remote_pub_res: Result<[u8; 32]> = match hs {
                    Err(_) => Err(anyhow::anyhow!("handshake timed out")),
                    Ok(r) => r,
                };
                match remote_pub_res {
                    Ok(remote_pub) => {
                        // Dedup: drop the guard before any await
                        let already = connected.lock().unwrap().contains(&remote_pub);
                        if already {
                            debug!("already connected to {:?}, not adding duplicate", &remote_pub[..4]);
                            tokio::time::sleep(Duration::from_secs(30)).await;
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
                        delay = Duration::from_secs(5);
                    }
                    Err(e) => warn!("handshake with {} failed: {}", addr, e),
                }
            }
            Err(e) => {
                debug!("connect to {} failed: {} (retry in {:?})", addr, e, delay);
            }
        }
        tokio::time::sleep(delay).await;
        // Exponential backoff with ±20% jitter to prevent thundering herd
        let jitter = 0.8 + rand::random::<f64>() * 0.4;
        delay = Duration::from_millis((delay.as_millis() as f64 * 2.0 * jitter) as u64)
            .min(Duration::from_secs(60));
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
