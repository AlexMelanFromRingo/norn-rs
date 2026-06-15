// TCP transport layer for norn-rs peer connections.
//
// Handshake: each side sends its 32-byte ed25519 pub key, then the
// connection is handed to PacketConn::handle_conn. All further security
// (authenticity, confidentiality, forward secrecy) is handled by the
// session layer — TCP is just a reliable byte pipe.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::obfs::{ObfsReader, ObfsWriter};
use crate::router::{LockOrRecover, PacketConn};

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
/// Maximum simultaneous unauthenticated handshakes in-flight from a SINGLE
/// remote IP. The global cap above is fair-share-blind: an attacker behind one
/// IP could occupy all 256 slots and starve every other peer. This per-IP cap
/// guarantees ≥ MAX_PENDING_HANDSHAKES / MAX_PER_IP_HANDSHAKES legitimate
/// peers can still complete a handshake under flood.
///
/// Defence-in-depth alongside Sybil PoW (`min_peer_difficulty_bits`): PoW is
/// per-IDENTITY, this cap is per-NETWORK-ENDPOINT. An attacker with one IP
/// and arbitrary CPU still cannot occupy more than 4 slots.
const MAX_PER_IP_HANDSHAKES: usize = 4;

/// Max consecutive FAILED attempts a discovery-triggered dial makes before it
/// gives up. Unauthenticated mDNS / multicast beacons must not be able to spawn
/// unbounded *persistent* dial tasks: without this, an on-LAN attacker
/// advertising many fake pub_keys would create one infinite retry loop per fake
/// key (each handshake fails, but the loop retries forever) → unbounded tasks,
/// breaking the flat per-node memory property. A successful connection resets
/// the counter, so only repeatedly-failing dials give up; a dropped legitimate
/// peer is re-dialled on its next beacon. Configured/admin dials are unbounded.
const DISCOVERY_DIAL_MAX_ATTEMPTS: u32 = 4;

/// Shared set of currently-connected peer pub keys (for dedup).
/// Per-peer connection counter. Replaces the historical
/// `HashSet<PubKey>` that allowed exactly one TCP/QUIC link per peer.
/// Multi-TCP bonding (one logical peer pair, N parallel TCPs to
/// aggregate cwnd past the single-flow ceiling) needs the counter:
/// dial / accept gates only refuse the (N+1)-th attempt, not the
/// 2nd-through-N. The cap is `MAX_PARALLEL_LINKS_PER_PEER` from
/// `router.rs`; same number governs `PeerData::txs.len()`.
pub type ConnectedPeers = Arc<Mutex<HashMap<[u8; 32], u32>>>;

/// RAII guard that decrements a per-IP handshake counter on drop. Ensures we
/// release the slot whether the spawned task exits via success, error, or
/// timeout — no leak path.
struct PerIpGuard {
    ip: std::net::IpAddr,
    counts: Arc<Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock_or_recover();
        if let Some(c) = counts.get_mut(&self.ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

/// Spawn a background task that polls `SO_TCP_INFO` on Linux every 5s and
/// pushes kernel-side RTT / loss into the router's `peer.lag` and
/// `peer.loss_rate`. On non-Linux it returns an immediately-completed handle
/// — the router falls back to the application-layer SIG_REQ probe.
///
/// The returned `JoinHandle` should be `abort()`ed once `handle_conn`
/// returns so the poller doesn't outlive the connection.
#[cfg(target_os = "linux")]
fn spawn_tcp_info_poller(
    fd: std::os::fd::RawFd,
    peer: [u8; 32],
    conn: Arc<PacketConn>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        // Discard the immediate tick so we don't sample before any traffic
        // has flowed.
        interval.tick().await;
        loop {
            interval.tick().await;
            match crate::tcp_info::read_tcp_info(fd) {
                Some(stats) => {
                    conn.record_kernel_link_stats(&peer, stats.rtt(), stats.loss_rate());
                }
                None => {
                    // getsockopt failed — usually means the socket is closed.
                    // Exit; the connection task is on its way out anyway.
                    break;
                }
            }
        }
    })
}

#[cfg(not(target_os = "linux"))]
fn spawn_tcp_info_poller(
    _fd: i32,
    _peer: [u8; 32],
    _conn: Arc<PacketConn>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {})
}

/// Apply TCP_NODELAY and SO_KEEPALIVE to a connected TcpStream.
///
/// Keepalive settings: first probe after 10s idle, retries every 3s, 3 retries.
/// This detects silent peer failures (e.g. network partition, crashed process)
/// within ~19 seconds without waiting for TCP's default 2-hour timeout.
///
/// Note on socket buffers: we **deliberately do NOT** call
/// `set_send_buffer_size` / `set_recv_buffer_size`. On Linux, an
/// explicit `setsockopt(SO_RCVBUF)` disables receive-window
/// auto-tuning for the socket and then clamps the chosen value to
/// `net.core.{r,w}mem_max` (default 208 KB on many distros). The net
/// effect is the *worst* of both worlds: the buffer never grows past
/// 208 KB, the receive window plateaus, and long-fat-pipe single-stream
/// throughput stalls at ~30 Mbit/s. Letting the kernel auto-tune
/// against `tcp_rmem.max` / `tcp_wmem.max` (defaults 6 MB / 4 MB on
/// Linux) gives properly scaling BDP behaviour without operator
/// intervention. Confirmed on a real UA↔NL WAN benchmark
/// (2026-05-18); see report under `bifrost-wan-test-2026-05-18`.
fn configure_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = socket2::SockRef::from(stream);
    // .with_interval()/.with_retries() are only available on Unix targets in
    // socket2 — Windows accepts only .with_time(). Gate accordingly so the
    // crate builds on x86_64-pc-windows-msvc.
    #[cfg(unix)]
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(3))
        .with_retries(3);
    #[cfg(not(unix))]
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10));
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
    vk.verify_strict(&buf, &Signature::from_bytes(sig))
        .context("handshake: signature verification failed")
}

/// Establish the transport byte stream for one TCP connection.
///
/// When `obfs_key` is set (roadmap #7) the obfuscation nonce exchange
/// runs first, on the raw socket, then both halves are wrapped in the
/// keystream obfuscator — so the NRN1 handshake that follows is itself
/// obfuscated. With no key the halves are returned plain. Either way
/// the result is one concrete reader/writer type the caller threads
/// through `handshake_over_stream` and `handle_conn`.
#[mutants::skip]
async fn establish(
    stream: TcpStream,
    obfs_key: Option<[u8; 32]>,
) -> io::Result<(ObfsReader<OwnedReadHalf>, ObfsWriter<OwnedWriteHalf>)> {
    match obfs_key {
        Some(key) => {
            let mut stream = stream;
            let hs = crate::obfs::obfs_handshake(&mut stream, &key).await?;
            let (r, w) = stream.into_split();
            Ok(hs.wrap(r, w))
        }
        None => {
            let (r, w) = stream.into_split();
            Ok((ObfsReader::plain(r), ObfsWriter::plain(w)))
        }
    }
}

/// Generic NRN1 authenticated handshake over any AsyncRead+AsyncWrite pair.
/// Extracted so the QUIC transport (`src/quic.rs`) can reuse exactly the
/// same wire protocol as the TCP transport — peers on either transport
/// authenticate identically.
#[mutants::skip]
pub async fn handshake_over_stream<R, W>(
    reader: &mut R,
    writer: &mut W,
    signing_key: &SigningKey,
) -> Result<[u8; 32]>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let our_pub = signing_key.verifying_key().to_bytes();
    let mut our_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut our_nonce);

    let mut hello = Vec::with_capacity(4 + 32 + 32);
    hello.extend_from_slice(&HANDSHAKE_MAGIC);
    hello.extend_from_slice(&our_pub);
    hello.extend_from_slice(&our_nonce);

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

    if their_pub == our_pub {
        bail!("handshake: peer announced our own pub_key (self-loop)");
    }
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
    // Per-source-IP in-flight handshake counter. Bounds Eclipse-attack capacity
    // from a single endpoint regardless of global capacity. See MAX_PER_IP_HANDSHAKES.
    let per_ip_counts: Arc<Mutex<std::collections::HashMap<std::net::IpAddr, usize>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));

    loop {
        let (stream, peer_addr) = match listener.accept().await {
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

        // Per-IP rate-limit. Bump the IP's counter atomically; if it would
        // exceed MAX_PER_IP_HANDSHAKES we drop and release the global permit.
        // The counter is decremented in a Drop-guard so handshake errors do
        // not leak slots.
        let ip = peer_addr.ip();
        {
            let mut counts = per_ip_counts.lock_or_recover();
            let entry = counts.entry(ip).or_insert(0);
            if *entry >= MAX_PER_IP_HANDSHAKES {
                warn!(
                    "per-IP handshake limit reached for {} ({} in flight), dropping",
                    ip, *entry
                );
                drop(stream);
                continue;
            }
            *entry += 1;
        }
        let ip_guard = PerIpGuard { ip, counts: per_ip_counts.clone() };

        let conn = conn.clone();
        let connected = connected.clone();
        tokio::spawn(async move {
            // ip_guard lives through the handshake and drops on either path —
            // success (we move into the long-lived loop) or failure.
            let _ip_guard = ip_guard;
            configure_socket(&stream);
            // Capture the OS fd before `establish` consumes the stream —
            // the Linux kernel-stats poller needs it; it stays valid for
            // the life of the split halves.
            #[cfg(target_os = "linux")]
            let fd = {
                use std::os::fd::AsRawFd;
                stream.as_raw_fd()
            };
            #[cfg(not(target_os = "linux"))]
            let fd: i32 = 0;

            // Roadmap #7: obfuscation nonce exchange (when a PSK is set)
            // + split + the NRN1 authenticated handshake, all under one
            // timeout. The obfuscation wraps the NRN1 handshake itself.
            let obfs_key = conn.obfuscation_key();
            let hs_result = timeout(HANDSHAKE_TIMEOUT, async {
                let (mut reader, mut writer) = establish(stream, obfs_key).await?;
                let remote_pub =
                    handshake_over_stream(&mut reader, &mut writer, conn.signing_key()).await?;
                Ok::<_, anyhow::Error>((remote_pub, reader, writer))
            }).await;

            // Release the handshake permit before the long-lived read loop.
            drop(permit);

            let (remote_pub, reader, writer) = match hs_result {
                Err(_) => { warn!("handshake timed out from {}", peer_addr); return; }
                Ok(Err(e)) => { warn!("handshake failed from {}: {:#}", peer_addr, e); return; }
                Ok(Ok(v)) => v,
            };

            // Sybil-resistance: refuse peers whose pub_key has insufficient
            // built-in proof-of-work. Each extra bit doubles the cost of
            // generating an identity.
            let min_bits = conn.min_peer_difficulty_bits();
            if min_bits > 0 {
                let got = crate::address::key_difficulty_bits(&remote_pub);
                if got < min_bits {
                    warn!(
                        "rejecting inbound from {} ({:?}): difficulty {} < required {}",
                        peer_addr, &remote_pub[..4], got, min_bits
                    );
                    return;
                }
            }

            // Per-peer link cap: accept up to MAX_PARALLEL_LINKS_PER_PEER
            // inbound connections from the same pub_key (multi-TCP
            // bonding). Each link runs its own NRN1 handshake and gets
            // its own writer task on the PacketConn side; the link
            // count grows here and shrinks in the cleanup at function
            // exit.
            {
                use crate::router::MAX_PARALLEL_LINKS_PER_PEER;
                let mut map = connected.lock_or_recover();
                let count = map.entry(remote_pub).or_insert(0);
                if (*count as usize) >= MAX_PARALLEL_LINKS_PER_PEER {
                    debug!(
                        "inbound from {:?} at cap ({} links), dropping",
                        &remote_pub[..4], *count
                    );
                    return;
                }
                *count += 1;
            }
            info!("accepted peer {:?} from {}", &remote_pub[..4], peer_addr);
            let poller = spawn_tcp_info_poller(fd, remote_pub, conn.clone());
            conn.handle_conn(remote_pub, reader, writer, 0).await;
            poller.abort();
            // Decrement link count; remove the entry when it hits 0
            // so subsequent dials don't see a stale zero blocking
            // them on the cap.
            {
                let mut map = connected.lock_or_recover();
                if let Some(count) = map.get_mut(&remote_pub) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        map.remove(&remote_pub);
                    }
                }
            }
        });
    }
}

/// Dial a peer by URI with automatic reconnection (exponential backoff).
// Skip mutations: retry loop with real TcpStream connect and backoff —
// mutations to connection logic, dedup, and backoff require a live network.
#[mutants::skip]
/// Persistent dial: retries forever with capped backoff. Used for configured
/// peers, the peer cache, and operator-initiated (admin) dials, where we want
/// to keep trying to reach a known, trusted endpoint indefinitely.
pub async fn dial(uri: &str, conn: Arc<PacketConn>, connected: ConnectedPeers) {
    dial_inner(uri, conn, connected, None).await;
}

/// Discovery-triggered dial: bounded retry. Used for unauthenticated mDNS /
/// multicast beacons so a flood of fake pub_keys can't spawn unbounded
/// persistent dial tasks (see [`DISCOVERY_DIAL_MAX_ATTEMPTS`]). A genuine peer
/// that drops is re-dialled when it next beacons.
pub async fn dial_discovered(uri: &str, conn: Arc<PacketConn>, connected: ConnectedPeers) {
    dial_inner(uri, conn, connected, Some(DISCOVERY_DIAL_MAX_ATTEMPTS)).await;
}

async fn dial_inner(
    uri: &str,
    conn: Arc<PacketConn>,
    connected: ConnectedPeers,
    max_attempts: Option<u32>,
) {
    let addr = match parse_tcp_uri(uri) {
        Ok(a) => a,
        Err(e) => { warn!("bad peer URI {}: {}", uri, e); return; }
    };

    let mut delay = Duration::from_secs(1);
    // Consecutive failed iterations (reset on a successful connection). When
    // `max_attempts` is Some, give up once this reaches the cap so an
    // unauthenticated beacon cannot keep a retry loop alive forever. Checked at
    // the top so EVERY retry path (connect fail, handshake fail, difficulty
    // refusal, link-cap poll) counts uniformly.
    let mut attempts: u32 = 0;
    loop {
        if let Some(max) = max_attempts
            && attempts >= max {
            debug!("dial to {} giving up after {} failed attempts", addr, attempts);
            return;
        }
        attempts += 1;
        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                configure_socket(&stream);
                // Capture the OS fd before `establish` consumes the stream.
                #[cfg(target_os = "linux")]
                let fd = {
                    use std::os::fd::AsRawFd;
                    stream.as_raw_fd()
                };
                #[cfg(not(target_os = "linux"))]
                let fd: i32 = 0;

                // Roadmap #7: obfuscation nonce exchange (when a PSK is
                // set) + split + the NRN1 handshake, all under one timeout.
                let obfs_key = conn.obfuscation_key();
                let hs = timeout(HANDSHAKE_TIMEOUT, async {
                    let (mut reader, mut writer) = establish(stream, obfs_key).await?;
                    let remote_pub =
                        handshake_over_stream(&mut reader, &mut writer, conn.signing_key()).await?;
                    Ok::<_, anyhow::Error>((remote_pub, reader, writer))
                }).await;
                let hs_res: Result<(
                    [u8; 32],
                    ObfsReader<OwnedReadHalf>,
                    ObfsWriter<OwnedWriteHalf>,
                )> = match hs {
                    Err(_) => Err(anyhow::anyhow!("handshake timed out")),
                    Ok(r) => r,
                };
                match hs_res {
                    Ok((remote_pub, reader, writer)) => {
                        // Symmetric Sybil-resistance check on outbound side:
                        // if the remote's pub_key falls below our minimum
                        // difficulty we drop and back off — peer cannot meet
                        // our policy so the cache shouldn't keep dialing it.
                        let min_bits = conn.min_peer_difficulty_bits();
                        if min_bits > 0 {
                            let got = crate::address::key_difficulty_bits(&remote_pub);
                            if got < min_bits {
                                warn!(
                                    "outbound: refusing peer {:?} at {} (difficulty {} < required {})",
                                    &remote_pub[..4], addr, got, min_bits
                                );
                                tokio::time::sleep(Duration::from_secs(300)).await;
                                continue;
                            }
                        }

                        // ── Crossing-dial deterministic tiebreak ──────────
                        // If BOTH peers dial each other simultaneously, naïve
                        // first-insert-wins dedup can leave each side keeping
                        // a TCP whose far-end the OTHER side dropped on its
                        // own dedup → both connections die. The classic fix:
                        // smaller-pub-key role = "dialer", larger = "accepter".
                        // The larger-pub side yields its dial to the peer's.
                        //
                        // BUT that only works if the peer actually dials us.
                        // A listen-only node (e.g. a bifrost-vpnd exit, whose
                        // `peers` list is empty) never dials back, so a client
                        // whose pub_key sorts higher than the exit's would
                        // defer forever. So: only yield if the peer has in
                        // fact reached us — wait briefly for their inbound
                        // dial, and if none appears, keep the link we already
                        // established.
                        let our_pub = conn.pub_key;
                        if our_pub > remote_pub {
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            let peer_reached_us = {
                                let map = connected.lock_or_recover();
                                map.get(&remote_pub).copied().unwrap_or(0) > 0
                            };
                            if peer_reached_us {
                                debug!(
                                    "dial yielded: peer {:?} reached us via its own dial \
                                     (we are the larger pub)",
                                    &remote_pub[..4]
                                );
                                tokio::time::sleep(Duration::from_secs(30)).await;
                                continue;
                            }
                            debug!(
                                "dial kept: no inbound from {:?} — peer is listen-only, \
                                 keeping our dialed link",
                                &remote_pub[..4]
                            );
                        }

                        // Per-peer link cap: refuse dial only when we
                        // already have MAX_PARALLEL_LINKS_PER_PEER live
                        // links to this pub_key (multi-TCP bonding).
                        // Take + release the MutexGuard in a tight scope
                        // before the `await` below — `MutexGuard` isn't
                        // `Send` so it can't live across an await point.
                        let count_now = {
                            let map = connected.lock_or_recover();
                            map.get(&remote_pub).copied().unwrap_or(0)
                        };
                        use crate::router::MAX_PARALLEL_LINKS_PER_PEER;
                        if (count_now as usize) >= MAX_PARALLEL_LINKS_PER_PEER {
                            debug!(
                                "already at {} links to {:?}, not adding more",
                                count_now, &remote_pub[..4]
                            );
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            continue;
                        }
                        {
                            let mut map = connected.lock_or_recover();
                            *map.entry(remote_pub).or_insert(0) += 1;
                        }
                        info!("connected to peer {:?} at {}", &remote_pub[..4], addr);
                        // Kernel TCP-info poller (Linux); no-op elsewhere.
                        let poller = spawn_tcp_info_poller(fd, remote_pub, conn.clone());
                        conn.handle_conn(remote_pub, reader, writer, 0).await;
                        poller.abort();
                        // handle_conn spawns reader/writer tasks and returns.
                        // Decrement link count on disconnect so re-dials
                        // can grab the slot back.
                        {
                            let mut map = connected.lock_or_recover();
                            if let Some(count) = map.get_mut(&remote_pub) {
                                *count = count.saturating_sub(1);
                                if *count == 0 {
                                    map.remove(&remote_pub);
                                }
                            }
                        }
                        // Reset backoff + failure counter on successful connect:
                        // a peer that genuinely connects (its handshake validated)
                        // is never given up on by the discovery bound.
                        delay = Duration::from_secs(5);
                        attempts = 0;
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

    // ── PerIpGuard counter accounting ────────────────────────────────────────

    #[test]
    fn per_ip_guard_decrements_on_drop() {
        let counts: Arc<Mutex<std::collections::HashMap<std::net::IpAddr, usize>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));
        let ip: std::net::IpAddr = "10.1.2.3".parse().unwrap();
        // Simulate two simultaneous handshakes.
        counts.lock().unwrap().insert(ip, 2);
        let g1 = PerIpGuard { ip, counts: counts.clone() };
        let g2 = PerIpGuard { ip, counts: counts.clone() };
        drop(g1);
        assert_eq!(*counts.lock().unwrap().get(&ip).unwrap(), 1,
            "drop must decrement to 1");
        drop(g2);
        assert!(!counts.lock().unwrap().contains_key(&ip),
            "drop to zero must remove the entry to bound map growth");
    }

    #[test]
    fn per_ip_guard_saturating_sub_handles_unexpected_zero() {
        // If the counter were somehow already 0 (programming bug elsewhere)
        // the Drop must NOT panic on overflow — saturating_sub guarantees it.
        let counts: Arc<Mutex<std::collections::HashMap<std::net::IpAddr, usize>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));
        let ip: std::net::IpAddr = "::1".parse().unwrap();
        counts.lock().unwrap().insert(ip, 0);
        let g = PerIpGuard { ip, counts: counts.clone() };
        drop(g); // must not panic
        assert!(!counts.lock().unwrap().contains_key(&ip),
            "decrement-from-zero path must still evict the entry");
    }

    #[test]
    fn per_ip_handshake_cap_is_nontrivial() {
        // Sanity: the cap exists and is small enough that one attacker IP
        // can't monopolise the global pool. Wrapped in const blocks so
        // clippy doesn't flag them as always-true runtime assertions —
        // they're really compile-time invariants.
        const _: () = assert!(MAX_PER_IP_HANDSHAKES > 0);
        const _: () = assert!(MAX_PER_IP_HANDSHAKES * 16 <= MAX_PENDING_HANDSHAKES);
    }

    // ── Discovery dial is bounded (DoS: unbounded persistent dials) ───────────

    #[tokio::test(start_paused = true)]
    async fn dial_discovered_gives_up_on_persistent_failure() {
        // A discovery-triggered dial to an endpoint that never accepts MUST
        // give up (return) rather than retry forever. Otherwise an on-LAN
        // attacker flooding fake-pub beacons spawns one unbounded persistent
        // task per fake key. `dial()` (None) loops forever by design; the
        // bounded `dial_discovered()` must terminate. 127.0.0.1:1 refuses
        // instantly and `start_paused` auto-advances the backoff sleeps, so
        // this completes fast in virtual time.
        use std::collections::HashMap;
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let conn = Arc::new(crate::router::PacketConn::new(sk));
        let connected: ConnectedPeers = Arc::new(Mutex::new(HashMap::new()));
        let done = tokio::time::timeout(
            Duration::from_secs(3600),
            dial_discovered("tcp://127.0.0.1:1", conn, connected),
        ).await;
        assert!(done.is_ok(),
            "bounded discovery dial must terminate on persistent failure, not hang forever");
    }
}
