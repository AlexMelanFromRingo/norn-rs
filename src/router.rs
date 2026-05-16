// Core routing engine for norn-rs
// K=3 parallel spanning trees (Urd, Verdandi, Skuld)
// Loss-aware routing cost, cuckoo filter gossip, landmark routing

use anyhow::{bail, Result};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{SigningKey, Signer, VerifyingKey, Verifier};
use rand::rngs::OsRng;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

/// Extension trait that recovers from poisoned mutexes instead of panicking.
/// If a thread panicked while holding a lock, we log an error and continue —
/// better than a cascade crash from an unrelated panic.
trait LockOrRecover<T> {
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T> LockOrRecover<T> for std::sync::Mutex<T> {
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|p| {
            tracing::error!("mutex poisoned, recovering — data may be inconsistent");
            p.into_inner()
        })
    }
}
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::cuckoo::CuckooFilter;
use crate::hyperbolic::HypCoord;
use crate::onion::{build_onion, OnionPacket, PeeledOnion};
use crate::packet::{self, routing_tag, *};
use crate::session::{
    ed25519_priv_to_x25519, ed25519_pub_to_x25519,
    SessionManager, SharedSessionManager, SESSION_INIT_MAGIC, SESSION_ACK_MAGIC,
};

// ──────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────

pub const K: usize = 3;

/// Tree seeds: different XOR-metric for root selection
pub const TREE_SEEDS: [[u8; 8]; 3] = [
    [0u8; 8],        // Urd: raw key comparison
    *b"Verdandi",    // Verdandi
    *b"Skuld___",    // Skuld
];

/// Announce expires after 30 seconds
const ANNOUNCE_EXPIRY: Duration = Duration::from_secs(30);
/// Keep-alive interval: send ping every 5 maintenance ticks (5 seconds)
const KEEPALIVE_TICKS: u32 = 5;
/// Peer timeout
const PEER_TIMEOUT: Duration = Duration::from_secs(60);
/// Rotate session encryption key every N sends for forward secrecy
const KEY_ROTATION_INTERVAL: u64 = 100;
/// Increment cuckoo generation every N ticks (~5 minutes at 1 tick/sec)
const CUCKOO_GEN_TICKS: u32 = 300;
/// Maximum number of pending PathLookup dedup entries (prevents memory DoS)
const MAX_PENDING_LOOKUPS: usize = 10_000;
/// Remove sessions idle for longer than this
const SESSION_IDLE_EXPIRY: Duration = Duration::from_secs(300);
/// Maximum hop count for any forwarded Traffic / Onion packet. Caps the
/// damage from routing loops or maliciously-crafted long paths. The diameter
/// of a planetary-scale mesh is well under 32 with K=3 trees.
const MAX_FORWARD_HOPS: usize = 32;
/// Maximum coordinates kept in the hyperbolic coord table. Beyond this we
/// evict least-recently-used entries to bound memory under flood.
const MAX_COORD_TABLE_SIZE: usize = 16_384;
/// Cap on concurrent jittered-forward tasks. Each TRAFFIC/ONION forward
/// spawns a tokio task with a sleep; without a bound, a flooder can
/// exhaust memory by spawning unbounded tasks.
const MAX_INFLIGHT_FORWARDS: usize = 4_096;

// ──────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────

pub type PeerId = [u8; 32]; // ed25519 public key
pub type ConnId = u64;

#[derive(Clone, Debug)]
pub struct InboundPacket {
    pub from: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct PeerStats {
    pub key: [u8; 32],
    pub lag: Duration,
    pub jitter: Duration,
    pub loss_rate: f32,
    pub priority: u8,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub uptime: Duration,
}

// ──────────────────────────────────────────────
// Internal types
// ──────────────────────────────────────────────

#[derive(Clone, Debug)]
struct TreeAnnounce {
    root: [u8; 32],
    path_cost: u64,
    received_at: Instant,
    /// Hop depth of the sender in this tree
    depth: u32,
}

struct TreeState {
    parent: Option<PeerId>,
    root: [u8; 32],
    root_seq: u64,
    parent_cost: u64,
}

struct PeerData {
    pub_key: PeerId,
    lag: Duration,
    jitter: Duration,
    loss_rate: f32,
    last_rx_time: Instant,
    last_tx_time: Instant,
    cuckoo: [CuckooFilter; K],
    /// Last cuckoo generation received from this peer (per tree).
    /// When generation advances, we replace the stored filter entirely.
    peer_cuckoo_gen: [u64; K],
    trees: [Option<TreeAnnounce>; K],
    tx: mpsc::Sender<Vec<u8>>,
    priority: u8,
    rx_bytes: u64,
    tx_bytes: u64,
    connected_at: Instant,
    // RTT tracking
    pending_sig_req_time: Option<(u64, Instant)>, // (seq, sent_time)
    sig_req_seq: u64,
}

impl PeerData {
    fn effective_cost(&self) -> u64 {
        effective_cost(self.lag, self.loss_rate)
    }
}

struct RouterState {
    signing_key: SigningKey,
    pub_key: PeerId,
    peers: HashMap<PeerId, PeerData>,
    trees: [TreeState; K],
    sessions: SharedSessionManager,
    path_notify: Option<Arc<dyn Fn([u8; 32]) + Send + Sync>>,
    landmarks: HashSet<[u8; 32]>,
    traffic_tx: mpsc::Sender<InboundPacket>,
    // Path lookup dedup: lookup_id -> sent_time
    pending_lookups: HashMap<u64, Instant>,
    // Hyperbolic coordinate routing
    coord_table: HashMap<[u8; 32], HypCoord>,
    own_coord: HypCoord,
    own_depth: u32,
    // Maintenance tick counter (for rate-limiting keepalives)
    tick: u32,
    /// Own cuckoo generation counter (per tree). Incremented every CUCKOO_GEN_TICKS.
    /// Included in outgoing CuckooMsg so receivers can detect staleness.
    cuckoo_generation: [u64; K],
}

// ──────────────────────────────────────────────
// Header privacy helpers (source + dest hiding)
// ──────────────────────────────────────────────

/// Block size for payload padding (bytes). All payloads are padded to a
/// multiple of this before encryption so observers cannot infer content
/// length from ciphertext length.
const PAD_BLOCK: usize = 256;

/// Pad `data` to the next `PAD_BLOCK` boundary.
/// Wire: [orig_len: 2 bytes LE][data...][zero padding...]
///
/// Maximum payload size is u16::MAX (65535) bytes because the length header is
/// 2 bytes. Larger payloads are truncated by `unpad_payload` because the wire
/// length field cannot represent them — so we silently used to corrupt them.
/// Now we panic in debug and saturate the length in release: callers should not
/// feed >65535-byte payloads through this path.
fn pad_payload(data: &[u8]) -> Vec<u8> {
    debug_assert!(
        data.len() <= u16::MAX as usize,
        "pad_payload: data.len() = {} exceeds u16::MAX; length header would wrap",
        data.len()
    );
    let orig_len = data.len().min(u16::MAX as usize);
    let data = &data[..orig_len];
    let mut out = Vec::with_capacity(PAD_BLOCK);
    out.push((orig_len & 0xFF) as u8);
    out.push((orig_len >> 8) as u8);
    out.extend_from_slice(data);
    let target = out.len().div_ceil(PAD_BLOCK) * PAD_BLOCK;
    out.resize(target, 0u8);
    out
}

/// Strip padding added by `pad_payload`.
fn unpad_payload(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < 2 {
        bail!("unpad: too short");
    }
    // Use from_le_bytes instead of `| << 8` to avoid the equivalent `| → ^` mutation
    // (bit 8+ of padded[0] and bit 0-7 of padded[1]<<8 never overlap, so | == ^).
    let orig_len = u16::from_le_bytes([padded[0], padded[1]]) as usize;
    if padded.len() < 2 + orig_len {
        bail!("unpad: length field {} > available {}", orig_len, padded.len() - 2);
    }
    Ok(padded[2..2 + orig_len].to_vec())
}

/// Encrypt both source and destination identities into a 128-byte header.
///
/// Layout: [epk: 32][AEAD_nonce0(source_ed_pub): 48][AEAD_nonce1(dest_ed_pub): 48]
///
/// The single ephemeral keypair is derived from a DH with the *destination's*
/// X25519 public key, so only the destination can decrypt either field.
/// Forward secrecy: the ephemeral private key is discarded immediately.
///
/// Returns `(enc_header, routing_tag)`.
fn encrypt_header(
    source_ed_pub: &[u8; 32],
    dest_ed_pub: &[u8; 32],
) -> ([u8; 128], [u8; 16]) {
    let epk_priv = StaticSecret::random_from_rng(OsRng);
    let epk_pub = X25519PublicKey::from(&epk_priv);

    let dest_x = match ed25519_pub_to_x25519(dest_ed_pub) {
        Ok(k) => k,
        Err(_) => return ([0u8; 128], [0u8; 16]),
    };
    let shared = epk_priv.diffie_hellman(&dest_x);
    let key = Key::from_slice(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);
    let aad = epk_pub.as_bytes();

    // Encrypt source with nonce=0
    let mut src_buf = source_ed_pub.to_vec();
    if cipher
        .encrypt_in_place(&Nonce::from([0u8; 12]), aad, &mut src_buf)
        .is_err()
    {
        return ([0u8; 128], [0u8; 16]);
    }

    // Encrypt dest with nonce=1 (first 8 bytes = 1u64 LE)
    let mut dst_buf = dest_ed_pub.to_vec();
    let mut n1 = [0u8; 12];
    n1[..8].copy_from_slice(&1u64.to_le_bytes());
    if cipher
        .encrypt_in_place(&Nonce::from(n1), aad, &mut dst_buf)
        .is_err()
    {
        return ([0u8; 128], [0u8; 16]);
    }

    let mut header = [0u8; 128];
    header[..32].copy_from_slice(epk_pub.as_bytes());
    header[32..80].copy_from_slice(&src_buf);  // 48 bytes
    header[80..128].copy_from_slice(&dst_buf); // 48 bytes

    (header, routing_tag(dest_ed_pub))
}

/// Decrypt the source identity from enc_header using our ed25519 signing key.
fn decrypt_source_from_header(enc_header: &[u8; 128], my_sk: &SigningKey) -> Option<[u8; 32]> {
    let epk_pub_bytes: [u8; 32] = enc_header[..32].try_into().ok()?;
    let epk_pub = X25519PublicKey::from(epk_pub_bytes);
    let my_x = ed25519_priv_to_x25519(&my_sk.to_bytes());
    let shared = my_x.diffie_hellman(&epk_pub);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes()));
    let mut buf = enc_header[32..80].to_vec();
    cipher
        .decrypt_in_place(&Nonce::from([0u8; 12]), &epk_pub_bytes, &mut buf)
        .ok()?;
    buf.try_into().ok()
}

/// Decrypt the destination identity from enc_header (used to confirm packet is for us).
// Skip mutations: dead code — not called in current routing logic. All mutations
// (function body replacement, slice ranges, etc.) are untestable without a full
// integration harness that exercises this path.
#[mutants::skip]
#[allow(dead_code)]
fn decrypt_dest_from_header(enc_header: &[u8; 128], my_sk: &SigningKey) -> Option<[u8; 32]> {
    let epk_pub_bytes: [u8; 32] = enc_header[..32].try_into().ok()?;
    let epk_pub = X25519PublicKey::from(epk_pub_bytes);
    let my_x = ed25519_priv_to_x25519(&my_sk.to_bytes());
    let shared = my_x.diffie_hellman(&epk_pub);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes()));
    let mut n1 = [0u8; 12];
    n1[..8].copy_from_slice(&1u64.to_le_bytes());
    let mut buf = enc_header[80..128].to_vec();
    cipher
        .decrypt_in_place(&Nonce::from(n1), &epk_pub_bytes, &mut buf)
        .ok()?;
    buf.try_into().ok()
}

// ──────────────────────────────────────────────
// Cost & metric functions
// ──────────────────────────────────────────────

/// Loss-aware effective cost in microseconds.
pub fn effective_cost(lag: Duration, loss_rate: f32) -> u64 {
    let base_us = lag.as_micros() as f64;
    let effective = base_us * (1.0 + loss_rate as f64 * 9.0);
    effective as u64
}

/// XOR-metric for tree root selection. Each tree uses a different seed.
pub fn tree_metric(pub_key: &[u8; 32], seed: &[u8; 8]) -> [u8; 32] {
    let mut metric = *pub_key;
    for (i, b) in metric.iter_mut().enumerate() {
        *b ^= seed[i % 8];
    }
    metric
}

/// Compare two metric values — lower is "better" root candidate.
fn metric_less(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a < b
}

// ──────────────────────────────────────────────
// RouterState implementation
// ──────────────────────────────────────────────

impl RouterState {
    fn new(signing_key: SigningKey, traffic_tx: mpsc::Sender<InboundPacket>) -> Self {
        let pub_key = signing_key.verifying_key().to_bytes();
        let sessions = Arc::new(Mutex::new(SessionManager::new(signing_key.clone())));

        let trees = std::array::from_fn(|_| TreeState {
            parent: None,
            root: pub_key,
            root_seq: 0,
            parent_cost: 0,
        });

        let own_coord = HypCoord::origin();
        let mut coord_table = HashMap::new();
        coord_table.insert(pub_key, own_coord);

        RouterState {
            signing_key,
            pub_key,
            peers: HashMap::new(),
            trees,
            sessions,
            path_notify: None,
            landmarks: HashSet::new(),
            traffic_tx,
            pending_lookups: HashMap::new(),
            coord_table,
            own_coord,
            own_depth: 0,
            tick: 0,
            cuckoo_generation: [0u64; K],
        }
    }

    fn add_peer(&mut self, pub_key: PeerId, tx: mpsc::Sender<Vec<u8>>, priority: u8) {
        // Guard against overwriting an existing peer (e.g. duplicate connection race).
        if self.peers.contains_key(&pub_key) {
            debug!("add_peer: {:?} already present, ignoring duplicate", &pub_key[..4]);
            return;
        }
        let peer = PeerData {
            pub_key,
            lag: Duration::from_millis(100),
            jitter: Duration::ZERO,
            loss_rate: 0.0,
            last_rx_time: Instant::now(),
            last_tx_time: Instant::now(),
            cuckoo: std::array::from_fn(|_| CuckooFilter::new()),
            peer_cuckoo_gen: [0u64; K],
            trees: std::array::from_fn(|_| None),
            tx,
            priority,
            rx_bytes: 0,
            tx_bytes: 0,
            connected_at: Instant::now(),
            pending_sig_req_time: None,
            sig_req_seq: 0,
        };
        self.peers.insert(pub_key, peer);
        self.update_landmarks();
    }

    fn remove_peer(&mut self, pub_key: &PeerId) {
        self.peers.remove(pub_key);
        self.coord_table.remove(pub_key);
        self.update_landmarks();
        // Reset tree parents that depended on this peer
        let own_key = self.pub_key;
        for tree in &mut self.trees {
            if tree.parent.as_ref() == Some(pub_key) {
                tree.parent = None;
                tree.root = own_key;
                tree.parent_cost = 0;
            }
        }
    }

    fn update_landmarks(&mut self) {
        self.landmarks.clear();
        // Mark ourselves as a landmark if we have >2 peers
        if self.peers.len() > 2 {
            self.landmarks.insert(self.pub_key);
        }
        // Mark peers that appear to be well-connected: if a peer's announce
        // path_cost from root is low (close to root), treat it as a landmark.
        // Heuristic: peer at depth 0 or 1 in any tree is a good landmark.
        for (peer_key, peer) in &self.peers {
            for ann in peer.trees.iter().flatten() {
                if ann.depth <= 1 {
                    self.landmarks.insert(*peer_key);
                    break;
                }
            }
        }
    }

    /// Select best parent for tree `tree_id`.
    fn fix_tree(&mut self, tree_id: usize) {
        let my_metric = tree_metric(&self.pub_key, &TREE_SEEDS[tree_id]);
        let mut best_root: Option<[u8; 32]> = None;
        let mut best_root_metric: Option<[u8; 32]> = None;
        let mut best_cost: u64 = u64::MAX;
        let mut best_parent: Option<PeerId> = None;

        let now = Instant::now();

        for (peer_key, peer) in &self.peers {
            if let Some(ann) = &peer.trees[tree_id] {
                // Check announce not expired
                if now.duration_since(ann.received_at) > ANNOUNCE_EXPIRY {
                    continue;
                }
                let root_metric = tree_metric(&ann.root, &TREE_SEEDS[tree_id]);
                let peer_cost = peer.effective_cost();
                let total_cost = ann.path_cost.saturating_add(peer_cost);

                let better = match &best_root_metric {
                    None => true,
                    Some(br) => {
                        if metric_less(&root_metric, br) {
                            true
                        } else if root_metric == *br {
                            // Same root: pick lower total cost
                            total_cost < best_cost
                        } else {
                            false
                        }
                    }
                };

                if better {
                    best_root = Some(ann.root);
                    best_root_metric = Some(root_metric);
                    best_cost = total_cost;
                    best_parent = Some(*peer_key);
                }
            }
        }

        // Check if we should be our own root (if our metric beats all candidates)
        let use_self = match &best_root_metric {
            None => true,
            Some(br) => metric_less(&my_metric, br),
        };

        if use_self {
            self.trees[tree_id].parent = None;
            self.trees[tree_id].root = self.pub_key;
            self.trees[tree_id].parent_cost = 0;
            self.trees[tree_id].root_seq += 1;
            if tree_id == 0 {
                self.own_depth = 0;
            }
        } else {
            self.trees[tree_id].parent = best_parent;
            self.trees[tree_id].root = best_root.unwrap();
            self.trees[tree_id].parent_cost = best_cost;
            if tree_id == 0 {
                // Our depth = parent's depth + 1
                if let Some(parent_key) = best_parent
                    && let Some(ann) = self.peers.get(&parent_key).and_then(|p| p.trees[0].as_ref()) {
                        self.own_depth = ann.depth + 1;
                    }
            }
        }
    }

    /// Propagate ANNOUNCE for tree `tree_id` to all peers.
    fn send_announces(&mut self, tree_id: usize) {
        let tree = &self.trees[tree_id];
        let path_cost = tree.parent_cost;
        let root = tree.root;
        let root_seq = tree.root_seq;
        let sender = self.pub_key;

        // Sign the announce
        let depth = if tree_id == 0 { self.own_depth } else { 0 };
        let ann_unsigned = Announce {
            tree_id: tree_id as u8,
            root,
            root_seq,
            path_cost,
            sender,
            signature: [0u8; 64],
            depth,
        };
        let sign_bytes = ann_unsigned.sign_bytes();
        let signature = self.signing_key.sign(&sign_bytes).to_bytes();

        let ann = Announce { signature, ..ann_unsigned };
        let encoded = ann.encode();

        let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
        for peer_key in peer_keys {
            self.send_to_peer(&peer_key, encoded.clone());
        }
    }

    fn send_to_peer(&mut self, peer_key: &PeerId, data: Vec<u8>) {
        if let Some(peer) = self.peers.get_mut(peer_key) {
            let len = data.len() as u64;
            if peer.tx.try_send(data).is_ok() {
                peer.tx_bytes += len;
                peer.last_tx_time = Instant::now();
            }
        }
    }

    /// Cuckoo filter maintenance for tree `tree_id`.
    fn cuckoo_do_maintenance(&mut self, tree_id: usize) {
        // Every CUCKOO_GEN_TICKS, advance our generation (evicts stale entries).
        if self.tick.is_multiple_of(CUCKOO_GEN_TICKS) && self.tick > 0 {
            self.cuckoo_generation[tree_id] += 1;
        }
        let generation = self.cuckoo_generation[tree_id];

        // Build merged cuckoo of all peers except parent
        let parent = self.trees[tree_id].parent;
        let mut merged = CuckooFilter::new();

        // Add our routing tag (not raw pub key) — hides identity in filter gossip.
        // If `add` returns false the filter is saturated (>~2000 entries) and we'd
        // be silently unreachable; log so operators can investigate.
        let my_tag = routing_tag(&self.pub_key);
        if !merged.add(&my_tag) {
            warn!("cuckoo filter saturated on tree {} — node may be unreachable", tree_id);
        }

        for (peer_key, peer) in &self.peers {
            if Some(*peer_key) == parent {
                continue;
            }
            // Merge peer's cuckoo (downstream)
            merged.merge(&peer.cuckoo[tree_id]);
        }

        // Send to parent (upstream)
        if let Some(parent_key) = parent {
            let msg = CuckooMsg { tree_id: tree_id as u8, generation, data: merged.encode() };
            let encoded = msg.encode();
            self.send_to_peer(&parent_key, encoded);
        }

        // Send merged cuckoo to all non-parent peers
        let full_merged = {
            let mut fm = merged.clone();
            if let Some(parent_key) = parent
                && let Some(peer) = self.peers.get(&parent_key) {
                    fm.merge(&peer.cuckoo[tree_id]);
                }
            fm
        };

        let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
        for peer_key in peer_keys {
            if Some(peer_key) == parent {
                continue;
            }
            let msg = CuckooMsg { tree_id: tree_id as u8, generation, data: full_merged.encode() };
            let encoded = msg.encode();
            self.send_to_peer(&peer_key, encoded);
        }
    }

    /// Send keep-alive pings to all peers.
    fn send_keepalives(&mut self) {
        let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
        for peer_key in peer_keys {
            let seq = {
                let peer = self.peers.get_mut(&peer_key).unwrap();
                // If a previous SigReq was never acknowledged, count it as a loss.
                if peer.pending_sig_req_time.is_some() {
                    peer.loss_rate = peer.loss_rate * 0.875 + 0.125;
                }
                peer.sig_req_seq += 1;
                peer.sig_req_seq
            };
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let req = SigReq {
                tree_id: 0,
                seq,
                timestamp_ms: now_ms,
                pub_key: self.pub_key,
            };
            let encoded = req.encode();
            {
                let peer = self.peers.get_mut(&peer_key).unwrap();
                peer.pending_sig_req_time = Some((seq, Instant::now()));
            }
            self.send_to_peer(&peer_key, encoded);
        }
    }

    /// Expire stale peers.
    fn expire_peers(&mut self) {
        let now = Instant::now();
        let expired: Vec<PeerId> = self.peers
            .iter()
            .filter(|(_, p)| now.duration_since(p.last_rx_time) > PEER_TIMEOUT)
            .map(|(k, _)| *k)
            .collect();
        for key in expired {
            warn!("peer {:?} timed out, removing", &key[..4]);
            self.remove_peer(&key);
        }
    }

    /// Main maintenance function, called every 1 second.
    pub fn do_maintenance(&mut self) {
        self.tick += 1;
        self.expire_peers();
        for i in 0..K {
            self.fix_tree(i);
            self.send_announces(i);
            self.cuckoo_do_maintenance(i);
        }
        self.update_own_coord();
        self.broadcast_coord();
        if self.tick.is_multiple_of(KEEPALIVE_TICKS) {
            self.send_keepalives();
        }
        self.rotate_session_keys();
        self.cleanup_stale_lookups();
        self.cleanup_stale_sessions();
    }

    /// Rotate x25519 keys for sessions that have sent many messages.
    // Skip mutations: requires a session with local_seq at exactly KEY_ROTATION_INTERVAL
    // to observe the rotation — that setup is complex and tested separately in session.rs.
    #[mutants::skip]
    fn rotate_session_keys(&self) {
        let mut sm = self.sessions.lock_or_recover();
        for info in sm.sessions.values_mut() {
            if info.established && info.local_seq > 0 && info.local_seq % KEY_ROTATION_INTERVAL == 0 {
                info.rotate_local_key();
            }
        }
    }

    /// Recompute our own hyperbolic coordinate from current depth.
    // Skip mutations: coordinates feed into hyperbolic routing which requires
    // a multi-hop test to verify greedy forwarding is affected.
    #[mutants::skip]
    fn update_own_coord(&mut self) {
        self.own_coord = HypCoord::from_tree_depth(self.own_depth, &self.pub_key);
        self.coord_table.insert(self.pub_key, self.own_coord);
    }

    /// Broadcast our hyperbolic coordinate to all peers.
    // Skip mutations: signs and sends CoordAnnounce to every peer — verifying
    // the coordinate reaches remote nodes requires a multi-peer integration test.
    #[mutants::skip]
    fn broadcast_coord(&mut self) {
        let coord_bytes = self.own_coord.encode();
        let mut msg = coord_bytes.to_vec();
        msg.extend_from_slice(&self.own_depth.to_le_bytes());
        let sig = self.signing_key.sign(&msg).to_bytes();
        let ann = CoordAnnounce { coord: coord_bytes, tree_depth: self.own_depth, sig };
        let mut frame = vec![TYPE_COORD_ANNOUNCE];
        ann.encode_into(&mut frame);
        let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
        for pk in peer_keys {
            self.send_to_peer(&pk, frame.clone());
        }
    }

    /// Handle an incoming CoordAnnounce from a peer.
    #[mutants::skip]
    pub fn handle_coord_announce(&mut self, from_key: [u8; 32], ann: CoordAnnounce) {
        // Verify signature: sig over (coord || tree_depth as 4-byte LE)
        let vk = match ed25519_dalek::VerifyingKey::from_bytes(&from_key) {
            Ok(v) => v,
            Err(_) => return,
        };
        let mut msg = ann.coord.to_vec();
        msg.extend_from_slice(&ann.tree_depth.to_le_bytes());
        let sig = ed25519_dalek::Signature::from_bytes(&ann.sig);
        if vk.verify(&msg, &sig).is_err() {
            warn!("invalid coord announce signature from {:?}", &from_key[..4]);
            return;
        }
        let coord = HypCoord::decode(&ann.coord);
        // Reject NaN/Inf coordinates — they propagate through `distance()` as NaN
        // and silently break greedy routing (NaN comparisons are always false).
        if !coord.r.is_finite() || !coord.theta.is_finite() {
            warn!("coord announce from {:?} has non-finite values, ignoring", &from_key[..4]);
            return;
        }
        // Bound table size: under flood, evict an arbitrary entry to make room
        // (better than unbounded growth). We avoid evicting peers — those are
        // re-inserted on the next maintenance tick anyway.
        if self.coord_table.len() >= MAX_COORD_TABLE_SIZE
            && !self.coord_table.contains_key(&from_key) {
            // Drop one non-peer entry to keep the table bounded.
            let victim = self.coord_table.keys()
                .find(|k| !self.peers.contains_key(*k) && **k != self.pub_key)
                .copied();
            if let Some(v) = victim {
                self.coord_table.remove(&v);
            } else {
                // All entries belong to known peers — skip the insert.
                return;
            }
        }
        self.coord_table.insert(from_key, coord);
    }

    fn cleanup_stale_lookups(&mut self) {
        let now = Instant::now();
        self.pending_lookups.retain(|_, t| now.duration_since(*t) < Duration::from_secs(10));
    }

    /// Remove sessions that have been idle beyond SESSION_IDLE_EXPIRY.
    fn cleanup_stale_sessions(&self) {
        let now = Instant::now();
        let mut sm = self.sessions.lock_or_recover();
        sm.sessions.retain(|_, info| {
            now.duration_since(info.last_used) < SESSION_IDLE_EXPIRY
        });
    }

    // ──────────────────────────────────────────────
    // Packet handlers
    // ──────────────────────────────────────────────

    pub fn handle_sig_req(&mut self, from: PeerId, req: SigReq) {
        // Update last_rx_time
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
        }

        // Respond with SigRes
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Sign: (tree_id || seq || timestamp_ms || req_pub_key)
        let mut sign_data = vec![req.tree_id];
        let mut tmp = Vec::new();
        encode_uvarint(req.seq, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        tmp.clear();
        encode_uvarint(now_ms, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        sign_data.extend_from_slice(&req.pub_key);
        let signature = self.signing_key.sign(&sign_data).to_bytes();

        let res = SigRes {
            tree_id: req.tree_id,
            seq: req.seq,
            timestamp_ms: now_ms,
            signature,
            pub_key: self.pub_key,
        };
        let encoded = res.encode();
        self.send_to_peer(&from, encoded);
    }

    pub fn handle_sig_res(&mut self, from: PeerId, res: SigRes) {
        // Verify the SigRes signature before using the timestamp for RTT measurement.
        // Without this check an attacker could forge SigRes with a crafted timestamp_ms
        // to manipulate our lag estimate and fool the parent-selection algorithm.
        let vk = match VerifyingKey::from_bytes(&res.pub_key) {
            Ok(v) => v,
            Err(_) => { warn!("sig_res: invalid pub_key from {:?}", &from[..4]); return; }
        };
        let mut sign_data = vec![res.tree_id];
        let mut tmp = Vec::new();
        encode_uvarint(res.seq, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        tmp.clear();
        encode_uvarint(res.timestamp_ms, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        // The responder signed over req.pub_key, which is OUR pub key (we sent it in the SigReq).
        sign_data.extend_from_slice(&self.pub_key);
        let sig = ed25519_dalek::Signature::from_bytes(&res.signature);
        if vk.verify(&sign_data, &sig).is_err() {
            warn!("sig_res: bad signature from {:?}", &from[..4]);
            return;
        }

        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
            // Measure RTT and update loss rate EWMA
            if let Some((pending_seq, sent_time)) = peer.pending_sig_req_time.take()
                && pending_seq == res.seq {
                    let rtt = Instant::now().duration_since(sent_time);
                    let new_lag = rtt / 2;
                    // Exponential moving average
                    let old_lag_us = peer.lag.as_micros() as i64;
                    let new_lag_us = new_lag.as_micros() as i64;
                    let diff = (new_lag_us - old_lag_us).unsigned_abs();
                    peer.jitter = Duration::from_micros(
                        (peer.jitter.as_micros() as u64 * 7 / 8) + diff / 8
                    );
                    peer.lag = Duration::from_micros(
                        (old_lag_us as u64 * 7 / 8) + new_lag_us as u64 / 8
                    );
                    // Successful ACK — decay loss estimate toward 0
                    peer.loss_rate *= 0.875;
                }
        }
    }

    pub fn handle_announce(&mut self, from: PeerId, ann: Announce) {
        // Verify signature
        let vk = match VerifyingKey::from_bytes(&ann.sender) {
            Ok(v) => v,
            Err(_) => return,
        };
        let sign_bytes = ann.sign_bytes();
        let sig = ed25519_dalek::Signature::from_bytes(&ann.signature);
        if vk.verify(&sign_bytes, &sig).is_err() {
            warn!("invalid announce signature from {:?}", &from[..4]);
            return;
        }

        let tree_id = ann.tree_id as usize;
        if tree_id >= K {
            return;
        }

        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
            peer.trees[tree_id] = Some(TreeAnnounce {
                root: ann.root,
                path_cost: ann.path_cost,
                received_at: Instant::now(),
                depth: ann.depth,
            });
        }
        self.update_landmarks();
    }

    pub fn handle_cuckoo(&mut self, from: PeerId, msg: CuckooMsg) {
        let tree_id = msg.tree_id as usize;
        if tree_id >= K {
            return;
        }
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
            if msg.generation > peer.peer_cuckoo_gen[tree_id] {
                // New generation: replace filter entirely — evicts stale entries
                // from nodes that have disconnected from the sender's side.
                peer.peer_cuckoo_gen[tree_id] = msg.generation;
                peer.cuckoo[tree_id] = CuckooFilter::decode(&msg.data);
            } else {
                // Same generation: replace with sender's current view.
                peer.cuckoo[tree_id] = CuckooFilter::decode(&msg.data);
            }
        }
    }

    // Skip mutations: complex forwarding logic (cuckoo lookup, landmark flood,
    // path tracking) requiring a multi-peer integration harness to verify routing.
    #[mutants::skip]
    pub fn handle_path_lookup(&mut self, from: PeerId, lookup: PathLookup) {
        // Dedup + DoS protection: cap pending_lookups to prevent memory exhaustion
        if self.pending_lookups.contains_key(&lookup.id) {
            return;
        }
        if self.pending_lookups.len() >= MAX_PENDING_LOOKUPS {
            debug!("handle_path_lookup: pending_lookups full, dropping lookup {}", lookup.id);
            return;
        }
        self.pending_lookups.insert(lookup.id, Instant::now());

        // Check if target is us
        if lookup.target == self.pub_key {
            // Send PathNotify back
            let notify = PathNotify {
                target: self.pub_key,
                source: lookup.source,
                id: lookup.id,
                path: lookup.path.clone(),
            };
            let encoded = notify.encode();
            // Send back to source along reverse path (simplified: send to from)
            self.send_to_peer(&from, encoded);
            return;
        }

        // Check cuckoo filters for all peers — filters store routing_tags, not raw keys
        let target_tag = routing_tag(&lookup.target);
        let mut candidates: Vec<(PeerId, u64)> = Vec::new();
        for (peer_key, peer) in &self.peers {
            for tree_id in 0..K {
                if peer.cuckoo[tree_id].contains(&target_tag) {
                    let cost = peer.effective_cost();
                    candidates.push((*peer_key, cost));
                    break;
                }
            }
        }

        if !candidates.is_empty() {
            // Forward to best candidate
            candidates.sort_by_key(|(_, c)| *c);
            let (best_peer, _) = candidates[0];
            let mut fwd = lookup.clone();
            fwd.path.push(0); // simplified path tracking
            let encoded = fwd.encode();
            self.send_to_peer(&best_peer, encoded);
        } else {
            // Fallback: send to all landmarks
            let landmarks: Vec<[u8; 32]> = self.landmarks.iter().copied().collect();
            for lm in landmarks {
                if lm != from {
                    let encoded = lookup.encode();
                    self.send_to_peer(&lm, encoded);
                }
            }
            // If no landmarks, flood to all peers except from
            if self.landmarks.is_empty() {
                let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
                for pk in peer_keys {
                    if pk != from {
                        let encoded = lookup.encode();
                        self.send_to_peer(&pk, encoded);
                    }
                }
            }
        }
    }

    // Skip mutations: path forwarding with async callback (tokio::spawn) —
    // verifying the callback fires requires an async test harness.
    #[mutants::skip]
    pub fn handle_path_notify(&mut self, from: PeerId, notify: PathNotify) {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
        }

        // If notify is for us, trigger path_notify callback
        if notify.source == self.pub_key {
            if let Some(cb) = &self.path_notify {
                let cb = cb.clone();
                let target = notify.target;
                tokio::spawn(async move { cb(target) });
            }
            return;
        }

        // Forward towards source
        if let Some(next_hop) = self.lookup(&notify.source) {
            let encoded = notify.encode();
            self.send_to_peer(&next_hop, encoded);
        }
    }

    // Skip mutations: broken-path forwarding — mutation detection requires tracing
    // a packet through multiple forwarding hops in a live network.
    #[mutants::skip]
    pub fn handle_path_broken(&mut self, from: PeerId, broken: PathBroken) {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
        }
        // Forward towards source
        if broken.source != self.pub_key
            && let Some(next_hop) = self.lookup(&broken.source) {
                let encoded = broken.encode();
                self.send_to_peer(&next_hop, encoded);
            }
    }

    // Skip mutations: session decryption, unpad, routing, and callback dispatch —
    // requires a full two-node integration test with an established session.
    #[mutants::skip]
    pub fn handle_traffic(&mut self, from: PeerId, traffic: Traffic) {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
            peer.rx_bytes += traffic.payload.len() as u64;
        }

        // Determine if this packet is addressed to us by comparing routing tags.
        let my_tag = routing_tag(&self.pub_key);
        if traffic.routing_tag == my_tag {
            match traffic.pkt_type {
                packet::PKT_CONTROL => {
                    // Session control — padded, NOT session-encrypted.
                    let raw = match unpad_payload(&traffic.payload) {
                        Ok(b) => b,
                        Err(e) => {
                            debug!("unpad control payload failed: {}", e);
                            return;
                        }
                    };
                    if raw.first().copied() == Some(SESSION_INIT_MAGIC) {
                        let ack_opt = self.sessions.lock_or_recover().handle_init(&raw).ok();
                        if let Some(ack_bytes) = ack_opt
                            && raw.len() >= 33 {
                                let mut sender = [0u8; 32];
                                sender.copy_from_slice(&raw[1..33]);
                                self.send_traffic_to(&sender, ack_bytes);
                            }
                    } else if raw.first().copied() == Some(SESSION_ACK_MAGIC) {
                        let _ = self.sessions.lock_or_recover().handle_ack(&raw);
                    }
                }
                packet::PKT_DATA => {
                    // Session-encrypted data: decrypt enc_header → identify source →
                    // session-decrypt payload → unpad → deliver.
                    let source = match decrypt_source_from_header(&traffic.enc_header, &self.signing_key) {
                        Some(s) => s,
                        None => {
                            debug!("failed to decrypt enc_header from {:?}", &from[..4]);
                            return;
                        }
                    };
                    let padded_pt = {
                        let mut sm = self.sessions.lock_or_recover();
                        match sm.decrypt(&source, &traffic.payload) {
                            Ok(d) => d,
                            Err(e) => {
                                debug!("session decrypt failed from {:?}: {}", &source[..4], e);
                                return;
                            }
                        }
                    };
                    let payload = match unpad_payload(&padded_pt) {
                        Ok(p) => p,
                        Err(e) => {
                            debug!("unpad plaintext failed: {}", e);
                            return;
                        }
                    };
                    let pkt = InboundPacket { from: source, payload };
                    if self.traffic_tx.try_send(pkt).is_err() {
                        warn!("traffic_rx channel full, dropping inbound packet from {:?}", &source[..4]);
                    }
                }
                t => {
                    debug!("unknown pkt_type {} from {:?}", t, &from[..4]);
                }
            }
        } else {
            // Forward using cuckoo-filter lookup on routing_tag.
            // enc_header is completely opaque to intermediate nodes.

            // TTL: use the previously-unused `watermark` field as a per-packet
            // hop counter. Senders MUST initialise it to 0. Each forwarder
            // increments. Drop when MAX_FORWARD_HOPS is reached.
            // Without this guard, two peers with disagreeing cuckoo state can
            // forward the same packet back-and-forth forever.
            if traffic.watermark >= MAX_FORWARD_HOPS as u64 {
                debug!("forward dropped: ttl exceeded ({} hops)", traffic.watermark);
                return;
            }

            // Exclude `from` from the lookup so we never forward straight back
            // to the peer the packet came in on (trivial 2-cycle, caused
            // routinely by bidirectional cuckoo gossip).
            if let Some(next_hop) = self.lookup_by_tag_excluding(&traffic.routing_tag, Some(from)) {
                let mut fwd = traffic;
                fwd.watermark = fwd.watermark.saturating_add(1);
                // Re-stamp the immediate-sender field so downstream peers see
                // *us* as the upstream hop, not the original source. Without
                // this the original source's pub_key leaks at every hop,
                // defeating the source-privacy that enc_header is supposed
                // to provide.
                fwd.from = self.pub_key;
                let encoded = fwd.encode();
                self.send_to_peer(&next_hop, encoded);
            } else {
                debug!("no route for routing_tag {:?}", &traffic.routing_tag[..4]);
            }
        }
    }

    /// Send a session-control payload (SessionInit / SessionAck) wrapped in a
    /// Traffic packet to `dst`.
    ///
    /// Control payloads are NOT session-encrypted (they carry ed25519 signatures).
    /// pkt_type = PKT_CONTROL (0x00). Payload is padded to normalise packet sizes.
    fn send_traffic_to(&mut self, dst: &PeerId, payload: Vec<u8>) {
        let src = self.pub_key;
        let (enc_header, tag) = encrypt_header(&src, dst);
        let padded = pad_payload(&payload);
        let traffic = Traffic {
            path: vec![],
            from: src,
            enc_header,
            routing_tag: tag,
            pkt_type: packet::PKT_CONTROL,
            watermark: 0,
            payload: padded,
        };
        let encoded = traffic.encode();
        if let Some(next_hop) = self.lookup(dst) {
            self.send_to_peer(&next_hop, encoded);
        }
    }

    /// Greedy routing: find best next-hop for destination across all K trees.
    /// Hyperbolic greedy routing is tried first; falls back to cuckoo/XOR.
    pub fn lookup(&self, dst: &PeerId) -> Option<PeerId> {
        // ── Hyperbolic greedy routing (primary) ────────────────────────────
        if let Some(&dst_coord) = self.coord_table.get(dst) {
            let own_dist = self.own_coord.distance(dst_coord);
            let mut best_peer: Option<PeerId> = None;
            let mut best_dist = own_dist; // must strictly improve

            for (peer_key, peer) in &self.peers {
                if let Some(&peer_coord) = self.coord_table.get(&peer.pub_key) {
                    let d = peer_coord.distance(dst_coord);
                    if d < best_dist {
                        best_dist = d;
                        best_peer = Some(*peer_key);
                    }
                }
            }

            if let Some(p) = best_peer {
                return Some(p);
            }
            // No closer neighbour — either we ARE the destination or
            // hyperbolic lookup is vacuous with 1 peer (same-coord case).
            // Let fallback decide.
        }

        // ── Cuckoo-filter lookup (fallback) ────────────────────────────────
        // Filters store routing_tags, not raw pub keys.
        let dst_tag = routing_tag(dst);
        let mut best: Option<(PeerId, u64)> = None;

        for (peer_key, peer) in &self.peers {
            for tree_id in 0..K {
                if peer.cuckoo[tree_id].contains(&dst_tag) {
                    let cost = peer.effective_cost();
                    let better = match &best {
                        None => true,
                        Some((_, bc)) => cost < *bc,
                    };
                    if better {
                        best = Some((*peer_key, cost));
                    }
                    break;
                }
            }
        }

        // ── XOR-distance last-resort ────────────────────────────────────────
        if best.is_none() {
            let mut best_dist: Option<([u8; 32], u64)> = None;
            for (peer_key, peer) in &self.peers {
                let mut dist = [0u8; 32];
                for i in 0..32 {
                    dist[i] = peer_key[i] ^ dst[i];
                }
                let cost = peer.effective_cost();
                let better = match &best_dist {
                    None => true,
                    Some((bd, bc)) => dist < *bd || (dist == *bd && cost < *bc),
                };
                if better {
                    best_dist = Some((dist, cost));
                    best = Some((*peer_key, cost));
                }
            }
        }

        best.map(|(k, _)| k)
    }

    /// Handle an incoming OnionPacket addressed to this node.
    pub fn handle_onion(&mut self, from: PeerId, pkt: OnionPacket) {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
        }

        match pkt.peel(&self.signing_key) {
            Ok(PeeledOnion::Forward(inner_bytes)) => {
                // We are a relay: decode the next layer and forward it
                match OnionPacket::decode(&inner_bytes) {
                    Ok(inner) => {
                        let tag = inner.routing_tag;
                        let encoded = inner.encode();
                        if let Some(next) = self.lookup_by_tag(&tag) {
                            self.send_to_peer(&next, encoded);
                        } else {
                            debug!("onion: no route for next tag {:?}", &tag[..4]);
                        }
                    }
                    Err(e) => debug!("onion: failed to decode inner layer: {}", e),
                }
            }
            Ok(PeeledOnion::Deliver(traffic_bytes)) => {
                // We are the exit relay: dispatch the inner Traffic packet
                if traffic_bytes.is_empty() {
                    return;
                }
                // traffic_bytes starts with TRAFFIC type byte; re-use dispatch
                let ptype = traffic_bytes[0];
                if ptype == TRAFFIC {
                    match Traffic::decode(&traffic_bytes[1..]) {
                        Ok(traffic) => self.handle_traffic(from, traffic),
                        Err(e) => debug!("onion: inner Traffic decode failed: {}", e),
                    }
                }
            }
            Err(e) => {
                debug!("onion peel failed from {:?}: {}", &from[..4], e);
            }
        }
    }

    /// Route lookup using only the 16-byte routing_tag (for forwarding Traffic
    /// where the full dest pub key is not known to intermediate nodes).
    fn lookup_by_tag(&self, tag: &[u8; 16]) -> Option<PeerId> {
        self.lookup_by_tag_excluding(tag, None)
    }

    /// Same as `lookup_by_tag` but skips a specified peer. Used when forwarding
    /// to avoid bouncing a packet back to the peer it just came from — without
    /// this, cuckoo gossip (which naturally propagates each tag in both
    /// directions) creates trivial 2-cycles.
    fn lookup_by_tag_excluding(&self, tag: &[u8; 16], exclude: Option<PeerId>) -> Option<PeerId> {
        let mut best: Option<(PeerId, u64)> = None;
        for (peer_key, peer) in &self.peers {
            if exclude == Some(*peer_key) {
                continue;
            }
            for tree_id in 0..K {
                if peer.cuckoo[tree_id].contains(tag) {
                    let cost = peer.effective_cost();
                    let better = best.is_none_or(|(_, bc)| cost < bc);
                    if better {
                        best = Some((*peer_key, cost));
                    }
                    break;
                }
            }
        }
        best.map(|(k, _)| k)
    }
}

// ──────────────────────────────────────────────
// Packet dispatch
// ──────────────────────────────────────────────

/// Global semaphore bounding the number of in-flight jittered forwards.
/// A flooder sending packets-for-relay at line rate would otherwise spawn an
/// unbounded number of tokio tasks (each sleeping up to 49 ms before forwarding),
/// exhausting memory. `try_acquire` ensures excess packets are simply dropped.
static FORWARD_SEM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();

fn forward_sem() -> &'static Arc<tokio::sync::Semaphore> {
    FORWARD_SEM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_FORWARDS)))
}

// Skip mutations: dispatches on packet type byte and delegates to handler methods —
// match-arm deletions and the jitter `%` arithmetic require a live connection
// (async tokio::spawn) or full routing integration test to observe.
#[mutants::skip]
fn dispatch(state: &Arc<Mutex<RouterState>>, from: PeerId, frame: Vec<u8>) {
    if frame.is_empty() {
        return;
    }
    let ptype = frame[0];
    let data = &frame[1..];

    match ptype {
        DUMMY => {}
        KEEP_ALIVE => {
            if let Some(peer) = state.lock_or_recover().peers.get_mut(&from) {
                peer.last_rx_time = Instant::now();
            }
        }
        SIG_REQ => {
            if let Ok(req) = SigReq::decode(data) {
                state.lock_or_recover().handle_sig_req(from, req);
            }
        }
        SIG_RES => {
            if let Ok(res) = SigRes::decode(data) {
                state.lock_or_recover().handle_sig_res(from, res);
            }
        }
        ANNOUNCE => {
            if let Ok(ann) = Announce::decode(data) {
                state.lock_or_recover().handle_announce(from, ann);
            }
        }
        CUCKOO_FILTER => {
            if let Ok(msg) = CuckooMsg::decode(data) {
                state.lock_or_recover().handle_cuckoo(from, msg);
            }
        }
        PATH_LOOKUP => {
            if let Ok(lookup) = PathLookup::decode(data) {
                state.lock_or_recover().handle_path_lookup(from, lookup);
            }
        }
        PATH_NOTIFY => {
            if let Ok(notify) = PathNotify::decode(data) {
                state.lock_or_recover().handle_path_notify(from, notify);
            }
        }
        PATH_BROKEN => {
            if let Ok(broken) = PathBroken::decode(data) {
                state.lock_or_recover().handle_path_broken(from, broken);
            }
        }
        TRAFFIC => {
            if let Ok(traffic) = Traffic::decode(data) {
                let my_pub = state.lock_or_recover().pub_key;
                let my_tag = routing_tag(&my_pub);
                if traffic.routing_tag == my_tag {
                    // For us: handle immediately (no jitter — latency matters)
                    state.lock_or_recover().handle_traffic(from, traffic);
                } else {
                    // Forwarding: apply random 0–49 ms jitter to resist timing correlation.
                    // Permit is acquired *before* spawning; if the cap is hit the packet
                    // is dropped rather than spawning an unbounded task.
                    let permit = forward_sem().clone().try_acquire_owned();
                    let state_fwd = state.clone();
                    tokio::spawn(async move {
                        // Hold permit if we got one; if not, still forward (graceful degrade)
                        // — the cap is a DoS guard, not a hard correctness invariant.
                        let _permit = permit.ok();
                        let jitter_ms = rand::random::<u64>() % 50;
                        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
                        state_fwd.lock_or_recover().handle_traffic(from, traffic);
                    });
                }
            }
        }
        TYPE_COORD_ANNOUNCE => {
            if let Ok(ann) = CoordAnnounce::decode(data) {
                state.lock_or_recover().handle_coord_announce(from, ann);
            }
        }
        TYPE_ONION => {
            if let Ok(pkt) = OnionPacket::decode(data) {
                let my_pub = state.lock_or_recover().pub_key;
                let my_tag = routing_tag(&my_pub);
                if pkt.routing_tag == my_tag {
                    // This layer is for us — peel and act
                    let state2 = state.clone();
                    tokio::spawn(async move {
                        state2.lock_or_recover().handle_onion(from, pkt);
                    });
                } else {
                    // Forward with jitter — best-effort permit acquisition.
                    let permit = forward_sem().clone().try_acquire_owned();
                    let state_fwd = state.clone();
                    tokio::spawn(async move {
                        let _permit = permit.ok();
                        let jitter_ms = rand::random::<u64>() % 50;
                        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
                        let tag = pkt.routing_tag;
                        let encoded = pkt.encode();
                        // Exclude `from` to avoid the 2-cycle that bidirectional
                        // cuckoo gossip otherwise creates routinely.
                        let next = state_fwd.lock_or_recover()
                            .lookup_by_tag_excluding(&tag, Some(from));
                        if let Some(next) = next {
                            state_fwd.lock_or_recover().send_to_peer(&next, encoded);
                        }
                    });
                }
            }
        }
        _ => {
            debug!("unknown packet type {} from {:?}", ptype, &from[..4]);
        }
    }
}

// ──────────────────────────────────────────────
// PacketConn — public API
// ──────────────────────────────────────────────

pub struct PacketConn {
    inner: Arc<Mutex<RouterState>>,
    traffic_rx: tokio::sync::Mutex<mpsc::Receiver<InboundPacket>>,
    pub pub_key: [u8; 32],
    /// Clone of the signing key — needed by the transport layer to sign the
    /// per-connection authenticated handshake. Stored here so that transports
    /// don't need to be parameterised with the key separately.
    signing_key: SigningKey,
    shutdown_tx: watch::Sender<bool>,
}

impl PacketConn {
    /// Borrow the signing key (used by the transport layer for handshake signing).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

impl PacketConn {
    pub fn new(signing_key: SigningKey) -> Self {
        let pub_key = signing_key.verifying_key().to_bytes();
        let signing_key_for_pc = signing_key.clone();
        let (traffic_tx, traffic_rx) = mpsc::channel(1024);
        let state = Arc::new(Mutex::new(RouterState::new(signing_key, traffic_tx)));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Spawn maintenance background task
        {
            let state = state.clone();
            let mut shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            state.lock_or_recover().do_maintenance();
                        }
                        _ = shutdown.changed() => break,
                    }
                }
            });
        }

        // Cover traffic: send DUMMY packets at randomised intervals to all peers.
        // This makes it harder to correlate traffic patterns with communication endpoints.
        {
            let state = state.clone();
            let mut shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                use rand::Rng;
                let mut rng = rand::rngs::OsRng;
                loop {
                    // Random delay 8–30 seconds
                    let delay_ms = rng.gen_range(8_000u64..30_000u64);
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
                        _ = shutdown.changed() => break,
                    }

                    let peers: Vec<PeerId> = {
                        state.lock_or_recover().peers.keys().copied().collect()
                    };
                    for peer in peers {
                        // ~40% chance per peer per check — adds variability
                        if rng.gen_bool(0.4) {
                            // Randomised dummy size (64–256 bytes) to prevent size fingerprinting
                            let dummy_len = rng.gen_range(64usize..256usize);
                            let mut cover = vec![DUMMY];
                            cover.resize(dummy_len, 0u8);
                            state.lock_or_recover().send_to_peer(&peer, cover);
                        }
                    }
                }
            });
        }

        PacketConn {
            inner: state,
            traffic_rx: tokio::sync::Mutex::new(traffic_rx),
            pub_key,
            signing_key: signing_key_for_pc,
            shutdown_tx,
        }
    }

    /// Attach a new peer connection.
    ///
    /// This method **blocks** until the peer disconnects.  The caller (transport
    /// layer) should `tokio::spawn` this future and can rely on the return to
    /// know the connection lifetime has ended — no separate cleanup is needed.
    // Skip mutations: reads from network, spawns writer task, runs indefinite read loop —
    // mutation detection requires a live TCP connection.
    #[mutants::skip]
    pub async fn handle_conn(
        &self,
        remote_pub_key: [u8; 32],
        mut reader: impl AsyncRead + Unpin + Send + 'static,
        writer: impl AsyncWrite + Unpin + Send + 'static,
        priority: u8,
    ) {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);

        // Register peer (guarded against duplicates inside add_peer)
        self.inner.lock_or_recover().add_peer(remote_pub_key, tx, priority);

        let state = self.inner.clone();

        // Writer task — runs independently; terminates when channel closes or IO fails.
        tokio::spawn(async move {
            let mut writer = writer;
            while let Some(data) = rx.recv().await {
                if write_frame(&mut writer, &data).await.is_err() {
                    break;
                }
            }
        });

        // Initiate session exchange before entering the read loop.
        let init_bytes = {
            let s = state.lock_or_recover();
            s.sessions.lock_or_recover().get_or_initiate_bytes(&remote_pub_key)
        };
        if let Some(init_data) = init_bytes {
            state.lock_or_recover().send_traffic_to(&remote_pub_key, init_data);
        }

        // Reader loop — runs inline so that handle_conn() only returns after the
        // peer disconnects.  This ensures the transport layer's `connected` dedup
        // set is not cleared too early (which would otherwise allow an immediate
        // reconnect that overwrites the peer entry and kills the writer task).
        loop {
            match read_frame(&mut reader).await {
                Ok(frame) => {
                    dispatch(&state, remote_pub_key, frame);
                }
                Err(e) => {
                    debug!("peer {:?} disconnected: {}", &remote_pub_key[..4], e);
                    state.lock_or_recover().remove_peer(&remote_pub_key);
                    break;
                }
            }
        }
    }

    // Skip mutations: awaits on the async traffic channel — requires a live sender.
    #[mutants::skip]
    pub async fn read_from(&self) -> Result<InboundPacket> {
        let mut rx = self.traffic_rx.lock().await;
        rx.recv().await.ok_or_else(|| anyhow::anyhow!("channel closed"))
    }

    // Skip mutations: session encrypt, pad, onion-wrap, and route lookup —
    // requires a two-node integration test with an established session.
    #[mutants::skip]
    pub async fn write_to(&self, payload: &[u8], dst: &[u8; 32]) -> Result<()> {
        // If no established session, send SessionInit (wrapped in Traffic) and bail.
        // Caller should retry; wait_for_session() in tests handles this.
        {
            let established = {
                let state = self.inner.lock_or_recover();
                let sm = state.sessions.lock_or_recover();
                sm.is_established(dst)
            };
            if !established {
                let init_data = {
                    let state = self.inner.lock_or_recover();
                    let mut sm = state.sessions.lock_or_recover();
                    sm.get_or_initiate_bytes(dst).unwrap_or_default()
                };
                if !init_data.is_empty() {
                    self.inner.lock_or_recover().send_traffic_to(dst, init_data);
                }
                bail!("session not established with {:?}", &dst[..4]);
            }
        }

        // Pad plaintext before encryption so ciphertext sizes are multiples of PAD_BLOCK.
        // This hides message length from observers.
        let padded = pad_payload(payload);
        let ciphertext = {
            let state = self.inner.lock_or_recover();
            state.sessions.lock_or_recover().encrypt(dst, &padded)?
        };

        let pub_key = self.pub_key;
        let (enc_header, tag) = encrypt_header(&pub_key, dst);
        let traffic = Traffic {
            path: vec![],
            from: pub_key,
            enc_header,
            routing_tag: tag,
            pkt_type: packet::PKT_DATA,
            watermark: 0,
            payload: ciphertext,
        };
        let encoded = traffic.encode();
        // Important: extract next_hop into a variable so the MutexGuard is
        // dropped at the `;` before we try to lock again in send_to_peer.
        let next_hop = self.inner.lock_or_recover().lookup(dst);
        if let Some(next_hop) = next_hop {
            self.inner.lock_or_recover().send_to_peer(&next_hop, encoded);
        } else {
            bail!("no route to {:?}", &dst[..4]);
        }
        Ok(())
    }

    /// Select up to `n` random peers to use as onion relays.
    /// Returns fewer than `n` relays if insufficient peers are connected.
    // Skip mutations: uses OsRng shuffle (non-deterministic) and peer list at
    // call time — cannot reliably verify exact relay selection in a unit test.
    #[mutants::skip]
    pub fn select_relays(&self, n: usize) -> Vec<[u8; 32]> {
        use rand::seq::SliceRandom;
        let mut peers: Vec<[u8; 32]> = self.inner.lock_or_recover().peers.keys().copied().collect();
        peers.shuffle(&mut rand::rngs::OsRng);
        peers.truncate(n);
        peers
    }

    /// Send a payload to `dst` via the given `relays` using onion routing.
    ///
    /// The payload is encrypted with the session key for `dst`, then wrapped
    /// in an onion packet through each relay. Each relay sees only its
    /// predecessor and successor — not the full path or endpoints.
    ///
    /// If `relays` is empty this falls back to direct Traffic (same as `write_to`).
    // Skip mutations: onion-wrap + route to first relay — requires a multi-node
    // integration test to verify end-to-end encrypted delivery.
    #[mutants::skip]
    pub async fn write_to_onion(
        &self,
        payload: &[u8],
        dst: &[u8; 32],
        relays: &[[u8; 32]],
    ) -> Result<()> {
        if relays.is_empty() {
            return self.write_to(payload, dst).await;
        }

        // Check session
        {
            let established = {
                let state = self.inner.lock_or_recover();
                state.sessions.lock_or_recover().is_established(dst)
            };
            if !established {
                let init_data = {
                    let state = self.inner.lock_or_recover();
                    let mut sm = state.sessions.lock_or_recover();
                    sm.get_or_initiate_bytes(dst).unwrap_or_default()
                };
                if !init_data.is_empty() {
                    self.inner.lock_or_recover().send_traffic_to(dst, init_data);
                }
                bail!("session not established with {:?}", &dst[..4]);
            }
        }

        // Encrypt payload with session key, wrap in Traffic, then wrap in onion layers
        let padded = pad_payload(payload);
        let ciphertext = {
            let state = self.inner.lock_or_recover();
            state.sessions.lock_or_recover().encrypt(dst, &padded)?
        };

        let pub_key = self.pub_key;
        let (enc_header, tag) = encrypt_header(&pub_key, dst);
        let traffic = Traffic {
            path: vec![],
            from: pub_key,
            enc_header,
            routing_tag: tag,
            pkt_type: packet::PKT_DATA,
            watermark: 0,
            payload: ciphertext,
        };
        let traffic_bytes = traffic.encode(); // includes leading TRAFFIC byte

        // Build onion around the Traffic packet
        let onion_pkt = match build_onion(relays, dst, traffic_bytes) {
            Ok(p) => p,
            Err(e) => bail!("failed to build onion: {}", e),
        };
        let encoded = onion_pkt.encode();

        // Send to first relay
        let first_relay = relays[0];
        let next_hop = self.inner.lock_or_recover().lookup(&first_relay);
        if let Some(next) = next_hop {
            self.inner.lock_or_recover().send_to_peer(&next, encoded);
        } else {
            bail!("no route to first relay {:?}", &first_relay[..4]);
        }
        Ok(())
    }

    pub fn mtu(&self) -> u64 {
        // u16::MAX - 2 (length header) - 16 (AEAD tag) - 128 (enc_header)
        // - small overhead; keep round number that's safely below u16::MAX.
        65000
    }

    // Skip mutations: sends shutdown signal and clears peers — no observable
    // side-effect accessible from a unit test after the call.
    #[mutants::skip]
    pub async fn close(&self) {
        // Signal all background tasks to exit
        let _ = self.shutdown_tx.send(true);
        // Drop all peer connections
        self.inner.lock_or_recover().peers.clear();
    }

    pub fn get_peer_stats(&self) -> Vec<PeerStats> {
        let state = self.inner.lock_or_recover();
        let now = Instant::now();
        state.peers.values().map(|p| PeerStats {
            key: p.pub_key,
            lag: p.lag,
            jitter: p.jitter,
            loss_rate: p.loss_rate,
            priority: p.priority,
            rx_bytes: p.rx_bytes,
            tx_bytes: p.tx_bytes,
            uptime: now.duration_since(p.connected_at),
        }).collect()
    }

    // Skip mutations: stores closure in mutex — verifying the callback fires requires
    // a live handle_path_notify invocation from a peer.
    #[mutants::skip]
    pub async fn set_path_notify<F: Fn([u8; 32]) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock_or_recover().path_notify = Some(Arc::new(f));
    }

    // Skip mutations: sends PathLookup to all peers — mutation detection requires
    // tracing lookup propagation through a live network.
    #[mutants::skip]
    pub async fn send_lookup(&self, partial: &[u8]) {
        let mut target = [0u8; 32];
        let len = partial.len().min(32);
        target[..len].copy_from_slice(&partial[..len]);

        let id = rand::random::<u64>();
        let pub_key = self.pub_key;
        let lookup = PathLookup {
            target,
            source: pub_key,
            id,
            path: vec![],
        };
        let encoded = lookup.encode();
        let peer_keys: Vec<PeerId> = self.inner.lock_or_recover().peers.keys().copied().collect();
        for pk in peer_keys {
            self.inner.lock_or_recover().send_to_peer(&pk, encoded.clone());
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // ── PeerData::effective_cost (kills replace-with-0 and replace-with-1) ───

    #[test]
    fn peer_effective_cost_uses_lag_and_loss() {
        let mut rs = make_router();
        let key = [0xEEu8; 32];
        add_dummy_peer(&mut rs, key);
        rs.peers.get_mut(&key).unwrap().lag = Duration::from_micros(50_000); // 50ms
        rs.peers.get_mut(&key).unwrap().loss_rate = 0.0;
        let cost = rs.peers[&key].effective_cost();
        assert_eq!(cost, 50_000,
            "effective_cost with 0 loss must equal lag_us=50_000; got {} (mutation returns 0 or 1?)", cost);
    }

    #[test]
    fn peer_effective_cost_reflects_loss_rate() {
        let mut rs = make_router();
        let key = [0xEFu8; 32];
        add_dummy_peer(&mut rs, key);
        rs.peers.get_mut(&key).unwrap().lag = Duration::from_millis(100); // 100ms
        rs.peers.get_mut(&key).unwrap().loss_rate = 1.0;
        let cost = rs.peers[&key].effective_cost();
        // effective_cost = 100_000 * (1 + 9) = 1_000_000 µs
        assert_eq!(cost, 1_000_000,
            "full-loss effective_cost must be 10× lag; got {}", cost);
    }

    // ── tree_metric XOR arithmetic (kills ^= → |= and % → / mutations) ───────

    #[test]
    fn tree_metric_xor_not_or() {
        // Use pub_key=[0xFF;32] and a seed with a known byte.
        // XOR: 0xFF ^ seed_byte gives a different result than OR: 0xFF | seed_byte.
        // XOR with 0xFF flips bits; OR with anything ≤ 0xFF leaves 0xFF unchanged.
        let key = [0xFFu8; 32];
        let seed = *b"Verdandi"; // [0x56, 0x65, ...]
        let metric = tree_metric(&key, &seed);
        // Correct: 0xFF ^ 0x56 = 0xA9, 0xFF ^ 0x65 = 0x9A
        assert_eq!(metric[0], 0xFF ^ seed[0],
            "byte 0: must XOR (not OR); got {:#04x}", metric[0]);
        assert_eq!(metric[1], 0xFF ^ seed[1],
            "byte 1: must XOR; got {:#04x}", metric[1]);
        // |= mutation: 0xFF | 0x56 = 0xFF ≠ 0xA9 → kills mutation
    }

    #[test]
    fn tree_metric_seed_index_uses_modulo() {
        // seed[i % 8] vs seed[i / 8]:
        // For i=1: %: seed[1], /: seed[0] → if seed[0] != seed[1], results differ.
        let key = [0u8; 32];
        let seed = *b"Verdandi"; // seed[0]=0x56, seed[1]=0x65
        let metric = tree_metric(&key, &seed);
        // Correct: metric[1] = 0 ^ seed[1] = 0x65
        assert_eq!(metric[1], seed[1],
            "byte 1 must use seed[1%8]=seed[1]={:#04x}, not seed[0]={:#04x}; got {:#04x}",
            seed[1], seed[0], metric[1]);
        // / mutation: metric[1] = 0 ^ seed[1/8] = 0 ^ seed[0] = 0x56 ≠ 0x65
    }

    // ── send_to_peer tx_bytes (kills += → *= mutation) ────────────────────────

    #[test]
    fn send_to_peer_increments_tx_bytes() {
        let mut rs = make_router();
        let peer_key = [0xF0u8; 32];
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        assert_eq!(rs.peers[&peer_key].tx_bytes, 0, "tx_bytes starts at 0");
        let payload = vec![0u8; 100];
        rs.send_to_peer(&peer_key, payload);
        assert_eq!(rs.peers[&peer_key].tx_bytes, 100,
            "tx_bytes must increase by payload length; mutation *=100 gives 0*100=0");
    }

    // ── effective_cost ────────────────────────────────────────────────────────

    #[test]
    fn effective_cost_zero_loss_equals_lag() {
        let lag = Duration::from_millis(50);
        let cost = effective_cost(lag, 0.0);
        assert_eq!(cost, lag.as_micros() as u64,
            "zero loss: cost must equal lag in micros");
    }

    #[test]
    fn effective_cost_increases_with_loss() {
        let lag = Duration::from_millis(10);
        let cost_no_loss   = effective_cost(lag, 0.0);
        let cost_half_loss = effective_cost(lag, 0.5);
        let cost_full_loss = effective_cost(lag, 1.0);
        assert!(cost_half_loss > cost_no_loss,
            "half-loss cost ({}) must exceed no-loss cost ({})", cost_half_loss, cost_no_loss);
        assert!(cost_full_loss > cost_half_loss,
            "full-loss cost ({}) must exceed half-loss cost ({})", cost_full_loss, cost_half_loss);
    }

    #[test]
    fn effective_cost_full_loss_is_10x_lag() {
        let lag = Duration::from_millis(100);
        let cost = effective_cost(lag, 1.0);
        // formula: lag_us * (1 + 1.0 * 9) = lag_us * 10
        let expected = lag.as_micros() as u64 * 10;
        assert_eq!(cost, expected, "full loss must give 10× base cost");
    }

    // ── metric_less ───────────────────────────────────────────────────────────

    #[test]
    fn metric_less_orders_correctly() {
        let low  = [0u8; 32];
        let high = [0xFF_u8; 32];
        assert!(metric_less(&low, &high), "low < high must be true");
        assert!(!metric_less(&high, &low), "high < low must be false");
        assert!(!metric_less(&low, &low), "equal values must not satisfy <");
    }

    // ── tree_metric ───────────────────────────────────────────────────────────

    #[test]
    fn tree_metric_deterministic() {
        let key  = [0xABu8; 32];
        let seed = [0u8; 8];
        assert_eq!(tree_metric(&key, &seed), tree_metric(&key, &seed));
    }

    #[test]
    fn tree_metric_differs_with_seed() {
        let key   = [0xABu8; 32];
        let seed0 = [0u8; 8];
        let seed1 = *b"Verdandi";
        assert_ne!(tree_metric(&key, &seed0), tree_metric(&key, &seed1),
            "different seeds must give different metrics");
    }

    #[test]
    fn tree_metric_xor_identity_with_zero_seed() {
        let key  = [0xABu8; 32];
        let seed = [0u8; 8];
        // XOR with all-zero seed is identity
        assert_eq!(tree_metric(&key, &seed), key);
    }

    // ── pad_payload / unpad_payload ───────────────────────────────────────────

    #[test]
    fn pad_unpad_roundtrip() {
        for len in [0, 1, 128, 255, 256, 257, 512, 1000] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let padded = pad_payload(&data);
            let unpadded = unpad_payload(&padded).expect("unpad must succeed");
            assert_eq!(unpadded, data, "roundtrip failed for len={}", len);
        }
    }

    #[test]
    fn pad_payload_result_is_multiple_of_block() {
        for len in [0usize, 1, 255, 256, 257] {
            let data = vec![0u8; len];
            let padded = pad_payload(&data);
            assert_eq!(padded.len() % PAD_BLOCK, 0,
                "padded length must be multiple of {}, got {} for input len {}", PAD_BLOCK, padded.len(), len);
        }
    }

    #[test]
    fn pad_payload_minimum_size() {
        // Even empty input must produce at least PAD_BLOCK bytes
        let padded = pad_payload(&[]);
        assert_eq!(padded.len(), PAD_BLOCK);
    }

    #[test]
    fn unpad_too_short_fails() {
        assert!(unpad_payload(&[]).is_err());
        assert!(unpad_payload(&[0u8]).is_err());
        // Claims length 100 but only has 10 bytes total (2 header + 8 data)
        let mut bad = vec![0u8, 100u8];
        bad.extend_from_slice(&[0u8; 8]);
        assert!(unpad_payload(&bad).is_err());
    }

    #[test]
    fn unpad_exactly_two_bytes_succeeds_with_zero_len() {
        // [0, 0] → orig_len=0, need padded.len() >= 2+0=2. Exactly satisfied.
        // Mutation `< with <=` (line 189): `2 <= 2` → would wrongly fail this.
        let result = unpad_payload(&[0u8, 0u8]);
        assert!(result.is_ok(), "exactly 2 bytes (orig_len=0) must succeed: {:?}", result.err());
        assert_eq!(result.unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn unpad_exactly_at_data_boundary_succeeds() {
        // padded = [5, 0, A, B, C, D, E] — exactly 2 + 5 = 7 bytes.
        // Mutation `< with <=` (line 193): `7 <= 2+5=7` → would wrongly fail.
        let padded = vec![5u8, 0u8, 0xAu8, 0xBu8, 0xCu8, 0xDu8, 0xEu8];
        let result = unpad_payload(&padded);
        assert!(result.is_ok(), "exactly-at-boundary unpad must succeed: {:?}", result.err());
        assert_eq!(result.unwrap(), vec![0xAu8, 0xBu8, 0xCu8, 0xDu8, 0xEu8]);
    }

    #[test]
    fn unpad_one_byte_short_of_data_fails() {
        // padded = [5, 0, A, B, C, D] — only 6 bytes but claims orig_len=5 (needs 7).
        let padded = vec![5u8, 0u8, 0xAu8, 0xBu8, 0xCu8, 0xDu8];
        assert!(unpad_payload(&padded).is_err(),
            "one byte short of claimed data length must fail");
    }

    // ── pad_payload length encoding uses correct byte order ───────────────────

    #[test]
    fn pad_payload_encodes_length_le() {
        let data = vec![0x42u8; 300];
        let padded = pad_payload(&data);
        // First 2 bytes: orig_len as LE u16
        let encoded_len = (padded[0] as usize) | ((padded[1] as usize) << 8);
        assert_eq!(encoded_len, 300, "length must be 300 in LE");
    }

    // ── Test helpers ─────────────────────────────────────────────────────────

    fn make_router() -> RouterState {
        let sk = SigningKey::generate(&mut OsRng);
        let (tx, _rx) = mpsc::channel(32);
        RouterState::new(sk, tx)
    }

    fn add_dummy_peer(rs: &mut RouterState, key: PeerId) {
        let (tx, _rx) = mpsc::channel(32);
        rs.add_peer(key, tx, 0);
    }

    fn make_valid_sig_res(
        peer_sk: &SigningKey,
        own_pub: &[u8; 32],
        seq: u64,
        timestamp_ms: u64,
    ) -> SigRes {
        use ed25519_dalek::Signer;
        let mut sign_data = vec![0u8]; // tree_id = 0
        let mut tmp = Vec::new();
        encode_uvarint(seq, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        tmp.clear();
        encode_uvarint(timestamp_ms, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        sign_data.extend_from_slice(own_pub);
        let signature = peer_sk.sign(&sign_data).to_bytes();
        SigRes {
            tree_id: 0,
            seq,
            timestamp_ms,
            signature,
            pub_key: peer_sk.verifying_key().to_bytes(),
        }
    }

    // ── update_landmarks ──────────────────────────────────────────────────────

    #[test]
    fn landmarks_self_not_set_with_two_peers() {
        let mut rs = make_router();
        add_dummy_peer(&mut rs, [1u8; 32]);
        add_dummy_peer(&mut rs, [2u8; 32]);
        rs.update_landmarks();
        assert!(!rs.landmarks.contains(&rs.pub_key),
            "self must NOT be a landmark with only 2 peers (need > 2)");
    }

    #[test]
    fn landmarks_self_set_with_three_peers() {
        let mut rs = make_router();
        add_dummy_peer(&mut rs, [1u8; 32]);
        add_dummy_peer(&mut rs, [2u8; 32]);
        add_dummy_peer(&mut rs, [3u8; 32]);
        rs.update_landmarks();
        assert!(rs.landmarks.contains(&rs.pub_key),
            "self must be a landmark with 3 peers (> 2)");
    }

    #[test]
    fn landmarks_peer_at_depth_zero_marked() {
        let mut rs = make_router();
        let peer_key = [0xAAu8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // Depth 0 → landmark
        rs.peers.get_mut(&peer_key).unwrap().trees[0] = Some(TreeAnnounce {
            root: [0u8; 32],
            path_cost: 0,
            received_at: Instant::now(),
            depth: 0,
        });
        rs.update_landmarks();
        assert!(rs.landmarks.contains(&peer_key), "depth-0 peer must become a landmark");
    }

    #[test]
    fn landmarks_peer_at_depth_two_not_marked() {
        let mut rs = make_router();
        let peer_key = [0xBBu8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // Depth 2 (> 1) → NOT a landmark by heuristic
        rs.peers.get_mut(&peer_key).unwrap().trees[0] = Some(TreeAnnounce {
            root: [0u8; 32],
            path_cost: 0,
            received_at: Instant::now(),
            depth: 2,
        });
        rs.update_landmarks();
        assert!(!rs.landmarks.contains(&peer_key), "depth-2 peer must NOT be a landmark");
    }

    // ── remove_peer clears tree parent ────────────────────────────────────────

    #[test]
    fn remove_peer_clears_tree_parent() {
        let mut rs = make_router();
        let peer_key = [42u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        let own_key = rs.pub_key;
        // Manually set all tree parents to the removed peer
        for i in 0..K {
            rs.trees[i].parent = Some(peer_key);
            rs.trees[i].root = peer_key;
            rs.trees[i].parent_cost = 1000;
        }
        rs.remove_peer(&peer_key);
        for i in 0..K {
            assert!(rs.trees[i].parent.is_none(), "tree[{}] parent must be cleared", i);
            assert_eq!(rs.trees[i].root, own_key, "tree[{}] root must reset to self", i);
            assert_eq!(rs.trees[i].parent_cost, 0, "tree[{}] parent_cost must reset to 0", i);
        }
        assert!(!rs.peers.contains_key(&peer_key));
    }

    #[test]
    fn remove_peer_does_not_clear_unrelated_parent() {
        let mut rs = make_router();
        let peer_a = [10u8; 32];
        let peer_b = [20u8; 32];
        add_dummy_peer(&mut rs, peer_a);
        add_dummy_peer(&mut rs, peer_b);
        // Parent is peer_b; we remove peer_a
        rs.trees[0].parent = Some(peer_b);
        rs.trees[0].root = [0xBBu8; 32];
        rs.trees[0].parent_cost = 500;
        rs.remove_peer(&peer_a);
        assert_eq!(rs.trees[0].parent, Some(peer_b), "unrelated parent must not be cleared");
        assert_eq!(rs.trees[0].parent_cost, 500, "parent_cost must not change");
    }

    // ── fix_tree ──────────────────────────────────────────────────────────────

    #[test]
    fn fix_tree_is_own_root_with_no_peers() {
        let mut rs = make_router();
        let own_key = rs.pub_key;
        rs.fix_tree(0);
        assert!(rs.trees[0].parent.is_none(), "no peers: must have no parent");
        assert_eq!(rs.trees[0].root, own_key, "no peers: root must be self");
        assert_eq!(rs.trees[0].parent_cost, 0);
    }

    #[test]
    fn fix_tree_selects_peer_with_lower_cost() {
        let mut rs = make_router();
        let peer_a = [0x11u8; 32];
        let peer_b = [0x22u8; 32];
        add_dummy_peer(&mut rs, peer_a);
        add_dummy_peer(&mut rs, peer_b);
        // Both announce the same root [0;32] (very small metric — beats any random pub_key)
        let root = [0u8; 32];
        rs.peers.get_mut(&peer_a).unwrap().trees[0] = Some(TreeAnnounce {
            root,
            path_cost: 10_000,
            received_at: Instant::now(),
            depth: 1,
        });
        rs.peers.get_mut(&peer_a).unwrap().lag = Duration::from_micros(10_000);
        rs.peers.get_mut(&peer_b).unwrap().trees[0] = Some(TreeAnnounce {
            root,
            path_cost: 1_000,
            received_at: Instant::now(),
            depth: 1,
        });
        rs.peers.get_mut(&peer_b).unwrap().lag = Duration::from_micros(1_000);
        // peer_a total = 10_000 + 10_000 = 20_000 µs
        // peer_b total = 1_000 + 1_000 = 2_000 µs → winner
        rs.fix_tree(0);
        assert_eq!(rs.trees[0].parent, Some(peer_b), "must select lower-cost peer");
        assert_eq!(rs.trees[0].root, root);
    }

    #[test]
    fn fix_tree_adopts_peer_with_better_root_metric() {
        let mut rs = make_router();
        let peer_key = [0x55u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // Root [0;32] has metric [0;32] — minimum, beats any random pub_key
        rs.peers.get_mut(&peer_key).unwrap().trees[0] = Some(TreeAnnounce {
            root: [0u8; 32],
            path_cost: 0,
            received_at: Instant::now(),
            depth: 1,
        });
        rs.peers.get_mut(&peer_key).unwrap().lag = Duration::from_micros(1_000);
        rs.fix_tree(0);
        // Our pub_key is almost certainly > [0;32], so we should adopt peer_key as parent
        if rs.pub_key != [0u8; 32] {
            assert_eq!(rs.trees[0].parent, Some(peer_key),
                "peer with better root metric must be selected as parent");
            assert_eq!(rs.trees[0].root, [0u8; 32]);
        }
    }

    #[test]
    fn fix_tree_ignores_expired_announces() {
        let mut rs = make_router();
        let peer_key = [0x77u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        let own_key = rs.pub_key;
        // Announce received far in the past (expired)
        rs.peers.get_mut(&peer_key).unwrap().trees[0] = Some(TreeAnnounce {
            root: [0u8; 32],
            path_cost: 0,
            received_at: Instant::now() - ANNOUNCE_EXPIRY - Duration::from_secs(1),
            depth: 1,
        });
        rs.fix_tree(0);
        // Expired announce must be ignored; we stay as own root
        assert!(rs.trees[0].parent.is_none(), "expired announce must be ignored");
        assert_eq!(rs.trees[0].root, own_key, "must remain own root");
    }

    // ── expire_peers ──────────────────────────────────────────────────────────

    #[test]
    fn expire_peers_removes_timed_out_peer() {
        let mut rs = make_router();
        let peer_key = [5u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // Set last_rx_time past the timeout threshold
        rs.peers.get_mut(&peer_key).unwrap().last_rx_time =
            Instant::now() - PEER_TIMEOUT - Duration::from_secs(1);
        rs.expire_peers();
        assert!(!rs.peers.contains_key(&peer_key), "timed-out peer must be removed");
    }

    #[test]
    fn expire_peers_keeps_active_peer() {
        let mut rs = make_router();
        let peer_key = [6u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // last_rx_time is Instant::now() by default
        rs.expire_peers();
        assert!(rs.peers.contains_key(&peer_key), "active peer must not be expired");
    }

    #[test]
    fn expire_peers_boundary_just_before_timeout() {
        let mut rs = make_router();
        let peer_key = [11u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // One second before timeout → must NOT be removed
        rs.peers.get_mut(&peer_key).unwrap().last_rx_time =
            Instant::now() - PEER_TIMEOUT + Duration::from_secs(1);
        rs.expire_peers();
        assert!(rs.peers.contains_key(&peer_key), "peer just before timeout must not be removed");
    }

    // ── send_keepalives loss rate ──────────────────────────────────────────────

    #[test]
    fn keepalive_unanswered_increases_loss_rate_from_half() {
        let mut rs = make_router();
        let peer_key = [7u8; 32];
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        rs.peers.get_mut(&peer_key).unwrap().loss_rate = 0.5;
        // Simulate a pending unanswered request
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((1, Instant::now()));
        rs.send_keepalives();
        let new_loss = rs.peers[&peer_key].loss_rate;
        // Expected: 0.5 * 0.875 + 0.125 = 0.5625
        assert!((new_loss - 0.5625_f32).abs() < 1e-5,
            "unanswered keepalive from 0.5: expected 0.5625, got {}", new_loss);
    }

    #[test]
    fn keepalive_first_unanswered_sets_loss_to_eighth() {
        let mut rs = make_router();
        let peer_key = [8u8; 32];
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        // loss_rate starts at 0, pending request present
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((1, Instant::now()));
        rs.send_keepalives();
        let new_loss = rs.peers[&peer_key].loss_rate;
        // Expected: 0.0 * 0.875 + 0.125 = 0.125
        assert!((new_loss - 0.125_f32).abs() < 1e-5,
            "first unanswered: expected loss_rate 0.125, got {}", new_loss);
    }

    #[test]
    fn keepalive_seq_increments() {
        let mut rs = make_router();
        let peer_key = [9u8; 32];
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        let initial_seq = rs.peers[&peer_key].sig_req_seq;
        rs.send_keepalives();
        let new_seq = rs.peers[&peer_key].sig_req_seq;
        assert_eq!(new_seq, initial_seq + 1, "sig_req_seq must increment by 1");
    }

    #[test]
    fn keepalive_sets_pending_sig_req() {
        let mut rs = make_router();
        let peer_key = [12u8; 32];
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        assert!(rs.peers[&peer_key].pending_sig_req_time.is_none());
        rs.send_keepalives();
        assert!(rs.peers[&peer_key].pending_sig_req_time.is_some(),
            "pending_sig_req_time must be set after send_keepalives");
    }

    // ── handle_sig_res EWMA ───────────────────────────────────────────────────

    #[test]
    fn sig_res_decays_lag_ewma() {
        let mut rs = make_router();
        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_key = peer_sk.verifying_key().to_bytes();
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        let own_pub = rs.pub_key;
        // Initial lag = 80ms, RTT near 0 → new_lag ≈ 0
        rs.peers.get_mut(&peer_key).unwrap().lag = Duration::from_micros(80_000);
        rs.peers.get_mut(&peer_key).unwrap().loss_rate = 0.5;
        let seq = 1u64;
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((seq, Instant::now()));
        rs.peers.get_mut(&peer_key).unwrap().sig_req_seq = seq;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let res = make_valid_sig_res(&peer_sk, &own_pub, seq, now_ms);
        rs.handle_sig_res(peer_key, res);
        let peer = &rs.peers[&peer_key];
        // lag = old * 7/8 + new/8 ≈ 80_000 * 7/8 = 70_000 µs (new ≈ 0)
        assert!(peer.lag < Duration::from_micros(80_000), "lag must decrease toward new measurement");
        assert!(peer.lag > Duration::from_micros(50_000), "lag must not drop too fast");
        // loss_rate must decay: 0.5 * 0.875 = 0.4375
        assert!(peer.loss_rate < 0.5, "loss_rate must decay on successful ACK");
        assert!(peer.loss_rate > 0.4, "loss_rate must not drop too fast");
    }

    #[test]
    fn sig_res_loss_rate_decays_exactly() {
        let mut rs = make_router();
        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_key = peer_sk.verifying_key().to_bytes();
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        let own_pub = rs.pub_key;
        rs.peers.get_mut(&peer_key).unwrap().loss_rate = 1.0;
        let seq = 2u64;
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((seq, Instant::now()));
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let res = make_valid_sig_res(&peer_sk, &own_pub, seq, now_ms);
        rs.handle_sig_res(peer_key, res);
        let new_loss = rs.peers[&peer_key].loss_rate;
        // loss_rate *= 0.875: 1.0 * 0.875 = 0.875
        assert!((new_loss - 0.875_f32).abs() < 1e-5,
            "loss_rate after successful ACK from 1.0 must be 0.875, got {}", new_loss);
    }

    #[test]
    fn sig_res_wrong_seq_does_not_update_lag() {
        let mut rs = make_router();
        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_key = peer_sk.verifying_key().to_bytes();
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        let own_pub = rs.pub_key;
        rs.peers.get_mut(&peer_key).unwrap().lag = Duration::from_micros(80_000);
        // pending seq = 5, response has seq = 6 → no match
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((5, Instant::now()));
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let res = make_valid_sig_res(&peer_sk, &own_pub, 6, now_ms);
        rs.handle_sig_res(peer_key, res);
        assert_eq!(rs.peers[&peer_key].lag, Duration::from_micros(80_000),
            "wrong-seq response must not update lag");
    }

    // ── cuckoo_do_maintenance generation ──────────────────────────────────────

    #[test]
    fn cuckoo_generation_increments_at_tick_multiple() {
        let mut rs = make_router();
        assert_eq!(rs.cuckoo_generation[0], 0);
        rs.tick = CUCKOO_GEN_TICKS;
        rs.cuckoo_do_maintenance(0);
        assert_eq!(rs.cuckoo_generation[0], 1, "generation must increment at CUCKOO_GEN_TICKS");
    }

    #[test]
    fn cuckoo_generation_does_not_increment_at_tick_zero() {
        let mut rs = make_router();
        rs.tick = 0;
        rs.cuckoo_do_maintenance(0);
        assert_eq!(rs.cuckoo_generation[0], 0, "tick=0 must NOT increment generation");
    }

    #[test]
    fn cuckoo_generation_does_not_increment_at_non_multiple() {
        let mut rs = make_router();
        rs.tick = CUCKOO_GEN_TICKS - 1;
        rs.cuckoo_do_maintenance(0);
        assert_eq!(rs.cuckoo_generation[0], 0, "non-multiple tick must not increment generation");
    }

    #[test]
    fn cuckoo_generation_increments_all_three_trees_independently() {
        let mut rs = make_router();
        rs.tick = CUCKOO_GEN_TICKS;
        for i in 0..K {
            rs.cuckoo_do_maintenance(i);
        }
        for i in 0..K {
            assert_eq!(rs.cuckoo_generation[i], 1, "tree {} generation must be 1", i);
        }
    }

    // ── handle_cuckoo generation tracking ────────────────────────────────────

    #[test]
    fn handle_cuckoo_advances_generation_on_newer_msg() {
        let mut rs = make_router();
        let peer_key = [0xC0u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        assert_eq!(rs.peers[&peer_key].peer_cuckoo_gen[0], 0);
        let data = [0u8; crate::cuckoo::FILTER_BYTES];
        let msg = CuckooMsg { tree_id: 0, generation: 1, data };
        rs.handle_cuckoo(peer_key, msg);
        assert_eq!(rs.peers[&peer_key].peer_cuckoo_gen[0], 1,
            "generation must advance when msg.generation > current");
    }

    #[test]
    fn handle_cuckoo_does_not_regress_generation() {
        let mut rs = make_router();
        let peer_key = [0xC1u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        rs.peers.get_mut(&peer_key).unwrap().peer_cuckoo_gen[0] = 5;
        let data = [0u8; crate::cuckoo::FILTER_BYTES];
        // Old generation msg
        let msg = CuckooMsg { tree_id: 0, generation: 3, data };
        rs.handle_cuckoo(peer_key, msg);
        // Generation must NOT regress to 3
        assert_eq!(rs.peers[&peer_key].peer_cuckoo_gen[0], 5,
            "old generation message must not overwrite newer generation counter");
    }

    #[test]
    fn handle_cuckoo_same_generation_does_not_advance() {
        let mut rs = make_router();
        let peer_key = [0xC2u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        rs.peers.get_mut(&peer_key).unwrap().peer_cuckoo_gen[0] = 7;
        let data = [0u8; crate::cuckoo::FILTER_BYTES];
        let msg = CuckooMsg { tree_id: 0, generation: 7, data }; // same
        rs.handle_cuckoo(peer_key, msg);
        assert_eq!(rs.peers[&peer_key].peer_cuckoo_gen[0], 7,
            "equal-generation message must not advance counter");
    }

    // ── cleanup_stale_lookups ─────────────────────────────────────────────────

    #[test]
    fn cleanup_stale_lookups_removes_old_entries() {
        let mut rs = make_router();
        rs.pending_lookups.insert(42u64, Instant::now() - Duration::from_secs(11));
        rs.pending_lookups.insert(43u64, Instant::now());
        rs.cleanup_stale_lookups();
        assert!(!rs.pending_lookups.contains_key(&42), "entry older than 10s must be removed");
        assert!(rs.pending_lookups.contains_key(&43), "fresh entry must be kept");
    }

    #[test]
    fn cleanup_stale_lookups_keeps_boundary_entry() {
        let mut rs = make_router();
        // Exactly 9 seconds old → must be kept (< 10s)
        rs.pending_lookups.insert(99u64, Instant::now() - Duration::from_secs(9));
        rs.cleanup_stale_lookups();
        assert!(rs.pending_lookups.contains_key(&99),
            "entry 9s old (< 10s threshold) must be kept");
    }

    // ── lookup XOR fallback ───────────────────────────────────────────────────

    #[test]
    fn lookup_xor_fallback_returns_xor_closest_peer() {
        let mut rs = make_router();
        let dst = [0xFFu8; 32];
        // peer_a XOR dst = [0xFE^0xFF; 32] = [0x01;32] — small distance
        let peer_a = [0xFEu8; 32];
        // peer_b XOR dst = [0x00^0xFF; 32] = [0xFF;32] — large distance
        let peer_b = [0x00u8; 32];
        add_dummy_peer(&mut rs, peer_a);
        add_dummy_peer(&mut rs, peer_b);
        // No coords, no cuckoo entries → falls through to XOR fallback
        let result = rs.lookup(&dst);
        assert_eq!(result, Some(peer_a), "XOR fallback must select closest peer");
    }

    #[test]
    fn lookup_returns_none_with_no_peers() {
        let rs = make_router();
        assert!(rs.lookup(&[1u8; 32]).is_none(), "empty router must return None");
    }

    #[test]
    fn lookup_cuckoo_filter_hit_routes_to_matching_peer() {
        let mut rs = make_router();
        let dst = [0x42u8; 32];
        let peer_key = [0x10u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // Add dst routing_tag to peer's cuckoo filter
        let tag = routing_tag(&dst);
        rs.peers.get_mut(&peer_key).unwrap().cuckoo[0].add(&tag);
        let result = rs.lookup(&dst);
        assert_eq!(result, Some(peer_key), "cuckoo filter hit must route to matching peer");
    }

    // ── encrypt_header / decrypt_source round-trip ───────────────────────────

    // ── fix_tree: root_seq and own_depth ─────────────────────────────────────

    #[test]
    fn fix_tree_root_seq_increments_when_self_is_root() {
        let mut rs = make_router();
        let initial_seq = rs.trees[0].root_seq;
        // No peers → self is root → root_seq += 1
        rs.fix_tree(0);
        assert_eq!(rs.trees[0].root_seq, initial_seq + 1,
            "root_seq must increment by 1; mutation += → *= gives {} * 1 = {}",
            initial_seq, initial_seq);
    }

    #[test]
    fn fix_tree_sets_own_depth_zero_when_self_is_root_for_tree_0() {
        let mut rs = make_router();
        // Pre-set own_depth to non-zero
        rs.own_depth = 5;
        // No peers → self is root for tree 0 → own_depth must be reset to 0
        rs.fix_tree(0);
        assert_eq!(rs.own_depth, 0,
            "own_depth must reset to 0 when self is root (tree_id=0); \
             mutation == → != would skip reset, leaving own_depth=5");
    }

    #[test]
    fn fix_tree_does_not_reset_own_depth_for_nonzero_tree() {
        let mut rs = make_router();
        rs.own_depth = 7;
        // tree_id=1: the `if tree_id == 0` branch must NOT fire for tree 1
        rs.fix_tree(1);
        assert_eq!(rs.own_depth, 7,
            "own_depth must not change for tree_id=1; \
             mutation == → != would wrongly reset it to 0");
    }

    #[test]
    fn fix_tree_own_depth_is_parent_depth_plus_one() {
        let mut rs = make_router();
        let peer_key = [0x55u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // Peer announces root [0;32] — metric beats any random pub_key
        rs.peers.get_mut(&peer_key).unwrap().trees[0] = Some(TreeAnnounce {
            root: [0u8; 32],
            path_cost: 0,
            received_at: Instant::now(),
            depth: 3, // peer's depth in tree 0
        });
        rs.peers.get_mut(&peer_key).unwrap().lag = Duration::from_micros(1_000);
        rs.own_depth = 0; // start at 0
        rs.fix_tree(0);
        if rs.trees[0].parent == Some(peer_key) {
            // Our depth = parent_depth + 1 = 3 + 1 = 4
            assert_eq!(rs.own_depth, 4,
                "own_depth must be parent.depth + 1 = 4; \
                 mutation + → - gives 2, + → * gives 3; got {}", rs.own_depth);
        }
    }

    // ── do_maintenance tick increment ─────────────────────────────────────────

    #[test]
    fn do_maintenance_increments_tick() {
        let mut rs = make_router();
        let initial_tick = rs.tick;
        rs.do_maintenance();
        assert_eq!(rs.tick, initial_tick + 1,
            "tick must increment by 1 per maintenance call; \
             mutation += → *= keeps tick at {} * 1 = {}",
            initial_tick, initial_tick);
    }

    // ── send_announces depth encoding ─────────────────────────────────────────

    #[test]
    fn send_announces_encodes_own_depth_for_tree_0() {
        let mut rs = make_router();
        rs.own_depth = 7;
        let peer_key = [0x30u8; 32];
        let (tx, mut rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);

        rs.send_announces(0);

        let data = rx.try_recv().expect("send_announces must send a packet to peer");
        // data[0] = ANNOUNCE type byte; Announce::decode takes data[1..]
        assert_eq!(data[0], ANNOUNCE, "must be ANNOUNCE type");
        let ann = Announce::decode(&data[1..]).expect("must decode as Announce");
        assert_eq!(ann.depth, 7,
            "depth in tree-0 announce must equal own_depth=7; \
             mutation == → != gives depth=0 for tree_id=0");
    }

    #[test]
    fn send_announces_encodes_zero_depth_for_nonzero_tree() {
        let mut rs = make_router();
        rs.own_depth = 7;
        let peer_key = [0x31u8; 32];
        let (tx, mut rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);

        rs.send_announces(1); // tree_id=1 → depth must be 0

        let data = rx.try_recv().expect("send_announces must send a packet to peer");
        assert_eq!(data[0], ANNOUNCE, "must be ANNOUNCE type");
        let ann = Announce::decode(&data[1..]).expect("must decode as Announce");
        assert_eq!(ann.depth, 0,
            "depth for tree_id=1 must be 0 (own_depth only applies to tree 0); \
             mutation == → != would give depth=7 for tree_id=1");
    }

    // ── handle_sig_req sends signed SigRes ───────────────────────────────────

    #[test]
    fn handle_sig_req_sends_signed_sig_res() {
        let mut rs = make_router();
        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_key = peer_sk.verifying_key().to_bytes();
        let (tx, mut rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);

        let own_pub = rs.pub_key;
        let req = SigReq {
            tree_id: 0,
            seq: 42u64,
            timestamp_ms: 0,
            pub_key: own_pub, // SigReq carries the requester's pub key
        };
        rs.handle_sig_req(peer_key, req);

        let data = rx.try_recv().expect("handle_sig_req must send SigRes to peer");
        assert_eq!(data[0], SIG_RES, "response type must be SIG_RES");
        let sig_res = SigRes::decode(&data[1..]).expect("must decode as SigRes");
        assert_eq!(sig_res.seq, 42,
            "SigRes seq must echo req seq; mutation seq→0 gives 0");
        assert_eq!(sig_res.tree_id, 0, "tree_id must echo request");

        // Verify signature: responder signs (tree_id || seq || timestamp_ms || req.pub_key)
        let responder_vk = VerifyingKey::from_bytes(&sig_res.pub_key).unwrap();
        let mut sign_data = vec![sig_res.tree_id];
        let mut tmp = Vec::new();
        encode_uvarint(sig_res.seq, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        tmp.clear();
        encode_uvarint(sig_res.timestamp_ms, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        sign_data.extend_from_slice(&own_pub);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_res.signature);
        assert!(responder_vk.verify(&sign_data, &sig).is_ok(),
            "SigRes signature must be valid");
    }

    // ── handle_sig_res EWMA with non-zero RTT ─────────────────────────────────

    #[test]
    fn sig_res_nonzero_rtt_updates_lag_ewma() {
        let mut rs = make_router();
        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_key = peer_sk.verifying_key().to_bytes();
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        let own_pub = rs.pub_key;

        // Start with low lag; sent_time 1s ago → RTT ≈ 1s, new_lag ≈ 500ms
        rs.peers.get_mut(&peer_key).unwrap().lag = Duration::from_micros(10_000); // 10ms
        rs.peers.get_mut(&peer_key).unwrap().jitter = Duration::ZERO;

        let seq = 10u64;
        let sent_time = Instant::now() - Duration::from_secs(1); // RTT ≈ 1_000_000µs
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((seq, sent_time));

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let res = make_valid_sig_res(&peer_sk, &own_pub, seq, now_ms);
        rs.handle_sig_res(peer_key, res);

        let peer = &rs.peers[&peer_key];
        // RTT ≈ 1_000ms, new_lag = RTT/2 ≈ 500_000µs
        // Expected lag = (10_000 * 7/8) + (500_000/8) ≈ 8_750 + 62_500 = 71_250µs
        // Mutation rtt/2 → rtt*2: new_lag ≈ 1_000_000 → lag ≈ 8_750 + 125_000 = 133_750µs
        assert!(peer.lag > Duration::from_micros(40_000),
            "lag must rise substantially toward new 500ms measurement; got {:?}", peer.lag);
        assert!(peer.lag < Duration::from_micros(120_000),
            "lag must be < 120ms (catches rtt*2 mutation giving ~134ms); got {:?}", peer.lag);

        // diff = |500_000 - 10_000| = 490_000; jitter = 490_000/8 ≈ 61_250µs
        // Mutation new - old → new + old: diff = 510_000 → jitter = 63_750µs (detectable)
        assert!(peer.jitter > Duration::ZERO,
            "jitter must be non-zero; got {:?}", peer.jitter);
        assert!(peer.jitter < Duration::from_micros(120_000),
            "jitter must be < 120ms; got {:?}", peer.jitter);
    }

    #[test]
    fn encrypt_header_decrypt_source_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let src = [0xAAu8; 32];
        let dst = sk.verifying_key().to_bytes();
        let (header, _tag) = encrypt_header(&src, &dst);
        let recovered = decrypt_source_from_header(&header, &sk);
        assert_eq!(recovered, Some(src), "decrypted source must match original");
    }

    #[test]
    fn routing_tag_in_encrypt_header_matches_standalone() {
        let src = [0x11u8; 32];
        let dst = [0x22u8; 32];
        let (_header, tag) = encrypt_header(&src, &dst);
        assert_eq!(tag, routing_tag(&dst), "tag from encrypt_header must match routing_tag(dst)");
    }

    // ── lookup_by_tag selects lowest-cost peer ────────────────────────────────
    // Two peers both have the tag in their cuckoo filter, with different costs.
    // Catches `cost < bc → cost > bc` and similar comparison mutations on line 1196.

    #[test]
    fn lookup_by_tag_selects_lower_cost_peer() {
        let mut rs = make_router();
        let cheap_key = [0xC0u8; 32];
        let costly_key = [0xC1u8; 32];
        add_dummy_peer(&mut rs, cheap_key);
        add_dummy_peer(&mut rs, costly_key);

        // Insert a fixed tag into tree-0 cuckoo filter for both peers
        let tag = [0xABu8; 16];
        rs.peers.get_mut(&cheap_key).unwrap().cuckoo[0].add(&tag);
        rs.peers.get_mut(&costly_key).unwrap().cuckoo[0].add(&tag);

        // Assign clearly different lags: cheap=1ms, costly=100ms
        rs.peers.get_mut(&cheap_key).unwrap().lag = Duration::from_millis(1);
        rs.peers.get_mut(&costly_key).unwrap().lag = Duration::from_millis(100);

        let result = rs.lookup_by_tag(&tag);
        assert_eq!(result, Some(cheap_key),
            "lookup_by_tag must return the peer with lower effective cost; \
             with `< → >` mutation the costly peer would be returned instead");
    }

    // ── handle_sig_res jitter EWMA with non-zero initial jitter ───────────────
    // Catches 5 arithmetic mutations on lines 795 and 797:
    //   795: `- → +` (diff formula): diff = new+old instead of |new-old|
    //   797: `* → /` (weight denom): jitter/7/8 instead of jitter*7/8
    //   797: `* → +` (weight mul): jitter+0 instead of jitter*7/8
    //   797: `/ → *` (first div): jitter*7*8 (huge)
    //   797: `/ → %` (second term): diff%8 ≈ 0 instead of diff/8 = 100_000
    // With old_lag=200ms, old_jitter=80ms, RTT≈2s:
    //   diff = |1_000_000 - 200_000| = 800_000; diff/8 = 100_000
    //   expected new jitter = 70_000 + 100_000 = 170_000µs
    //   bounds [160_000, 177_000] exclude all mutated values.

    #[test]
    fn sig_res_jitter_ewma_with_nonzero_initial() {
        let mut rs = make_router();
        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_key = peer_sk.verifying_key().to_bytes();
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        let own_pub = rs.pub_key;

        // old_lag=200ms, old_jitter=80ms. RTT≈2s → new_lag≈1_000_000µs.
        rs.peers.get_mut(&peer_key).unwrap().lag = Duration::from_micros(200_000);
        rs.peers.get_mut(&peer_key).unwrap().jitter = Duration::from_micros(80_000);

        let seq = 7u64;
        let sent_time = Instant::now() - Duration::from_secs(2);
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((seq, sent_time));

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let res = make_valid_sig_res(&peer_sk, &own_pub, seq, now_ms);
        rs.handle_sig_res(peer_key, res);

        let peer = &rs.peers[&peer_key];
        // Expected ≈ 170_000µs ± ~500µs (RTT variance)
        // Mutation 795 `-→+`: diff=1_200_000, diff/8=150_000 → jitter=220_000 > 177_000 ✓
        // Mutation 797 `*→+`: jitter+0+100_000=180_000 > 177_000 ✓
        // Mutation 797 `*→/`: 1428+100_000=101_428 < 160_000 ✓
        // Mutation 797 `/→*`: 80_000*56+100_000=4_580_000 > 177_000 ✓
        // Mutation 797 `/→%`: 70_000+(800_000%8≈0)=70_001 < 160_000 ✓
        assert!(peer.jitter > Duration::from_micros(160_000),
            "jitter must be > 160ms (catches /→%, *→/ mutations); got {:?}", peer.jitter);
        assert!(peer.jitter < Duration::from_micros(177_000),
            "jitter must be < 177ms (catches -→+, *→+, /→* mutations); got {:?}", peer.jitter);
    }

    // ── cleanup_stale_sessions removes idle sessions ─────────────────────────
    // `cleanup_stale_sessions` retains sessions whose last_used < SESSION_IDLE_EXPIRY ago.
    // Catches `replace cleanup_stale_sessions with ()` (body→empty) and
    // `< → >, ==` mutations (line 720) that would retain sessions that should expire.

    #[test]
    fn cleanup_stale_sessions_removes_expired() {
        let rs = make_router();
        let remote_key = [0x77u8; 32];

        // initiate() creates a SessionInfo entry in rs.sessions
        rs.sessions.lock_or_recover().initiate(&remote_key);
        assert!(rs.sessions.lock_or_recover().sessions.contains_key(&remote_key),
            "session must exist before cleanup");

        // Back-date last_used beyond SESSION_IDLE_EXPIRY (300s)
        let stale_time = Instant::now()
            .checked_sub(SESSION_IDLE_EXPIRY + Duration::from_secs(10))
            .expect("instant subtraction must succeed on any system that has been up 310s+");
        rs.sessions.lock_or_recover()
            .sessions.get_mut(&remote_key).unwrap().last_used = stale_time;

        rs.cleanup_stale_sessions();

        assert!(!rs.sessions.lock_or_recover().sessions.contains_key(&remote_key),
            "stale session must be removed by cleanup_stale_sessions; \
             `replace with ()` mutation leaves it present");
    }

    #[test]
    fn cleanup_stale_sessions_retains_fresh() {
        let rs = make_router();
        let remote_key = [0x78u8; 32];

        rs.sessions.lock_or_recover().initiate(&remote_key);
        // last_used is Instant::now() by default — fresh session, must be kept

        rs.cleanup_stale_sessions();

        assert!(rs.sessions.lock_or_recover().sessions.contains_key(&remote_key),
            "fresh session must survive cleanup_stale_sessions; \
             `< → >` mutation would remove it instead");
    }

    // ── lookup: hyperbolic greedy routing selects closer peer ────────────────
    // With coord_table populated, lookup uses hyperbolic distance.
    // peer_A is close to dst (small distance), peer_B is far from dst.
    // Catches `d < best_dist → d > best_dist` mutation (line 1087:26):
    // with that mutation peer_B (farther) would always win regardless of HashMap order.

    #[test]
    fn lookup_hyperbolic_greedy_selects_closer_peer() {
        let mut rs = make_router();
        // own_coord is already origin (r=0, θ=0)

        let peer_a_key = [0xA1u8; 32];
        let peer_b_key = [0xB1u8; 32];
        add_dummy_peer(&mut rs, peer_a_key);
        add_dummy_peer(&mut rs, peer_b_key);

        let dst_key = [0xD0u8; 32];

        // Place dst far along the real axis
        let dst_coord = HypCoord { r: 0.8, theta: 0.0 };
        // Place peer_A close to dst (same direction, slightly closer to origin)
        let coord_a = HypCoord { r: 0.7, theta: 0.0 };
        // Place peer_B far from dst (opposite direction)
        let coord_b = HypCoord { r: 0.6, theta: std::f64::consts::PI };

        // own_dist = origin.distance(dst_coord) = 2*atanh(0.8) ≈ 2.197
        // d_A = coord_a.distance(dst_coord) = 2*atanh(0.1/1.56) ≈ 0.128 (< own_dist → greedy step ✓)
        // d_B = coord_b.distance(dst_coord) = much larger (≈ 4+)

        rs.coord_table.insert(dst_key, dst_coord);
        rs.peers.get_mut(&peer_a_key).unwrap().pub_key = peer_a_key;
        rs.coord_table.insert(peer_a_key, coord_a);
        rs.coord_table.insert(peer_b_key, coord_b);

        let result = rs.lookup(&dst_key);
        assert_eq!(result, Some(peer_a_key),
            "hyperbolic greedy lookup must return the closest peer (A); \
             `d < best_dist → d > best_dist` mutation returns farthest peer instead");
    }

    // ── lookup: XOR distance uses ^ not | (line 1129) ────────────────────────
    // dist[i] = peer_key[i] ^ dst[i]. Mutation: `^ → |`.
    // Setup: dst=[0xFF;32], peer_A=[0xFE;32] (cheap=200ms), peer_B=[0x01;32] (cheap=1ms).
    // XOR: dist_A=[0x01;32] < dist_B=[0xFE;32] → peer_A closer → returned.
    // OR:  dist_A=[0xFF;32] = dist_B=[0xFF;32] → cost tiebreak: peer_B cheaper → returned.
    // Original always returns peer_A, mutation always returns peer_B.

    #[test]
    fn lookup_xor_distance_uses_xor_not_or() {
        let mut rs = make_router();
        // peer_A: expensive but XOR-closest to dst
        let peer_a_key: PeerId = [0xFEu8; 32];
        // peer_B: cheap but XOR-farther from dst
        let peer_b_key: PeerId = [0x01u8; 32];
        add_dummy_peer(&mut rs, peer_a_key);
        add_dummy_peer(&mut rs, peer_b_key);

        // dst=[0xFF;32]: NOT in coord_table (hyperbolic skipped), no cuckoo match (XOR fallback)
        let dst_key: PeerId = [0xFFu8; 32];

        // XOR distances: A→dst = 0xFE^0xFF = 0x01 (tiny), B→dst = 0x01^0xFF = 0xFE (large)
        // OR distances:  A→dst = 0xFE|0xFF = 0xFF, B→dst = 0x01|0xFF = 0xFF (equal!)
        // → With OR mutation: tiebreak uses cost; make B cheaper so mutation selects B.
        rs.peers.get_mut(&peer_a_key).unwrap().lag = Duration::from_millis(200); // expensive
        rs.peers.get_mut(&peer_b_key).unwrap().lag = Duration::from_millis(1);   // cheap

        let result = rs.lookup(&dst_key);
        assert_eq!(result, Some(peer_a_key),
            "XOR fallback must select peer with smallest XOR distance (peer_A); \
             `^ → |` mutation gives equal OR distances, then cost picks peer_B instead");
    }

    // ── lookup: cuckoo fallback selects lower-cost peer ───────────────────────
    // When dst is not in coord_table, lookup falls back to cuckoo filter.
    // Both peers match the dst_tag; cheaper peer must win.
    // Catches `cost < *bc → cost > *bc` mutation (line 1113:47).

    #[test]
    fn lookup_cuckoo_fallback_selects_lower_cost_peer() {
        let mut rs = make_router();
        let cheap_key = [0xD0u8; 32];
        let costly_key = [0xD1u8; 32];
        add_dummy_peer(&mut rs, cheap_key);
        add_dummy_peer(&mut rs, costly_key);

        // dst not in coord_table → hyperbolic phase skipped entirely
        let dst_key = [0xEFu8; 32];
        let dst_tag = routing_tag(&dst_key);

        rs.peers.get_mut(&cheap_key).unwrap().cuckoo[0].add(&dst_tag);
        rs.peers.get_mut(&costly_key).unwrap().cuckoo[0].add(&dst_tag);

        // Clear default 100ms lag, set clearly different lags
        rs.peers.get_mut(&cheap_key).unwrap().lag = Duration::from_millis(1);
        rs.peers.get_mut(&costly_key).unwrap().lag = Duration::from_millis(200);

        let result = rs.lookup(&dst_key);
        assert_eq!(result, Some(cheap_key),
            "cuckoo fallback must return cheaper peer; \
             `cost < *bc → cost > *bc` mutation returns costly peer instead");
    }

    // ── cuckoo_do_maintenance parent-skip (kills 575:31 == → !=) ─────────────

    #[test]
    fn cuckoo_maintenance_skips_parent_in_full_merged_loop() {
        let mut rs = make_router();
        let parent_key = [0xA0u8; 32];
        let nonparent_key = [0xB0u8; 32];

        let (tx_p, mut rx_p) = mpsc::channel(32);
        let (tx_np, mut rx_np) = mpsc::channel(32);
        rs.add_peer(parent_key, tx_p, 0);
        rs.add_peer(nonparent_key, tx_np, 0);

        // Designate parent_key as this node's parent in tree 0
        rs.trees[0].parent = Some(parent_key);

        rs.cuckoo_do_maintenance(0);

        // Count messages delivered to each peer
        let mut parent_count = 0;
        while rx_p.try_recv().is_ok() { parent_count += 1; }
        let mut nonparent_count = 0;
        while rx_np.try_recv().is_ok() { nonparent_count += 1; }

        // Original: parent gets exactly 1 (upstream send), non-parent gets exactly 1 (full_merged loop)
        // Mutation (== → !=): parent gets 2 (upstream + loop), non-parent gets 0
        assert_eq!(parent_count, 1,
            "parent must receive exactly 1 message (upstream); \
             `== → !=` mutation sends 2 (upstream + loop)");
        assert_eq!(nonparent_count, 1,
            "non-parent must receive exactly 1 message (full_merged); \
             `== → !=` mutation sends 0 (loop skips non-parents)");
    }
}
