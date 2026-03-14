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
use tokio::sync::mpsc;
use tracing::{debug, warn};
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
fn pad_payload(data: &[u8]) -> Vec<u8> {
    let orig_len = data.len();
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
    let orig_len = (padded[0] as usize) | ((padded[1] as usize) << 8);
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

        let parent = tree.parent;
        let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
        for peer_key in peer_keys {
            // Don't send back to parent (avoid loops)
            if Some(peer_key) == parent {
                // Still send to parent (parent needs to know our subtree)
                // Actually in spanning tree: send downstream to non-parents, and our own announce to parent
            }
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

        // Add our routing tag (not raw pub key) — hides identity in filter gossip
        let my_tag = routing_tag(&self.pub_key);
        merged.add(&my_tag);

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
    }

    /// Rotate x25519 keys for sessions that have sent many messages.
    fn rotate_session_keys(&self) {
        let mut sm = self.sessions.lock().unwrap();
        for info in sm.sessions.values_mut() {
            if info.established && info.local_seq > 0 && info.local_seq % KEY_ROTATION_INTERVAL == 0 {
                info.rotate_local_key();
            }
        }
    }

    /// Recompute our own hyperbolic coordinate from current depth.
    fn update_own_coord(&mut self) {
        self.own_coord = HypCoord::from_tree_depth(self.own_depth, &self.pub_key);
        self.coord_table.insert(self.pub_key, self.own_coord);
    }

    /// Broadcast our hyperbolic coordinate to all peers.
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
        self.coord_table.insert(from_key, coord);
    }

    fn cleanup_stale_lookups(&mut self) {
        let now = Instant::now();
        self.pending_lookups.retain(|_, t| now.duration_since(*t) < Duration::from_secs(10));
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
            // Measure RTT
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

    pub fn handle_path_lookup(&mut self, from: PeerId, lookup: PathLookup) {
        // Dedup
        if self.pending_lookups.contains_key(&lookup.id) {
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
                        let ack_opt = self.sessions.lock().unwrap().handle_init(&raw).ok();
                        if let Some(ack_bytes) = ack_opt
                            && raw.len() >= 33 {
                                let mut sender = [0u8; 32];
                                sender.copy_from_slice(&raw[1..33]);
                                self.send_traffic_to(&sender, ack_bytes);
                            }
                    } else if raw.first().copied() == Some(SESSION_ACK_MAGIC) {
                        let _ = self.sessions.lock().unwrap().handle_ack(&raw);
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
                        let mut sm = self.sessions.lock().unwrap();
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
                    let _ = self.traffic_tx.try_send(pkt);
                }
                t => {
                    debug!("unknown pkt_type {} from {:?}", t, &from[..4]);
                }
            }
        } else {
            // Forward using cuckoo-filter lookup on routing_tag.
            // enc_header is completely opaque to intermediate nodes.
            if let Some(next_hop) = self.lookup_by_tag(&traffic.routing_tag) {
                let encoded = traffic.encode();
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
        let mut best: Option<(PeerId, u64)> = None;
        for (peer_key, peer) in &self.peers {
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

fn dispatch(state: &Arc<Mutex<RouterState>>, from: PeerId, frame: Vec<u8>) {
    if frame.is_empty() {
        return;
    }
    let ptype = frame[0];
    let data = &frame[1..];

    match ptype {
        DUMMY => {}
        KEEP_ALIVE => {
            if let Some(peer) = state.lock().unwrap().peers.get_mut(&from) {
                peer.last_rx_time = Instant::now();
            }
        }
        SIG_REQ => {
            if let Ok(req) = SigReq::decode(data) {
                state.lock().unwrap().handle_sig_req(from, req);
            }
        }
        SIG_RES => {
            if let Ok(res) = SigRes::decode(data) {
                state.lock().unwrap().handle_sig_res(from, res);
            }
        }
        ANNOUNCE => {
            if let Ok(ann) = Announce::decode(data) {
                state.lock().unwrap().handle_announce(from, ann);
            }
        }
        CUCKOO_FILTER => {
            if let Ok(msg) = CuckooMsg::decode(data) {
                state.lock().unwrap().handle_cuckoo(from, msg);
            }
        }
        PATH_LOOKUP => {
            if let Ok(lookup) = PathLookup::decode(data) {
                state.lock().unwrap().handle_path_lookup(from, lookup);
            }
        }
        PATH_NOTIFY => {
            if let Ok(notify) = PathNotify::decode(data) {
                state.lock().unwrap().handle_path_notify(from, notify);
            }
        }
        PATH_BROKEN => {
            if let Ok(broken) = PathBroken::decode(data) {
                state.lock().unwrap().handle_path_broken(from, broken);
            }
        }
        TRAFFIC => {
            if let Ok(traffic) = Traffic::decode(data) {
                let my_pub = state.lock().unwrap().pub_key;
                let my_tag = routing_tag(&my_pub);
                if traffic.routing_tag == my_tag {
                    // For us: handle immediately (no jitter — latency matters)
                    state.lock().unwrap().handle_traffic(from, traffic);
                } else {
                    // Forwarding: apply random 0–49 ms jitter to resist timing correlation
                    let state_fwd = state.clone();
                    tokio::spawn(async move {
                        let jitter_ms = rand::random::<u64>() % 50;
                        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
                        state_fwd.lock().unwrap().handle_traffic(from, traffic);
                    });
                }
            }
        }
        TYPE_COORD_ANNOUNCE => {
            if let Ok(ann) = CoordAnnounce::decode(data) {
                state.lock().unwrap().handle_coord_announce(from, ann);
            }
        }
        TYPE_ONION => {
            if let Ok(pkt) = OnionPacket::decode(data) {
                let my_pub = state.lock().unwrap().pub_key;
                let my_tag = routing_tag(&my_pub);
                if pkt.routing_tag == my_tag {
                    // This layer is for us — peel and act
                    let state2 = state.clone();
                    tokio::spawn(async move {
                        state2.lock().unwrap().handle_onion(from, pkt);
                    });
                } else {
                    // Forward with jitter
                    let state_fwd = state.clone();
                    tokio::spawn(async move {
                        let jitter_ms = rand::random::<u64>() % 50;
                        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
                        let tag = pkt.routing_tag;
                        let encoded = pkt.encode();
                        if let Some(next) = state_fwd.lock().unwrap().lookup_by_tag(&tag) {
                            state_fwd.lock().unwrap().send_to_peer(&next, encoded);
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
}

impl PacketConn {
    pub fn new(signing_key: SigningKey) -> Self {
        let pub_key = signing_key.verifying_key().to_bytes();
        let (traffic_tx, traffic_rx) = mpsc::channel(1024);
        let state = Arc::new(Mutex::new(RouterState::new(signing_key, traffic_tx)));

        // Spawn maintenance background task
        {
            let state = state.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    state.lock().unwrap().do_maintenance();
                }
            });
        }

        // Cover traffic: send DUMMY packets at randomised intervals to all peers.
        // This makes it harder to correlate traffic patterns with communication endpoints.
        {
            let state = state.clone();
            tokio::spawn(async move {
                use rand::Rng;
                let mut rng = rand::rngs::OsRng;
                loop {
                    // Random delay 8–30 seconds
                    let delay_ms = rng.gen_range(8_000u64..30_000u64);
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;

                    let peers: Vec<PeerId> = {
                        state.lock().unwrap().peers.keys().copied().collect()
                    };
                    for peer in peers {
                        // ~40% chance per peer per check — adds variability
                        if rng.gen_bool(0.4) {
                            // Randomised dummy size (64–256 bytes) to prevent size fingerprinting
                            let dummy_len = rng.gen_range(64usize..256usize);
                            let mut cover = vec![DUMMY];
                            cover.resize(dummy_len, 0u8);
                            state.lock().unwrap().send_to_peer(&peer, cover);
                        }
                    }
                }
            });
        }

        PacketConn {
            inner: state,
            traffic_rx: tokio::sync::Mutex::new(traffic_rx),
            pub_key,
        }
    }

    /// Attach a new peer connection.
    ///
    /// This method **blocks** until the peer disconnects.  The caller (transport
    /// layer) should `tokio::spawn` this future and can rely on the return to
    /// know the connection lifetime has ended — no separate cleanup is needed.
    pub async fn handle_conn(
        &self,
        remote_pub_key: [u8; 32],
        mut reader: impl AsyncRead + Unpin + Send + 'static,
        writer: impl AsyncWrite + Unpin + Send + 'static,
        priority: u8,
    ) {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);

        // Register peer (guarded against duplicates inside add_peer)
        self.inner.lock().unwrap().add_peer(remote_pub_key, tx, priority);

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
            let s = state.lock().unwrap();
            s.sessions.lock().unwrap().get_or_initiate_bytes(&remote_pub_key)
        };
        if let Some(init_data) = init_bytes {
            state.lock().unwrap().send_traffic_to(&remote_pub_key, init_data);
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
                    state.lock().unwrap().remove_peer(&remote_pub_key);
                    break;
                }
            }
        }
    }

    pub async fn read_from(&self) -> Result<InboundPacket> {
        let mut rx = self.traffic_rx.lock().await;
        rx.recv().await.ok_or_else(|| anyhow::anyhow!("channel closed"))
    }

    pub async fn write_to(&self, payload: &[u8], dst: &[u8; 32]) -> Result<()> {
        // If no established session, send SessionInit (wrapped in Traffic) and bail.
        // Caller should retry; wait_for_session() in tests handles this.
        {
            let established = {
                let state = self.inner.lock().unwrap();
                let sm = state.sessions.lock().unwrap();
                sm.is_established(dst)
            };
            if !established {
                let init_data = {
                    let state = self.inner.lock().unwrap();
                    let mut sm = state.sessions.lock().unwrap();
                    sm.get_or_initiate_bytes(dst).unwrap_or_default()
                };
                if !init_data.is_empty() {
                    self.inner.lock().unwrap().send_traffic_to(dst, init_data);
                }
                bail!("session not established with {:?}", &dst[..4]);
            }
        }

        // Pad plaintext before encryption so ciphertext sizes are multiples of PAD_BLOCK.
        // This hides message length from observers.
        let padded = pad_payload(payload);
        let ciphertext = {
            let state = self.inner.lock().unwrap();
            state.sessions.lock().unwrap().encrypt(dst, &padded)?
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
        let next_hop = self.inner.lock().unwrap().lookup(dst);
        if let Some(next_hop) = next_hop {
            self.inner.lock().unwrap().send_to_peer(&next_hop, encoded);
        } else {
            bail!("no route to {:?}", &dst[..4]);
        }
        Ok(())
    }

    /// Select up to `n` random peers to use as onion relays.
    /// Returns fewer than `n` relays if insufficient peers are connected.
    pub fn select_relays(&self, n: usize) -> Vec<[u8; 32]> {
        use rand::seq::SliceRandom;
        let mut peers: Vec<[u8; 32]> = self.inner.lock().unwrap().peers.keys().copied().collect();
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
                let state = self.inner.lock().unwrap();
                state.sessions.lock().unwrap().is_established(dst)
            };
            if !established {
                let init_data = {
                    let state = self.inner.lock().unwrap();
                    let mut sm = state.sessions.lock().unwrap();
                    sm.get_or_initiate_bytes(dst).unwrap_or_default()
                };
                if !init_data.is_empty() {
                    self.inner.lock().unwrap().send_traffic_to(dst, init_data);
                }
                bail!("session not established with {:?}", &dst[..4]);
            }
        }

        // Encrypt payload with session key, wrap in Traffic, then wrap in onion layers
        let padded = pad_payload(payload);
        let ciphertext = {
            let state = self.inner.lock().unwrap();
            state.sessions.lock().unwrap().encrypt(dst, &padded)?
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
        let next_hop = self.inner.lock().unwrap().lookup(&first_relay);
        if let Some(next) = next_hop {
            self.inner.lock().unwrap().send_to_peer(&next, encoded);
        } else {
            bail!("no route to first relay {:?}", &first_relay[..4]);
        }
        Ok(())
    }

    pub fn mtu(&self) -> u64 {
        65535
    }

    pub async fn close(&self) {
        // Drop all peer connections
        self.inner.lock().unwrap().peers.clear();
    }

    pub fn get_peer_stats(&self) -> Vec<PeerStats> {
        let state = self.inner.lock().unwrap();
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

    pub async fn set_path_notify<F: Fn([u8; 32]) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock().unwrap().path_notify = Some(Arc::new(f));
    }

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
        let peer_keys: Vec<PeerId> = self.inner.lock().unwrap().peers.keys().copied().collect();
        for pk in peer_keys {
            self.inner.lock().unwrap().send_to_peer(&pk, encoded.clone());
        }
    }
}

