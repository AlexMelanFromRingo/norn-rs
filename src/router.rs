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
use crate::packet::*;
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
// Source privacy helpers
// ──────────────────────────────────────────────

/// Encrypt a sender's ed25519 pub key so only `dest_ed_pub` can read it.
///
/// Output: [epk: 32][ChaCha20Poly1305(source_ed_pub, aad=epk): 48] = 80 bytes
/// The ephemeral X25519 keypair is discarded after use (forward secrecy).
fn encrypt_source(source_ed_pub: &[u8; 32], dest_ed_pub: &[u8; 32]) -> [u8; 80] {
    // Ephemeral X25519 keypair
    let epk_priv = StaticSecret::random_from_rng(OsRng);
    let epk_pub = X25519PublicKey::from(&epk_priv);

    // Derive dest's X25519 pub key from its ed25519 pub key
    let dest_x = match ed25519_pub_to_x25519(dest_ed_pub) {
        Ok(k) => k,
        Err(_) => return [0u8; 80],
    };

    // ECDH shared secret → ChaCha20Poly1305 key
    let shared = epk_priv.diffie_hellman(&dest_x);
    let key = Key::from_slice(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);

    // Nonce = 0 (safe because key is unique per ephemeral pair)
    let nonce = Nonce::from([0u8; 12]);
    let aad = epk_pub.as_bytes();

    let mut buf = source_ed_pub.to_vec();
    if cipher.encrypt_in_place(&nonce, aad, &mut buf).is_err() {
        return [0u8; 80];
    }
    // buf is now 48 bytes (32 plaintext + 16 tag)

    let mut out = [0u8; 80];
    out[..32].copy_from_slice(epk_pub.as_bytes());
    out[32..].copy_from_slice(&buf);
    out
}

/// Decrypt enc_source using our ed25519 signing key.
/// Returns the sender's ed25519 pub key, or None if decryption fails.
fn decrypt_source(enc_source: &[u8; 80], my_signing_key: &SigningKey) -> Option<[u8; 32]> {
    let epk_pub_bytes: [u8; 32] = enc_source[..32].try_into().ok()?;
    let epk_pub = X25519PublicKey::from(epk_pub_bytes);
    let ciphertext = &enc_source[32..]; // 48 bytes

    // Convert our ed25519 priv to x25519 priv
    let my_x_priv = ed25519_priv_to_x25519(&my_signing_key.to_bytes());

    // ECDH shared secret
    let shared = my_x_priv.diffie_hellman(&epk_pub);
    let key = Key::from_slice(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from([0u8; 12]);
    let aad = &epk_pub_bytes;

    let mut buf = ciphertext.to_vec();
    cipher.decrypt_in_place(&nonce, aad, &mut buf).ok()?;
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
                if let Some(parent_key) = best_parent {
                    if let Some(ann) = self.peers.get(&parent_key).and_then(|p| p.trees[0].as_ref()) {
                        self.own_depth = ann.depth + 1;
                    }
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
        if self.tick % CUCKOO_GEN_TICKS == 0 && self.tick > 0 {
            self.cuckoo_generation[tree_id] += 1;
        }
        let generation = self.cuckoo_generation[tree_id];

        // Build merged cuckoo of all peers except parent
        let parent = self.trees[tree_id].parent;
        let mut merged = CuckooFilter::new();

        // Add our own key to our cuckoo
        merged.add(&self.pub_key);

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
            if let Some(parent_key) = parent {
                if let Some(peer) = self.peers.get(&parent_key) {
                    fm.merge(&peer.cuckoo[tree_id]);
                }
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
        if self.tick % KEEPALIVE_TICKS == 0 {
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
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
            // Measure RTT
            if let Some((pending_seq, sent_time)) = peer.pending_sig_req_time.take() {
                if pending_seq == res.seq {
                    let rtt = Instant::now().duration_since(sent_time);
                    let new_lag = rtt / 2;
                    // Exponential moving average
                    let old_lag_us = peer.lag.as_micros() as i64;
                    let new_lag_us = new_lag.as_micros() as i64;
                    let diff = (new_lag_us - old_lag_us).unsigned_abs() as u64;
                    peer.jitter = Duration::from_micros(
                        (peer.jitter.as_micros() as u64 * 7 / 8) + diff / 8
                    );
                    peer.lag = Duration::from_micros(
                        (old_lag_us as u64 * 7 / 8) + new_lag_us as u64 / 8
                    );
                }
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

        // Check cuckoo filters for all peers
        let mut candidates: Vec<(PeerId, u64)> = Vec::new();
        for (peer_key, peer) in &self.peers {
            for tree_id in 0..K {
                if peer.cuckoo[tree_id].contains(&lookup.target) {
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
        if broken.source != self.pub_key {
            if let Some(next_hop) = self.lookup(&broken.source) {
                let encoded = broken.encode();
                self.send_to_peer(&next_hop, encoded);
            }
        }
    }

    pub fn handle_traffic(&mut self, from: PeerId, traffic: Traffic) {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
            peer.rx_bytes += traffic.payload.len() as u64;
        }

        if traffic.dest == self.pub_key {
            // Session control messages carry the sender's ed pub key inside the
            // payload wire format ([magic:1][ed_pub:32]...) — no need to decrypt
            // enc_source for routing the ACK.
            if traffic.payload.first().copied() == Some(SESSION_INIT_MAGIC) {
                let ack_opt = self.sessions.lock().unwrap().handle_init(&traffic.payload).ok();
                if let Some(ack_bytes) = ack_opt {
                    // Extract sender's ed pub from payload (bytes 1..33)
                    if traffic.payload.len() >= 33 {
                        let mut sender = [0u8; 32];
                        sender.copy_from_slice(&traffic.payload[1..33]);
                        self.send_traffic_to(&sender, ack_bytes);
                    }
                }
                return;
            }
            if traffic.payload.first().copied() == Some(SESSION_ACK_MAGIC) {
                let _ = self.sessions.lock().unwrap().handle_ack(&traffic.payload);
                return;
            }

            // Regular encrypted payload: decrypt enc_source to identify sender,
            // then use the session key for that sender to decrypt the payload.
            let source = match decrypt_source(&traffic.enc_source, &self.signing_key) {
                Some(s) => s,
                None => {
                    debug!("failed to decrypt enc_source in Traffic from {:?}", &from[..4]);
                    return;
                }
            };

            let decrypted = {
                let mut sm = self.sessions.lock().unwrap();
                match sm.decrypt(&source, &traffic.payload) {
                    Ok(d) => d,
                    Err(e) => {
                        debug!("decrypt failed from {:?}: {}", &source[..4], e);
                        return;
                    }
                }
            };
            let pkt = InboundPacket { from: source, payload: decrypted };
            let _ = self.traffic_tx.try_send(pkt);
        } else {
            // Forward using greedy routing — enc_source is opaque to us
            if let Some(next_hop) = self.lookup(&traffic.dest) {
                let encoded = traffic.encode();
                self.send_to_peer(&next_hop, encoded);
            } else {
                debug!("no route to {:?}", &traffic.dest[..4]);
            }
        }
    }

    /// Send a payload wrapped in a Traffic packet to `dst`, routing greedily.
    fn send_traffic_to(&mut self, dst: &PeerId, payload: Vec<u8>) {
        let src = self.pub_key;
        let enc_source = encrypt_source(&src, dst);
        let traffic = Traffic {
            path: vec![],
            from: src,
            enc_source,
            dest: *dst,
            watermark: 0,
            payload,
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
        let mut best: Option<(PeerId, u64)> = None;

        for (peer_key, peer) in &self.peers {
            for tree_id in 0..K {
                if peer.cuckoo[tree_id].contains(dst) {
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
                state.lock().unwrap().handle_traffic(from, traffic);
            }
        }
        TYPE_COORD_ANNOUNCE => {
            if let Ok(ann) = CoordAnnounce::decode(data) {
                state.lock().unwrap().handle_coord_announce(from, ann);
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

        PacketConn {
            inner: state,
            traffic_rx: tokio::sync::Mutex::new(traffic_rx),
            pub_key,
        }
    }

    /// Attach a new peer connection.
    pub async fn handle_conn(
        &self,
        remote_pub_key: [u8; 32],
        mut reader: impl AsyncRead + Unpin + Send + 'static,
        mut writer: impl AsyncWrite + Unpin + Send + 'static,
        priority: u8,
    ) {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);

        // Register peer
        self.inner.lock().unwrap().add_peer(remote_pub_key, tx, priority);

        let state = self.inner.clone();

        // Writer task
        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if write_frame(&mut writer, &data).await.is_err() {
                    break;
                }
            }
        });

        // Reader task
        let state_r = state.clone();
        tokio::spawn(async move {
            loop {
                match read_frame(&mut reader).await {
                    Ok(frame) => {
                        dispatch(&state_r, remote_pub_key, frame);
                    }
                    Err(e) => {
                        debug!("peer {:?} disconnected: {}", &remote_pub_key[..4], e);
                        state_r.lock().unwrap().remove_peer(&remote_pub_key);
                        break;
                    }
                }
            }
        });

        // Initiate session exchange: wrap SessionInit in Traffic so it follows
        // the same path as data and works correctly in multi-hop scenarios.
        let init_bytes = {
            let s = state.lock().unwrap();
            s.sessions.lock().unwrap().get_or_initiate_bytes(&remote_pub_key)
        };
        if let Some(init_data) = init_bytes {
            state.lock().unwrap().send_traffic_to(&remote_pub_key, init_data);
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

        let ciphertext = {
            let state = self.inner.lock().unwrap();
            state.sessions.lock().unwrap().encrypt(dst, payload)?
        };

        let pub_key = self.pub_key;
        let enc_source = encrypt_source(&pub_key, dst);
        let traffic = Traffic {
            path: vec![],
            from: pub_key,
            enc_source,
            dest: *dst,
            watermark: 0,
            payload: ciphertext,
        };
        let encoded = traffic.encode();
        // Important: extract next_hop into a variable so the MutexGuard is
        // dropped at the `;` before we try to lock again in send_to_peer.
        // Rust extends temporary lifetimes in `if let` scrutinees to the end
        // of the block, which would cause a deadlock with std::sync::Mutex.
        let next_hop = self.inner.lock().unwrap().lookup(dst);
        if let Some(next_hop) = next_hop {
            self.inner.lock().unwrap().send_to_peer(&next_hop, encoded);
        } else {
            bail!("no route to {:?}", &dst[..4]);
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

