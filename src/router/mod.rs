// Core routing engine for norn-rs
// K=3 parallel spanning trees (Urd, Verdandi, Skuld)
// Loss-aware routing cost, cuckoo filter gossip, landmark routing

use anyhow::{bail, Result};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
use rand::rngs::OsRng;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

mod diagnostics;
pub use diagnostics::*;
mod lockutil;
use lockutil::*;
mod onion;
mod handlers;
mod reputation;
mod coords;
mod path_negative;
#[cfg(feature = "sphinx")]
mod capabilities;

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
/// Roadmap #9: adaptive control-plane cadence bounds. While the
/// topology digest is unchanged the ANNOUNCE / CoordAnnounce interval
/// backs off linearly from MIN to MAX ticks; any change snaps it back
/// to MIN. MAX stays well under `ANNOUNCE_EXPIRY` (30 s) so a
/// neighbour's cached announce is always refreshed before it expires.
const CONTROL_MIN_INTERVAL: u32 = 1;
const CONTROL_MAX_INTERVAL: u32 = 8;
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
/// Size of the per-node onion-replay LRU. Each entry is a 32-byte hash.
/// At 4 096 entries that's 128 KiB — enough to cover ~minutes of cells at
/// modest traffic rates without growing unbounded.
const ONION_REPLAY_CACHE_SIZE: usize = 4_096;
/// Rotate the onion ephemeral key every N maintenance ticks (1 hour at 1 Hz).
const ONION_KEY_ROTATION_TICKS: u32 = 3_600;
/// Broadcast reputation reports about our direct peers every N ticks (~60s).
const REPUTATION_REPORT_TICKS: u32 = 60;
/// Maximum age (ms) of a reputation report we still trust / forward.
const REPUTATION_VALIDITY_MS: u64 = 60 * 60 * 1_000; // 1h
/// Cap on remembered reputation entries (per observed × per observer).
const MAX_REPUTATION_OBSERVATIONS: usize = 16_384;
/// Broadcast our OnionKeyAnnounce every N maintenance ticks (~5 min) and on rotation.
const ONION_KEY_ANNOUNCE_TICKS: u32 = 300;
/// Maximum age (ms) of an OnionKeyAnnounce that we still trust / forward.
const ONION_KEY_VALIDITY_MS: u64 = 24 * 60 * 60 * 1_000;
/// Cap on remembered foreign onion keys (LRU-ish via HashMap, evicts on insert
/// when full — see record_remote_onion_key).
const MAX_REMOTE_ONION_KEYS: usize = 16_384;
/// Re-flood our CapabilityAnnounce every N ticks (≈ 60 s), and once at tick 1, so
/// newly-joined peers learn our capabilities promptly. Caps are static, so the
/// seq-dedup makes re-floods cheap.
#[cfg(feature = "sphinx")]
const CAPABILITY_BROADCAST_TICKS: u32 = 60;
/// Maximum age (ms) of a CapabilityAnnounce we still trust / forward.
#[cfg(feature = "sphinx")]
const CAPABILITY_VALIDITY_MS: u64 = 24 * 60 * 60 * 1_000;
/// Cap on remembered foreign capability records (evicts a non-peer entry on
/// insert when full — mirrors record_remote_onion_key).
#[cfg(feature = "sphinx")]
const MAX_CAPABILITY_ENTRIES: usize = 16_384;
/// Issue one path-validation probe every N maintenance ticks.
const PROBE_INTERVAL_TICKS: u32 = 15;
/// How long a `(peer, routing_tag)` negative-route hint stays in cache.
/// Tradeoff: too short → cuckoo FPs keep wasting forwards; too long → real
/// route restorations (after a peer recovers) take this long to be tried
/// again. 60s sits in the middle, well below typical cuckoo gossip churn.
const PATH_NEG_TTL: Duration = Duration::from_secs(60);
/// Cap on the negative cache to bound memory. 16k entries × ~50 bytes ≈ 800 KB.
const MAX_PATH_NEG_CACHE: usize = 16_384;
/// Initial TTL for an outbound PathNegative frame. Each hop decrements;
/// frame is dropped at zero. Caps the reach of forged PathNegatives so an
/// attacker cannot poison routes across the entire mesh from one node.
const PATH_NEG_INITIAL_TTL: u8 = 4;
/// Minimum distinct observers required before `consensus_trust` returns Some.
/// Below this we treat the observation set as too small to defeat a Sybil
/// (the attacker could plausibly own ALL the observers). Caller then falls
/// back to local trust alone, which already has anti-poisoning via probe
/// success / failure.
const REPUTATION_MIN_QUORUM: usize = 3;
/// Fraction of observers (each end) discarded by the trimmed mean before
/// averaging. 0.25 means drop top 25 % and bottom 25 %. A coalition must
/// hold more than 25 % of WEIGHTED voting power on this peer to shift
/// consensus — a much higher bar than the simple-mean default that lets
/// one extreme vote pull the average by 1/N.
const REPUTATION_TRIM_FRAC: f64 = 0.25;
/// PoW difficulty at which an observer's weight saturates to 1.0. Below this,
/// weight scales linearly from `REPUTATION_WEIGHT_FLOOR` → 1.0. Picked to
/// match a realistic Sybil-resistance ask (16 bits ≈ 65k iterations, cheap
/// for a real peer, expensive at fleet scale for an attacker).
const REPUTATION_WEIGHT_BITS: u32 = 16;
/// Minimum weight any observer gets, regardless of PoW. Prevents PoW=0
/// observations from being silently discarded — they still count, just at
/// 1/N of a fully-PoWed peer.
const REPUTATION_WEIGHT_FLOOR: f64 = 0.0625; // 1/16
/// Probes that have been pending this long without a PathNotify are counted
/// as a failure: the via-peer's trust score decays.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Trust score in [0.01, 4.0]; 1.0 is the default. Operators can spot a
    /// poisoning attempt by an outlier with very low trust.
    pub trust: f32,
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

/// Roadmap #9: snapshot of everything the periodic control broadcasts
/// (`send_announces` ×K + `broadcast_coord`) encode. Two equal
/// snapshots mean a re-broadcast would carry the same topology, so the
/// adaptive cadence can safely skip it.
///
/// Deliberately excludes `parent_cost`: it is a soft routing metric
/// that jitters with RTT noise, and letting it refresh lazily within
/// `CONTROL_MAX_INTERVAL` instead of forcing a broadcast every tick is
/// exactly the freshness-for-chatter trade roadmap #9 makes. The digest
/// keeps only *topological identity* — root, root_seq, parent, depth —
/// plus the onion ephemeral pub the CoordAnnounce carries and the peer
/// count, so a peer join/leave snaps the cadence back to fast.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ControlDigest {
    trees: [(PeerId, u64, Option<PeerId>); K],
    own_depth: u32,
    onion_eph_pub: [u8; 32],
    peer_count: usize,
}

/// Public snapshot of one tree's current state — returned by
/// `PacketConn::get_tree_state` and rendered into `/metrics` so a scraper
/// can reconstruct the global per-tree topology across all nodes.
#[derive(Clone, Debug)]
pub struct TreeStat {
    pub tree_id: u8,
    /// Pub_key of the current root candidate this node sees.
    pub root: [u8; 32],
    /// Direct parent in this tree. `None` means we ARE the root.
    pub parent: Option<[u8; 32]>,
    /// Hop distance from root, as derived from received Announces.
    /// Only meaningful for tree 0 (we only track own_depth there).
    pub depth: u32,
    /// Cost of the best path to root (us → parent → … → root).
    pub parent_cost: u64,
    /// Whether we are the root in this tree right now.
    pub is_root: bool,
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
    /// Parallel write channels. One per underlying TCP/QUIC link this
    /// peer is connected over. `send_to_peer` round-robins across them
    /// so a single peer pair can saturate more than one kernel TCP
    /// flow — each link runs its own CUBIC cwnd, so on a long-fat WAN
    /// where one flow caps at the loss-driven steady-state, N flows
    /// aggregate to N× before any one of them collides with the same
    /// loss event. v0.1 (single-tx) was a degenerate `txs.len() == 1`.
    txs: Vec<mpsc::Sender<Vec<u8>>>,
    /// Round-robin counter for picking the next tx slot. Wrapping
    /// usize so it's free of atomics on the sync `&mut self` send
    /// path.
    next_tx: usize,
    priority: u8,
    rx_bytes: u64,
    tx_bytes: u64,
    connected_at: Instant,
    // RTT tracking
    pending_sig_req_time: Option<(u64, Instant)>, // (seq, sent_time)
    sig_req_seq: u64,
    /// Latest onion-ephemeral X25519 pub key this peer has advertised (via signed
    /// CoordAnnounce). Used when selecting this peer as a relay so that we
    /// encrypt the onion layer with its CURRENT ephemeral key rather than its
    /// long-term identity-derived key.
    onion_eph_pub: Option<[u8; 32]>,
    /// Trust score in [TRUST_MIN, TRUST_MAX]. Used as a cost multiplier in
    /// lookup_by_tag: peers with lower trust get a higher effective cost and
    /// are de-prioritised when multiple peers claim the same routing tag.
    /// This neutralises cuckoo poisoning: a malicious peer that claims tags
    /// it can't actually reach will fail probes (when probing is enabled) and
    /// fall to the bottom of the lookup ranking.
    trust: f32,
}

/// Maximum number of parallel write channels we'll register for one
/// peer pub_key. The default-1 (no-multi) case still works because a
/// vec-of-1 just round-robins to itself. Cap is set high enough to
/// accommodate sane multi-TCP / multi-QUIC bonding (8 cores, 8 flows)
/// without letting a misbehaving peer redial unbounded.
pub const MAX_PARALLEL_LINKS_PER_PEER: usize = 8;

/// Starting trust for a new peer.
const TRUST_INITIAL: f32 = 1.0;
/// Floor — peers never lose ALL trust (a fully-poisoned filter would still
/// be tried as a last-resort path).
const TRUST_MIN: f32 = 0.01;
/// Ceiling — boosts don't accumulate beyond this.
const TRUST_MAX: f32 = 4.0;

impl PeerData {
    fn effective_cost(&self) -> u64 {
        effective_cost(self.lag, self.loss_rate)
    }

    /// Trust-adjusted cost: low trust → high cost → de-prioritised in lookups.
    /// Caps at u64::MAX to avoid overflow.
    #[allow(dead_code)] // kept for symmetry with `trust_adjusted_cost_with`; used by tests
    fn trust_adjusted_cost(&self) -> u64 {
        self.trust_adjusted_cost_with(self.trust)
    }

    /// Same as `trust_adjusted_cost` but with the trust value supplied
    /// externally — used by `lookup_by_tag_excluding` to blend the local
    /// trust score with the network-consensus trust derived from
    /// `ReputationReport` gossip.
    fn trust_adjusted_cost_with(&self, trust: f32) -> u64 {
        let base = self.effective_cost() as f64;
        let trust = trust.clamp(TRUST_MIN, TRUST_MAX) as f64;
        let adjusted = base / trust;
        if adjusted >= u64::MAX as f64 { u64::MAX } else { adjusted as u64 }
    }

    /// Decay trust on probe failure / route timeout. Multiplicative for fast
    /// recovery (one bad probe ≠ permanent black-listing).
    fn decay_trust(&mut self) {
        self.trust = (self.trust * 0.5).max(TRUST_MIN);
    }

    /// Boost trust on probe success / observed successful delivery.
    fn boost_trust(&mut self) {
        self.trust = (self.trust * 1.2).min(TRUST_MAX);
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
    /// Rotating per-node onion ephemeral keypair. Distinct from `signing_key`
    /// for forward secrecy: compromising the long-term identity does not let
    /// an attacker decrypt past onion traffic that transited this node.
    onion_keys: crate::onion::OnionKeyChain,
    /// LRU-style set of recent onion (epk, aead-prefix) hashes for replay
    /// detection. Bounded; oldest entries evicted when full.
    onion_seen: std::collections::VecDeque<[u8; 32]>,
    /// O(1) membership mirror of `onion_seen`. The VecDeque keeps FIFO
    /// eviction order; this set answers "seen before?" without an O(n)
    /// linear scan on every onion packet (the relay hot path). Both hold
    /// exactly the same elements.
    onion_seen_set: std::collections::HashSet<[u8; 32]>,
    /// Network-wide table of current onion ephemeral pubs per identity.
    /// Populated from OnionKeyAnnounce floods. Latest seq per origin wins.
    /// (seq, eph_pub, recorded_at)
    remote_onion_keys: HashMap<[u8; 32], (u64, [u8; 32], Instant)>,
    /// Monotonic seq for our own OnionKeyAnnounce broadcasts.
    own_onion_key_seq: u64,
    /// Network-wide table of advertised capabilities per identity, from
    /// CapabilityAnnounce floods. (caps_bitfield, seq, recorded_at); latest seq
    /// per origin wins. A sender consults this before choosing the Sphinx onion.
    #[cfg(feature = "sphinx")]
    peer_capabilities: HashMap<[u8; 32], (u32, u64, Instant)>,
    /// Monotonic seq for our own CapabilityAnnounce broadcasts.
    #[cfg(feature = "sphinx")]
    own_caps_seq: u64,
    /// Which onion format we BUILD when sending (config; default Auto). Inbound
    /// always accepts both. See `path_supports_sphinx` for the Auto decision.
    #[cfg(feature = "sphinx")]
    onion_format: crate::config::OnionFormat,
    /// Outgoing probe table: probe_id → (peer-we-sent-via, sent_at).
    /// On matching PathNotify → boost trust + remove. On timeout (handled
    /// in cleanup_stale_probes) → decay trust + remove.
    pending_probes: HashMap<u64, (PeerId, Instant)>,
    /// Reputation table: per observed peer, map of observer → (seq, score, recorded_at).
    /// Populated from `ReputationReport` frames received from anywhere in
    /// the mesh; used to compute consensus trust that biases lookups.
    reputation: HashMap<[u8; 32], HashMap<[u8; 32], ReputationEntry>>,
    /// Monotonic seq for our own outbound reputation reports.
    own_reputation_seq: u64,
    /// Optional callback fired when a HolePunch frame is received with us
    /// as the target. Receives (initiator_pub_key, claimed_endpoint).
    /// Operators set this via PacketConn::set_on_hole_punch to drive a
    /// simultaneous outbound QUIC connect for symmetric-NAT traversal.
    hole_punch_cb: Option<HolePunchCb>,
    /// Negative-routing cache. Populated when an UPSTREAM peer tells us
    /// (via `PathNegative`) that *they* failed to deliver a packet we sent
    /// for `routing_tag`. We then avoid picking that peer for that tag for
    /// `PATH_NEG_TTL`. Bounds cuckoo-FP cost to one wasted forward per
    /// (peer, tag) per TTL.
    ///
    /// Wait — the directionality matters: PathNegative travels UPSTREAM
    /// (from a forwarder back to whoever sent the doomed packet). So when
    /// WE receive it from peer P, we should learn "P cannot reach this
    /// tag" → cache (P, tag). Next lookup_by_tag skips P.
    path_negative_cache: HashMap<([u8; 32], [u8; 16]), Instant>,
    /// Roadmap #9 adaptive control-plane cadence: the last broadcast
    /// topology digest, the tick it went out on, and the current
    /// inter-broadcast interval in ticks.
    last_control_digest: Option<ControlDigest>,
    last_control_tick: u32,
    control_interval: u32,
}

/// One observation in `reputation`.
type ReputationEntry = (u64, f32, Instant);

/// Callback alias for the hole-punch handler.
type HolePunchCb = Arc<dyn Fn([u8; 32], String) + Send + Sync>;

mod header;
// `pub` so the public metric fns (tree_metric, effective_cost, …) keep their
// public-API status after the split (they were `pub fn` at the router root).
pub mod treemath;
use header::*;
use treemath::*;

// ──────────────────────────────────────────────
// RouterState implementation
// ──────────────────────────────────────────────

impl RouterState {
    fn new(signing_key: SigningKey, traffic_tx: mpsc::Sender<InboundPacket>) -> Self {
        let pub_key = signing_key.verifying_key().to_bytes();
        let sessions = Arc::new(std::sync::RwLock::new(SessionManager::new(signing_key.clone())));
        let onion_keys = crate::onion::OnionKeyChain::with_identity_fallback(&signing_key);

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
            onion_keys,
            onion_seen: std::collections::VecDeque::with_capacity(ONION_REPLAY_CACHE_SIZE),
            onion_seen_set: std::collections::HashSet::with_capacity(ONION_REPLAY_CACHE_SIZE),
            remote_onion_keys: HashMap::new(),
            own_onion_key_seq: 0,
            #[cfg(feature = "sphinx")]
            peer_capabilities: HashMap::new(),
            #[cfg(feature = "sphinx")]
            own_caps_seq: 0,
            #[cfg(feature = "sphinx")]
            onion_format: crate::config::OnionFormat::Auto,
            pending_probes: HashMap::new(),
            reputation: HashMap::new(),
            own_reputation_seq: 0,
            hole_punch_cb: None,
            path_negative_cache: HashMap::new(),
            last_control_digest: None,
            last_control_tick: 0,
            control_interval: CONTROL_MIN_INTERVAL,
        }
    }

    /// Register a write channel for a peer. If the peer already exists
    /// (multi-link case — same pub_key over a second TCP connection),
    /// the new sender is appended to the existing `txs` list so
    /// `send_to_peer` can spread traffic round-robin across both
    /// links. Caps the per-peer link count at `MAX_PARALLEL_LINKS_PER_PEER`
    /// to bound memory and writer-task count even if a misbehaving
    /// peer keeps redialing.
    fn add_peer(&mut self, pub_key: PeerId, tx: mpsc::Sender<Vec<u8>>, priority: u8) {
        if let Some(existing) = self.peers.get_mut(&pub_key) {
            if existing.txs.len() >= MAX_PARALLEL_LINKS_PER_PEER {
                debug!(
                    "add_peer: {:?} already at the {}-link cap, ignoring extra link",
                    &pub_key[..4], MAX_PARALLEL_LINKS_PER_PEER
                );
                return;
            }
            existing.txs.push(tx);
            debug!(
                "add_peer: {:?} now has {} parallel link(s)",
                &pub_key[..4], existing.txs.len()
            );
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
            txs: vec![tx],
            next_tx: 0,
            priority,
            rx_bytes: 0,
            tx_bytes: 0,
            connected_at: Instant::now(),
            pending_sig_req_time: None,
            sig_req_seq: 0,
            onion_eph_pub: None,
            trust: TRUST_INITIAL,
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
        // Drop the cached encryption session too.
        //
        // Without this, when the peer reconnects (handle_conn picks
        // up a fresh TCP after the old one died), the new SessionInit
        // takes the "existing session" branch in `SessionManager::
        // handle_init` and reuses the OLD `local_x25519_priv`. That's
        // structurally OK for crossing-init convergence, BUT every
        // intervening write_to call hits `is_established(dst) == true`
        // and encrypts with the still-cached keys. The bytes go into
        // a dead TCP socket / phantom session and disappear without
        // ever surfacing a "session not established" error that the
        // mux's write_with_session_wait would retry on. End result:
        // the data plane silently stops working until the daemon is
        // restarted.
        //
        // Real-WAN repro on 2026-05-19: ping through bifrost-vpnd
        // tunnel kept failing 4/4 after exit restart even though the
        // TCP reconnected. Caching the session prevented the natural
        // retry path that already worked for cold-start cases.
        self.sessions.write_or_recover().remove(pub_key);
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
        // Use the current epoch so root selection sweeps across the network
        // over time instead of pinning a deterministic permanent root that an
        // attacker can DDoS or censor (mitigation for the "static root" risk).
        let epoch = current_tree_epoch();
        let my_metric = tree_metric_at(&self.pub_key, &TREE_SEEDS[tree_id], epoch);
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
                let root_metric = tree_metric_at(&ann.root, &TREE_SEEDS[tree_id], epoch);
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

    /// Roadmap #9: snapshot the topology the periodic control
    /// broadcasts would carry — see [`ControlDigest`].
    fn control_digest(&self) -> ControlDigest {
        ControlDigest {
            trees: std::array::from_fn(|i| {
                let t = &self.trees[i];
                (t.root, t.root_seq, t.parent)
            }),
            own_depth: self.own_depth,
            onion_eph_pub: *self.onion_keys.pub_key().as_bytes(),
            peer_count: self.peers.len(),
        }
    }

    /// Roadmap #9: adaptive control-plane cadence.
    ///
    /// `send_announces` (×K) and `broadcast_coord` otherwise re-flood
    /// the *same* bytes to every peer every tick once a neighbourhood
    /// is stable — fixed-rate chatter that scales with the node count.
    /// Instead: digest the topology; while the digest is unchanged let
    /// the interval back off linearly to `CONTROL_MAX_INTERVAL`; on any
    /// change snap back to `CONTROL_MIN_INTERVAL` and broadcast at once.
    /// Keepalives (independent, every `KEEPALIVE_TICKS`) still keep the
    /// links themselves from being declared dead.
    fn maybe_broadcast_control(&mut self) {
        let digest = self.control_digest();
        let changed = self.last_control_digest != Some(digest);
        self.control_interval = if changed {
            CONTROL_MIN_INTERVAL
        } else {
            (self.control_interval + 1).min(CONTROL_MAX_INTERVAL)
        };
        let due = changed
            || self.tick.wrapping_sub(self.last_control_tick) >= self.control_interval;
        if !due {
            CONTROL_SUPPRESSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        for i in 0..K {
            self.send_announces(i);
        }
        self.broadcast_coord();
        self.last_control_digest = Some(digest);
        self.last_control_tick = self.tick;
        CONTROL_BROADCASTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn send_to_peer(&mut self, peer_key: &PeerId, data: Vec<u8>) {
        if let Some(peer) = self.peers.get_mut(peer_key) {
            if peer.txs.is_empty() {
                debug!(
                    "send_to_peer: {:?} has zero link channels — peer is mid-teardown, drop",
                    &peer_key[..4]
                );
                return;
            }
            let len = data.len() as u64;
            // Round-robin across the parallel link channels. The starting
            // slot is the wrapping `next_tx` cursor; on TrySendError::Full
            // we walk the remaining slots once before giving up, so a single
            // saturated link doesn't drop the frame as long as one of the
            // siblings has headroom. This is the "spillover" piece of
            // bonding — without it, three healthy 8K-slot channels plus one
            // wedged channel would still drop 25% of frames.
            let n = peer.txs.len();
            let start = peer.next_tx % n;
            peer.next_tx = peer.next_tx.wrapping_add(1);
            let mut last_full = false;
            for offset in 0..n {
                let idx = (start + offset) % n;
                let tx = &peer.txs[idx];
                match tx.try_send(data.clone()) {
                    Ok(()) => {
                        peer.tx_bytes += len;
                        peer.last_tx_time = Instant::now();
                        return;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        last_full = true;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        // Closed channel = writer task exited (peer link
                        // died). Drop it from the rotation so we don't
                        // keep trying it. Walk the rest, then GC outside
                        // the loop.
                    }
                }
            }
            // Sweep closed senders out.
            peer.txs.retain(|tx| !tx.is_closed());
            if peer.txs.is_empty() {
                debug!(
                    "send_to_peer: peer {:?} lost all links, awaiting reconnect",
                    &peer_key[..4]
                );
            } else if last_full {
                // All remaining links were full at the moment we tried.
                warn!(
                    "send_to_peer: dropping frame for peer {:?} (all {} channels full)",
                    &peer_key[..4], peer.txs.len()
                );
            }
        }
    }

    /// Cuckoo filter maintenance for tree `tree_id`.
    fn cuckoo_do_maintenance(&mut self, tree_id: usize) {
        // Every CUCKOO_GEN_TICKS, advance our generation (evicts stale entries).
        // Under accelerated-rotation mode the interval drops to N seconds for
        // test-cluster purposes (does not affect production).
        let interval = accelerate_rotations_secs()
            .map(|s| s.max(1) as u32)
            .unwrap_or(CUCKOO_GEN_TICKS);
        if self.tick.is_multiple_of(interval) && self.tick > 0 {
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

        // MALICIOUS test mode: inject random routing_tags so neighbours
        // route traffic toward us that we can't deliver. This is the canonical
        // cuckoo-poisoning attack — used by the test harness to verify the
        // mesh's PathNegative + trust-decay stack actually ejects bad actors.
        // No-op when NORN_MALICIOUS_MODE is unset (production path).
        let poison_count = malicious_cuckoo_poison_tags();
        if poison_count > 0 {
            // New random tags every emission so victims can't dedupe.
            let mut rng = OsRng;
            for _ in 0..poison_count {
                let mut tag = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rng, &mut tag);
                merged.add(&tag);
            }
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
                // If a previous SigReq was never acknowledged, count it as a loss
                // AND decay this peer's trust score. A peer that doesn't respond
                // to liveness pings shouldn't be trusted with route claims either.
                if peer.pending_sig_req_time.is_some() {
                    peer.loss_rate = peer.loss_rate * 0.875 + 0.125;
                    peer.decay_trust();
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
            self.cuckoo_do_maintenance(i);
        }
        self.update_own_coord();
        // Roadmap #9: adaptive cadence — replaces the unconditional
        // per-tick `send_announces` ×K + `broadcast_coord`.
        self.maybe_broadcast_control();
        if self.tick.is_multiple_of(KEEPALIVE_TICKS) {
            self.send_keepalives();
        }
        self.rotate_session_keys();
        self.rotate_onion_keys_if_due();
        self.rotate_pq_keys_if_due();
        // Periodically re-announce our onion ephemeral pub so the network-wide
        // table heals after splits/peer churn. Multiple-of check fires on the
        // first tick too — that's the deliberate cold-start announce.
        if self.tick == 1 || self.tick.is_multiple_of(ONION_KEY_ANNOUNCE_TICKS) {
            self.broadcast_onion_key_announce();
        }
        // Capability gossip — cold-start at tick 1, then periodically so newly
        // joined peers learn we accept the Sphinx onion.
        #[cfg(feature = "sphinx")]
        if self.tick == 1 || self.tick.is_multiple_of(CAPABILITY_BROADCAST_TICKS) {
            self.broadcast_capabilities();
        }
        // Active route validation: probe one cuckoo claim per cycle.
        if self.tick.is_multiple_of(PROBE_INTERVAL_TICKS) && self.tick > 0 {
            self.probe_cuckoo_claim();
        }
        // Reputation gossip: every minute send signed trust reports about
        // each direct peer. Receivers aggregate into consensus_trust used
        // alongside local trust in routing decisions.
        if self.tick.is_multiple_of(REPUTATION_REPORT_TICKS) && self.tick > 0 {
            self.broadcast_reputation();
        }
        self.cleanup_stale_probes();
        self.cleanup_stale_lookups();
        self.cleanup_stale_sessions();
        self.cleanup_path_negative_cache();
    }

    /// Rotate the onion ephemeral keypair at the configured cadence.
    /// On rotation, the old key moves to the `previous` slot so in-flight
    /// onions still decrypt for one more period, then is zeroized on the
    /// rotation after that. Also forces an immediate OnionKeyAnnounce so
    /// neighbours don't keep building onions with our about-to-expire pub.
    #[mutants::skip]
    fn rotate_onion_keys_if_due(&mut self) {
        // Under NORN_ACCELERATE_ROTATIONS_SECS, treat that env value as the
        // tick interval directly (1 tick = 1s). At default this stays at
        // ONION_KEY_ROTATION_TICKS = 3600 (1h).
        let interval = accelerate_rotations_secs()
            .map(|s| s.max(1) as u32)
            .unwrap_or(ONION_KEY_ROTATION_TICKS);
        if self.tick.is_multiple_of(interval) && self.tick > 0 {
            self.onion_keys.rotate();
            self.broadcast_onion_key_announce();
            debug!("onion keys rotated at tick {} (interval {})", self.tick, interval);
        }
    }

    /// Rotate the long-term ML-KEM keypair if the time-based threshold has
    /// passed. Cheap when nothing's due; we just check the timer.
    #[mutants::skip]
    fn rotate_pq_keys_if_due(&self) {
        let mut sm = self.sessions.write_or_recover();
        if sm.maybe_rotate_pq_keys() {
            debug!("ML-KEM long-term keypair rotated");
        }
    }

    /// Periodic OnionKeyAnnounce broadcast. Each broadcast carries a strictly
    /// increasing seq so receivers can dedup/order. We flood to all peers;
    /// each peer that's first-to-see for this (origin, seq) forwards onward.
    #[mutants::skip]
    fn broadcast_onion_key_announce(&mut self) {
        self.own_onion_key_seq += 1;
        let seq = self.own_onion_key_seq;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let onion_eph_pub = *self.onion_keys.pub_key().as_bytes();
        let unsigned = OnionKeyAnnounce {
            origin: self.pub_key,
            seq,
            valid_from_ms: now_ms,
            onion_eph_pub,
            sig: [0u8; 64],
        };
        let sig = self.signing_key.sign(&unsigned.sign_bytes()).to_bytes();
        let ann = OnionKeyAnnounce { sig, ..unsigned };
        // Record ourselves so onion_hop_for can find us via remote_onion_keys too.
        self.remote_onion_keys.insert(
            self.pub_key,
            (seq, onion_eph_pub, Instant::now()),
        );
        let encoded = ann.encode();
        let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
        for pk in peer_keys {
            self.send_to_peer(&pk, encoded.clone());
        }
    }

    /// Handle an incoming OnionKeyAnnounce. Verify, dedup by (origin, seq),
    /// drop expired, then forward to all peers except the sender.
    pub fn handle_onion_key_announce(&mut self, from: PeerId, ann: OnionKeyAnnounce) {
        // Reject announces purportedly from ourselves (self-loop / spoof).
        if ann.origin == self.pub_key {
            return;
        }
        // Verify signature against the announced origin.
        let vk = match VerifyingKey::from_bytes(&ann.origin) {
            Ok(v) => v,
            Err(_) => return,
        };
        if vk.verify_strict(&ann.sign_bytes(), &ed25519_dalek::Signature::from_bytes(&ann.sig)).is_err() {
            warn!("invalid OnionKeyAnnounce sig from origin {:?}", &ann.origin[..4]);
            return;
        }
        // Freshness window.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let age = now_ms.saturating_sub(ann.valid_from_ms);
        if age > ONION_KEY_VALIDITY_MS {
            debug!("OnionKeyAnnounce too old ({}ms > {}ms), dropping", age, ONION_KEY_VALIDITY_MS);
            return;
        }
        // Also reject far-future timestamps (skew abuse).
        if ann.valid_from_ms > now_ms.saturating_add(60_000) {
            debug!("OnionKeyAnnounce from too far in future, dropping");
            return;
        }
        // Dedup: forward only if strictly newer than the last seq we saw from this origin.
        let is_newer = match self.remote_onion_keys.get(&ann.origin) {
            Some((prev_seq, _, _)) => ann.seq > *prev_seq,
            None => true,
        };
        if !is_newer {
            return; // already saw this or a newer one; do not re-forward
        }
        self.record_remote_onion_key(ann.origin, ann.seq, ann.onion_eph_pub);

        // Also reflect into PeerData (if origin is a direct peer) so that the
        // existing select_relays() picks up the eph for direct-peer fast path.
        if let Some(peer) = self.peers.get_mut(&ann.origin) {
            peer.onion_eph_pub = Some(ann.onion_eph_pub);
        }

        // Flood-forward to all peers except the sender.
        let encoded = ann.encode();
        let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
        for pk in peer_keys {
            if pk != from {
                self.send_to_peer(&pk, encoded.clone());
            }
        }
    }

    /// Pick one (peer, target_identity) pair where the peer's cuckoo claims
    /// to know `routing_tag(target_identity)`, then send a PathLookup for
    /// that identity *only via* that peer. The peer either delivers (we
    /// receive a PathNotify with matching id → trust boost) or it doesn't
    /// (probe times out → trust decay).
    ///
    /// This converts the otherwise-passive trust score into an active
    /// poisoning detector: a peer that lies about cuckoo membership will be
    /// caught the first time we probe one of its false claims.
    #[mutants::skip]
    fn probe_cuckoo_claim(&mut self) {
        // Collect candidate (via_peer, target_identity) pairs.
        // We consider any known identity (other direct peer or any origin in
        // remote_onion_keys) that the via_peer's cuckoo claims.
        let mut candidates: Vec<(PeerId, [u8; 32])> = Vec::new();
        let known_identities: Vec<[u8; 32]> = self.peers.keys().copied()
            .chain(self.remote_onion_keys.keys().copied())
            .filter(|id| *id != self.pub_key)
            .collect();
        for (peer_key, peer) in &self.peers {
            for target in &known_identities {
                if target == peer_key {
                    continue; // trivial: P always claims P
                }
                let tag = routing_tag(target);
                if peer.cuckoo.iter().any(|cf| cf.contains(&tag)) {
                    candidates.push((*peer_key, *target));
                }
            }
        }
        if candidates.is_empty() {
            return;
        }
        // Pick one at random.
        use rand::seq::SliceRandom;
        let &(via, target) = candidates.choose(&mut OsRng).unwrap();

        // Send PathLookup via that specific peer (not the usual flood).
        let id = rand::random::<u64>();
        let lookup = PathLookup {
            target,
            source: self.pub_key,
            id,
            path: vec![],
        };
        let encoded = lookup.encode();
        self.send_to_peer(&via, encoded);
        self.pending_probes.insert(id, (via, Instant::now()));
        debug!("probe: id={} target={:?} via={:?}", id, &target[..4], &via[..4]);
    }

    /// Sweep expired probes. Each timed-out probe decays the via-peer's trust.
    #[mutants::skip]
    fn cleanup_stale_probes(&mut self) {
        let now = Instant::now();
        let expired: Vec<(u64, PeerId)> = self.pending_probes.iter()
            .filter_map(|(id, (via, t))| {
                if now.duration_since(*t) > PROBE_TIMEOUT {
                    Some((*id, *via))
                } else {
                    None
                }
            })
            .collect();
        for (id, via) in expired {
            self.pending_probes.remove(&id);
            if let Some(peer) = self.peers.get_mut(&via) {
                peer.decay_trust();
                debug!("probe {} via {:?} timed out → trust decayed to {}", id, &via[..4], peer.trust);
            }
        }
    }

    /// Record a (potentially new) remote onion key. Caps the table at
    /// MAX_REMOTE_ONION_KEYS by evicting a random non-peer entry when full.
    fn record_remote_onion_key(&mut self, origin: [u8; 32], seq: u64, eph: [u8; 32]) {
        if !self.remote_onion_keys.contains_key(&origin)
            && self.remote_onion_keys.len() >= MAX_REMOTE_ONION_KEYS {
            // Evict a non-peer entry to make room. Falls back to skipping the
            // insert if every entry belongs to a current peer.
            let victim = self.remote_onion_keys.keys()
                .find(|k| !self.peers.contains_key(*k) && **k != self.pub_key)
                .copied();
            if let Some(v) = victim {
                self.remote_onion_keys.remove(&v);
            } else {
                return;
            }
        }
        self.remote_onion_keys.insert(origin, (seq, eph, Instant::now()));
    }

    /// Rotate x25519 keys for sessions that have sent many messages.
    // Skip mutations: requires a session with local_seq at exactly KEY_ROTATION_INTERVAL
    // to observe the rotation — that setup is complex and tested separately in session.rs.
    #[mutants::skip]
    fn rotate_session_keys(&self) {
        let sm = self.sessions.read_or_recover();
        // Snapshot the per-peer handles first so we don't hold the
        // outer SessionManager lock while doing per-peer rotation.
        let handles: Vec<_> = sm.sessions.values().cloned().collect();
        drop(sm);
        for handle in handles {
            let mut info = handle.lock().unwrap();
            if info.established && info.local_seq > 0 && info.local_seq % KEY_ROTATION_INTERVAL == 0 {
                info.rotate_local_key();
            }
        }
    }

    fn cleanup_stale_lookups(&mut self) {
        let now = Instant::now();
        self.pending_lookups.retain(|_, t| now.duration_since(*t) < Duration::from_secs(10));
    }

    /// Remove sessions that have been idle beyond SESSION_IDLE_EXPIRY.
    fn cleanup_stale_sessions(&self) {
        let now = Instant::now();
        let mut sm = self.sessions.write_or_recover();
        sm.sessions.retain(|_, handle| {
            // Per-peer lock: nobody else is allowed to be inside
            // this session's crypto while we read `last_used`, so
            // the lock is uncontended in practice.
            let info = handle.lock().unwrap();
            now.duration_since(info.last_used) < SESSION_IDLE_EXPIRY
        });
    }

    // ──────────────────────────────────────────────
    // Packet handlers
    // ──────────────────────────────────────────────

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
                if routing_tag_eq(&traffic.routing_tag, &my_tag) {
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
        TYPE_ONION_KEY_ANNOUNCE => {
            if let Ok(ann) = OnionKeyAnnounce::decode(data) {
                state.lock_or_recover().handle_onion_key_announce(from, ann);
            }
        }
        #[cfg(feature = "sphinx")]
        crate::packet::TYPE_CAPABILITIES => {
            if let Ok(ann) = crate::packet::CapabilityAnnounce::decode(data) {
                state.lock_or_recover().handle_capabilities(from, ann);
            }
        }
        TYPE_REPUTATION_REPORT => {
            if let Ok(r) = ReputationReport::decode(data) {
                state.lock_or_recover().handle_reputation_report(from, r);
            }
        }
        TYPE_HOLE_PUNCH => {
            if let Ok(hp) = HolePunch::decode(data) {
                state.lock_or_recover().handle_hole_punch(from, hp);
            }
        }
        TYPE_PATH_NEGATIVE => {
            if let Ok(neg) = crate::packet::PathNegative::decode(data) {
                state.lock_or_recover().handle_path_negative(from, neg);
            }
        }
        TYPE_ONION => {
            if let Ok(pkt) = OnionPacket::decode(data) {
                let my_pub = state.lock_or_recover().pub_key;
                let my_tag = routing_tag(&my_pub);
                if routing_tag_eq(&pkt.routing_tag, &my_tag) {
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
                        match next {
                            Some(next) => {
                                state_fwd.lock_or_recover().send_to_peer(&next, encoded);
                            }
                            None => {
                                // Onion FP/dead-end: tell upstream so it stops picking us.
                                state_fwd.lock_or_recover()
                                    .send_path_negative(from, tag, PATH_NEG_INITIAL_TTL);
                            }
                        }
                    });
                }
            }
        }
        #[cfg(feature = "sphinx")]
        crate::sphinx::TYPE_ONION_SPHINX => {
            if frame.len() != crate::sphinx::CELL_SIZE {
                debug!("sphinx: bad cell size {} from {:?}", frame.len(), &from[..4]);
                return;
            }
            // Cleartext per-segment routing tag — route to it exactly like a
            // legacy onion's outer tag. Copy it out before `frame` is moved.
            let cell_tag: [u8; 16] = frame[1..17].try_into().unwrap();
            let my_pub = state.lock_or_recover().pub_key;
            if routing_tag_eq(&cell_tag, &routing_tag(&my_pub)) {
                // We are this onion hop — peel and re-address.
                let state2 = state.clone();
                tokio::spawn(async move {
                    state2.lock_or_recover().handle_sphinx(from, frame);
                });
            } else {
                // Forwarding node: relay the unchanged cell toward cell_tag, jittered.
                let permit = forward_sem().clone().try_acquire_owned();
                let state_fwd = state.clone();
                tokio::spawn(async move {
                    let _permit = permit.ok();
                    let jitter_ms = rand::random::<u64>() % 50;
                    tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
                    let next = state_fwd.lock_or_recover()
                        .lookup_by_tag_excluding(&cell_tag, Some(from));
                    match next {
                        Some(next) => state_fwd.lock_or_recover().send_to_peer(&next, frame),
                        None => state_fwd.lock_or_recover()
                            .send_path_negative(from, cell_tag, PATH_NEG_INITIAL_TTL),
                    }
                });
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

/// Encrypt one `payload` for `dst`, wrap it in a `Traffic` envelope, and
/// hand it to the routing layer for dispatch.
///
/// This is the expensive half of [`PacketConn::write_to`] — pad +
/// ChaCha20-Poly1305 + envelope encode + route lookup — factored out so
/// the inline path and the Roadmap #2 crypto worker pool share one
/// implementation. Synchronous on purpose: the only routing step
/// (`lookup` + `send_to_peer`) is non-blocking — it just pushes onto a
/// per-peer mpsc — so a worker task can call this directly without an
/// `.await`.
///
/// Assumes the session with `dst` is already established; callers do the
/// establishment check (and queue a `SessionInit`) before reaching here.
fn encrypt_and_dispatch(
    inner: &Arc<Mutex<RouterState>>,
    pub_key: &[u8; 32],
    payload: &[u8],
    dst: &[u8; 32],
) -> Result<()> {
    // Pad before encryption so ciphertext sizes are multiples of
    // PAD_BLOCK — hides message length from observers.
    let padded = pad_payload(payload);
    // Clone the per-peer SessionHandle under a short read lock, then
    // encrypt under that peer's own mutex so encrypts to OTHER peers
    // never queue behind us.
    let handle = {
        let state = inner.lock_or_recover();
        let sm = state.sessions.read_or_recover();
        sm.get_session(dst)
    };
    let ciphertext = match handle {
        Some(h) => h.lock().unwrap().encrypt(&padded)?,
        None => bail!("session not established with {:?}", &dst[..4]),
    };

    let (enc_header, tag) = encrypt_header(pub_key, dst);
    let traffic = Traffic {
        path: vec![],
        from: *pub_key,
        enc_header,
        routing_tag: tag,
        pkt_type: packet::PKT_DATA,
        watermark: 0,
        payload: ciphertext,
    };
    let encoded = traffic.encode();
    // next_hop into a variable so the MutexGuard drops at the `;`
    // before send_to_peer relocks.
    let next_hop = inner.lock_or_recover().lookup(dst);
    match next_hop {
        Some(next_hop) => {
            inner.lock_or_recover().send_to_peer(&next_hop, encoded);
            Ok(())
        }
        None => bail!("no route to {:?}", &dst[..4]),
    }
}

/// One unit of deferred crypto work: encrypt `payload` for `dst` and
/// route it. Built by [`PacketConn::write_to`] when the worker pool is
/// enabled, drained by a [`crypto_worker`].
struct CryptoJob {
    payload: Vec<u8>,
    dst: [u8; 32],
}

/// Roadmap #2: a fixed pool of crypto worker tasks that lift the
/// pad + ChaCha20-Poly1305 encrypt + envelope + dispatch off the
/// caller's task. On a multi-thread tokio runtime the workers land on
/// separate OS threads, so the AEAD runs on several cores in parallel.
///
/// Each worker owns one mpsc queue; `write_to` hashes the destination
/// key to a worker, so every packet for a given peer lands on the *same*
/// worker. Two consequences fall out of that for free: per-peer wire
/// order is preserved (one FIFO queue), and a peer's session mutex is
/// never contended across workers.
///
/// Opt-in via `NodeConfig.crypto_workers`. On a single-core box, or a
/// WAN-bottlenecked link where ChaCha20 is a fraction of a percent of
/// one core, leave it disabled — the queueing hop is pure overhead
/// there. It earns its keep on fast (≥ ~500 Mbit/s) links where crypto
/// is a real share of a core.
struct CryptoPool {
    senders: Vec<mpsc::Sender<CryptoJob>>,
}

impl CryptoPool {
    /// Try to enqueue `payload` for `dst` on its worker. Returns `false`
    /// if the chosen worker's queue is full or closed — the caller then
    /// encrypts inline rather than dropping the packet, so the pool is a
    /// pure offload optimisation and never costs delivery.
    fn try_submit(&self, payload: &[u8], dst: &[u8; 32]) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        // First 8 bytes of the (uniformly random) ed25519 key make a
        // fine hash; modulo maps it to a stable worker index.
        let idx = (u64::from_le_bytes(dst[..8].try_into().unwrap())
            % self.senders.len() as u64) as usize;
        self.senders[idx]
            .try_send(CryptoJob { payload: payload.to_vec(), dst: *dst })
            .is_ok()
    }
}

/// Body of one crypto worker: drain `CryptoJob`s, encrypt+dispatch each,
/// exit when the queue closes or the node shuts down.
async fn crypto_worker(
    mut rx: mpsc::Receiver<CryptoJob>,
    inner: Arc<Mutex<RouterState>>,
    pub_key: [u8; 32],
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            job = rx.recv() => {
                let Some(job) = job else { break };
                if let Err(e) =
                    encrypt_and_dispatch(&inner, &pub_key, &job.payload, &job.dst)
                {
                    debug!("crypto worker: dropping packet for {:?}: {e}", &job.dst[..4]);
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

pub struct PacketConn {
    inner: Arc<Mutex<RouterState>>,
    traffic_rx: tokio::sync::Mutex<mpsc::Receiver<InboundPacket>>,
    pub pub_key: [u8; 32],
    /// Clone of the signing key — needed by the transport layer to sign the
    /// per-connection authenticated handshake. Stored here so that transports
    /// don't need to be parameterised with the key separately.
    signing_key: SigningKey,
    /// Sybil-resistance threshold: an inbound peer's pub_key MUST have at
    /// least this many leading 1-bits in BLAKE2b(pub_key) (cf.
    /// `address::key_difficulty_bits`). 0 = no requirement. Stored as
    /// AtomicU32 so it can be raised at runtime without locking.
    min_peer_difficulty_bits: Arc<std::sync::atomic::AtomicU32>,
    shutdown_tx: watch::Sender<bool>,
    /// Roadmap #2: optional multi-core crypto worker pool. `None` until
    /// `enable_crypto_pool` installs one; once set, `write_to` offloads
    /// the encrypt+dispatch half onto it. `OnceLock` so the hot path
    /// reads it lock-free.
    crypto_pool: std::sync::OnceLock<CryptoPool>,
    /// Roadmap #7: optional transport-obfuscation key, derived from the
    /// configured PSK. `None` (unset) = obfuscation off. The transport
    /// layer reads it via `obfuscation_key()` to decide whether to wrap
    /// each TCP link in the keystream obfuscator.
    obfs_key: std::sync::OnceLock<[u8; 32]>,
}

impl PacketConn {
    /// Borrow the signing key (used by the transport layer for handshake signing).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Current Sybil-resistance threshold in bits.
    pub fn min_peer_difficulty_bits(&self) -> u32 {
        self.min_peer_difficulty_bits.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Set the Sybil-resistance threshold. Inbound peers with fewer
    /// `key_difficulty_bits` are refused at the transport layer.
    pub fn set_min_peer_difficulty_bits(&self, bits: u32) {
        self.min_peer_difficulty_bits.store(bits, std::sync::atomic::Ordering::Relaxed);
    }

    /// Roadmap #7: install the transport-obfuscation PSK. An empty
    /// string leaves obfuscation off (the default). Idempotent and
    /// one-shot — call once at node startup, before transports spawn.
    pub fn set_obfuscation_psk(&self, psk: &str) {
        if let Some(key) = crate::obfs::derive_psk_key(psk) {
            let _ = self.obfs_key.set(key);
            tracing::info!("transport obfuscation enabled (roadmap #7)");
        }
    }

    /// Select which onion format `write_to_onion` builds (see
    /// [`crate::config::OnionFormat`]). Call once at node startup from config.
    #[cfg(feature = "sphinx")]
    pub fn set_onion_format(&self, fmt: crate::config::OnionFormat) {
        self.inner.lock_or_recover().onion_format = fmt;
    }

    /// Roadmap #7: the derived obfuscation key, or `None` when
    /// obfuscation is off. Read by the TCP transport per connection.
    pub fn obfuscation_key(&self) -> Option<[u8; 32]> {
        self.obfs_key.get().copied()
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
            min_peer_difficulty_bits: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            shutdown_tx,
            crypto_pool: std::sync::OnceLock::new(),
            obfs_key: std::sync::OnceLock::new(),
        }
    }

    /// Roadmap #2: spin up a pool of `workers` crypto worker tasks.
    /// Once installed, [`write_to`](Self::write_to) offloads the
    /// pad + encrypt + envelope + dispatch half of each send onto a
    /// worker (chosen by hashing the destination key), so the AEAD runs
    /// off the caller's task and across cores.
    ///
    /// Idempotent and one-shot: the first call with `workers > 0`
    /// installs the pool; `workers == 0` and any later call are no-ops.
    /// Call once at node startup, before traffic flows. A good value is
    /// the physical core count; see `NodeConfig.crypto_workers`.
    pub fn enable_crypto_pool(&self, workers: usize) {
        if workers == 0 || self.crypto_pool.get().is_some() {
            return;
        }
        let mut senders = Vec::with_capacity(workers);
        for _ in 0..workers {
            // Queue depth mirrors the per-peer write channel (8192):
            // deep enough to ride out a burst, bounded so a flooder
            // can't grow it without limit. Overflow falls back to
            // inline encryption — see CryptoPool::try_submit.
            let (tx, rx) = mpsc::channel::<CryptoJob>(8192);
            senders.push(tx);
            tokio::spawn(crypto_worker(
                rx,
                self.inner.clone(),
                self.pub_key,
                self.shutdown_tx.subscribe(),
            ));
        }
        let _ = self.crypto_pool.set(CryptoPool { senders });
        tracing::info!("crypto worker pool enabled: {workers} worker(s)");
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
        // Per-peer write channel. 256 was too small under sustained
        // load: a SOCKS5 download with N pipelined Data frames would
        // saturate the channel, `try_send` would silently drop frames,
        // our ARQ would retransmit, and TCP's CUBIC would interpret
        // the apparent burstiness as packet loss and halve cwnd —
        // collapsing single-stream throughput to ~37 Mbit/s on
        // long-fat WAN even after the bifrost-side reliability window
        // had been bumped to 4 MB. Sizing at 8192 lets ~512 MB of
        // pipelined Traffic frames queue before backpressure kicks in
        // (typical encrypted Traffic ≤ 64 KB).
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8192);

        // Register peer (guarded against duplicates inside add_peer)
        self.inner.lock_or_recover().add_peer(remote_pub_key, tx, priority);

        let state = self.inner.clone();

        // Writer task — runs independently; terminates when channel closes or IO fails.
        //
        // sendmmsg-style coalescing: after the first frame arrives via
        // `recv().await`, drain any siblings that are already enqueued
        // with `try_recv()` and ship the whole batch with one
        // `write_frames_batched` call (= one `write_all`, = one
        // syscall). Bounds the batch at MAX_WRITE_BATCH so a flood
        // of telemetry doesn't grow our coalesce buffer without a
        // ceiling, and so the writer still yields back to tokio at
        // a sane cadence under heavy fan-in.
        const MAX_WRITE_BATCH: usize = 32;
        tokio::spawn(async move {
            let mut writer = writer;
            let mut batch: Vec<Vec<u8>> = Vec::with_capacity(MAX_WRITE_BATCH);
            while let Some(first) = rx.recv().await {
                batch.clear();
                batch.push(first);
                while batch.len() < MAX_WRITE_BATCH {
                    match rx.try_recv() {
                        Ok(more) => batch.push(more),
                        Err(_) => break, // empty or closed — flush what we have
                    }
                }
                if crate::packet::write_frames_batched(&mut writer, &batch).await.is_err() {
                    break;
                }
                // Flush so a buffered writer (the roadmap #7 obfuscation
                // layer) never strands a batch's tail when the peer goes
                // idle. A no-op for the bare TCP write half.
                if writer.flush().await.is_err() {
                    break;
                }
            }
        });

        // Initiate session exchange before entering the read loop.
        let init_bytes = {
            let s = state.lock_or_recover();
            s.sessions.write_or_recover().get_or_initiate_bytes(&remote_pub_key)
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
                let sm = state.sessions.read_or_recover();
                sm.is_established(dst)
            };
            if !established {
                let init_data = {
                    let state = self.inner.lock_or_recover();
                    let mut sm = state.sessions.write_or_recover();
                    sm.get_or_initiate_bytes(dst).unwrap_or_default()
                };
                if !init_data.is_empty() {
                    self.inner.lock_or_recover().send_traffic_to(dst, init_data);
                }
                bail!("session not established with {:?}", &dst[..4]);
            }
        }

        // Roadmap #2: with a crypto worker pool installed, hand the
        // expensive half (pad + ChaCha20-Poly1305 + envelope + route +
        // dispatch) to a worker so it runs on another core while this
        // task returns. `dst` is hashed to a fixed worker, so packets
        // for one peer keep submission order and never contend on that
        // peer's session mutex. A saturated pool falls through to
        // inline encryption below — never a drop.
        if let Some(pool) = self.crypto_pool.get()
            && pool.try_submit(payload, dst)
        {
            return Ok(());
        }
        encrypt_and_dispatch(&self.inner, &self.pub_key, payload, dst)
    }

    /// Batched analogue of `write_to`: encrypt + envelope + dispatch N
    /// payloads to the same destination under one round of session-
    /// manager mutex acquisitions.
    ///
    /// Why it exists: every `write_to` takes `state.sessions.lock`
    /// once for the encrypt and `state.inner.lock` twice for the
    /// route lookup + send_to_peer. For a 16-packet coalesced batch
    /// from `bifrost-vpnd::egress`, doing 16 independent `write_to`
    /// calls means 16 × 3 mutex acquires under load. Folding them
    /// into one call amortises the lock cost — important when the
    /// session manager's internal lock contention is on the perf-
    /// hot path (it's behind ChaCha20-Poly1305 today, but the perf
    /// trace flagged it as the next layer to surface once crypto
    /// stops being the dominant user-mode cost).
    ///
    /// Behaviour notes:
    /// * Returns `Ok(0)` if `payloads` is empty.
    /// * If the session isn't established, queues a SessionInit and
    ///   bails with the same error as `write_to`. None of the
    ///   payloads are sent.
    /// * If route lookup fails *after* encryption, bails — the
    ///   encrypted payloads are discarded (next call will retry).
    /// * Order is preserved: the writer task's
    ///   `write_frames_batched` keeps them in submission order on
    ///   the wire.
    ///
    /// Returns the number of payloads actually queued for the peer.
    #[mutants::skip]
    pub async fn write_to_batch(
        &self, payloads: &[Vec<u8>], dst: &[u8; 32],
    ) -> Result<usize> {
        if payloads.is_empty() {
            return Ok(0);
        }
        // Session establishment check — same shape as write_to.
        let established = {
            let state = self.inner.lock_or_recover();
            let sm = state.sessions.read_or_recover();
            sm.is_established(dst)
        };
        if !established {
            let init_data = {
                let state = self.inner.lock_or_recover();
                let mut sm = state.sessions.write_or_recover();
                sm.get_or_initiate_bytes(dst).unwrap_or_default()
            };
            if !init_data.is_empty() {
                self.inner.lock_or_recover().send_traffic_to(dst, init_data);
            }
            bail!("session not established with {:?}", &dst[..4]);
        }

        // Per-peer session lock: clone the SessionHandle once,
        // drop the SessionManager read lock, then encrypt all
        // payloads under one acquire of the per-peer mutex. Other
        // peers' encrypt/decrypt paths stay unblocked (Roadmap #2).
        let pub_key = self.pub_key;
        let (enc_header, tag) = encrypt_header(&pub_key, dst);
        let handle = {
            let state = self.inner.lock_or_recover();
            let sm = state.sessions.read_or_recover();
            sm.get_session(dst)
        };
        let Some(handle) = handle else {
            bail!("session not established with {:?}", &dst[..4]);
        };
        let encoded_frames: Vec<Vec<u8>> = {
            let mut info = handle.lock().unwrap();
            let mut out = Vec::with_capacity(payloads.len());
            for p in payloads {
                let padded = pad_payload(p);
                let ciphertext = info.encrypt(&padded)?;
                let traffic = Traffic {
                    path: vec![],
                    from: pub_key,
                    enc_header,
                    routing_tag: tag,
                    pkt_type: packet::PKT_DATA,
                    watermark: 0,
                    payload: ciphertext,
                };
                out.push(traffic.encode());
            }
            out
        };

        // Route lookup once.
        let next_hop = self.inner.lock_or_recover().lookup(dst);
        let Some(next_hop) = next_hop else {
            bail!("no route to {:?}", &dst[..4]);
        };

        // Dispatch each encoded frame. send_to_peer round-robins
        // across the peer's multi-link tx vec, so consecutive frames
        // in this batch get spread across N TCP links naturally.
        let mut sent = 0usize;
        {
            let mut state = self.inner.lock_or_recover();
            for f in encoded_frames {
                state.send_to_peer(&next_hop, f);
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Select up to `n` random peers to use as onion relays.
    /// Returns fewer than `n` relays if insufficient peers are connected
    /// **with a known onion ephemeral pub** (learned via CoordAnnounce). Peers
    /// without one are skipped — we cannot give forward secrecy if we'd have
    /// to fall back to identity-derived keys.
    #[mutants::skip]
    pub fn select_relays(&self, n: usize) -> Vec<crate::onion::OnionHop> {
        use rand::seq::SliceRandom;
        let mut hops: Vec<crate::onion::OnionHop> = self.inner.lock_or_recover()
            .peers
            .values()
            .filter_map(|p| {
                p.onion_eph_pub.map(|eph| crate::onion::OnionHop {
                    identity_ed_pub: p.pub_key,
                    ephemeral_x_pub: eph,
                })
            })
            .collect();
        hops.shuffle(&mut rand::rngs::OsRng);
        hops.truncate(n);
        hops
    }

    /// Look up an OnionHop for the given identity.
    ///
    /// Returns `Some` with the peer's *current* announced ephemeral pub when
    /// known (full forward secrecy). When unknown — e.g. the identity is not
    /// a direct peer and we've never heard a CoordAnnounce from them — falls
    /// back to deriving an X25519 pub from the identity's Ed25519 key. The
    /// fallback works (Ed25519/X25519 share a curve so the derivation is
    /// well-defined) but provides NO forward secrecy for that hop: a future
    /// identity compromise lets the attacker decrypt past onion layers built
    /// against the derived key.
    ///
    /// A `warn!` is logged on fallback so operators can see which dests need
    /// out-of-band ephemeral-key propagation (a future PROTOCOL.md extension).
    pub fn onion_hop_for(&self, identity: &[u8; 32]) -> Option<crate::onion::OnionHop> {
        let state = self.inner.lock_or_recover();
        // Self-destination: use our own current onion pub.
        if identity == &state.pub_key {
            return Some(crate::onion::OnionHop {
                identity_ed_pub: *identity,
                ephemeral_x_pub: *state.onion_keys.pub_key().as_bytes(),
            });
        }
        // Direct peer with a known ephemeral (fast path, populated by either
        // CoordAnnounce or OnionKeyAnnounce).
        if let Some(p) = state.peers.get(identity)
            && let Some(eph) = p.onion_eph_pub {
            return Some(crate::onion::OnionHop {
                identity_ed_pub: *identity,
                ephemeral_x_pub: eph,
            });
        }
        // Network-wide table: OnionKeyAnnounce from anywhere in the mesh.
        if let Some((_, eph, _)) = state.remote_onion_keys.get(identity) {
            return Some(crate::onion::OnionHop {
                identity_ed_pub: *identity,
                ephemeral_x_pub: *eph,
            });
        }
        // Fallback: derive X25519 from the Ed25519 identity. Provides
        // confidentiality but not forward secrecy for this hop.
        match crate::session::ed25519_pub_to_x25519(identity) {
            Ok(x) => {
                warn!(
                    "onion hop {:?}: no advertised ephemeral pub, falling back to identity-derived key (no FS for this hop)",
                    &identity[..4]
                );
                Some(crate::onion::OnionHop {
                    identity_ed_pub: *identity,
                    ephemeral_x_pub: *x.as_bytes(),
                })
            }
            Err(_) => None,
        }
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
        relays: &[crate::onion::OnionHop],
    ) -> Result<()> {
        if relays.is_empty() {
            return self.write_to(payload, dst).await;
        }

        // Onion format selection (OnionFormat). Sphinx removes the legacy
        // per-layer length leak; build it when forced, or under Auto when every
        // hop advertises support. Otherwise fall through to the legacy builder
        // below (also the Auto fallback for not-yet-capable paths).
        #[cfg(feature = "sphinx")]
        let use_sphinx = {
            let st = self.inner.lock_or_recover();
            match st.onion_format {
                crate::config::OnionFormat::Legacy => false,
                crate::config::OnionFormat::Sphinx => true,
                crate::config::OnionFormat::Auto => st.path_supports_sphinx(relays, dst),
            }
        };
        #[cfg(feature = "sphinx")]
        if use_sphinx {
            return self.write_to_onion_sphinx(payload, dst, relays).await;
        }

        // We need the destination's *current* onion ephemeral pub to build the
        // innermost layer. If we don't have one yet, abort — caller should
        // wait for a CoordAnnounce from the destination (or use write_to
        // which doesn't require it).
        let dest_hop = self.onion_hop_for(dst)
            .ok_or_else(|| anyhow::anyhow!(
                "no onion ephemeral pub known for dst {:?}; wait for CoordAnnounce or use write_to",
                &dst[..4]
            ))?;

        // Check session
        {
            let established = {
                let state = self.inner.lock_or_recover();
                state.sessions.read_or_recover().is_established(dst)
            };
            if !established {
                let init_data = {
                    let state = self.inner.lock_or_recover();
                    let mut sm = state.sessions.write_or_recover();
                    sm.get_or_initiate_bytes(dst).unwrap_or_default()
                };
                if !init_data.is_empty() {
                    self.inner.lock_or_recover().send_traffic_to(dst, init_data);
                }
                bail!("session not established with {:?}", &dst[..4]);
            }
        }

        let padded = pad_payload(payload);
        // `encrypt` is `&self` on SessionManager (it goes through the
        // per-peer Mutex<SessionInfo> internally), so a read guard is
        // sufficient — multiple concurrent encrypts to different
        // peers share this lock.
        let ciphertext = {
            let state = self.inner.lock_or_recover();
            state.sessions.read_or_recover().encrypt(dst, &padded)?
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
        let traffic_bytes = traffic.encode();

        let onion_pkt = match build_onion(relays, &dest_hop, traffic_bytes) {
            Ok(p) => p,
            Err(e) => bail!("failed to build onion: {}", e),
        };
        let encoded = onion_pkt.encode();

        let first_relay = relays[0].identity_ed_pub;
        let next_hop = self.inner.lock_or_recover().lookup(&first_relay);
        if let Some(next) = next_hop {
            self.inner.lock_or_recover().send_to_peer(&next, encoded);
        } else {
            bail!("no route to first relay {:?}", &first_relay[..4]);
        }
        Ok(())
    }

    /// Like [`Self::write_to_onion`] but builds a fixed-size Sphinx-style cell
    /// (`crate::sphinx`) — no per-layer cleartext length, so no onion-depth leak
    /// (REVIEW-FINDINGS #3). Additive and opt-in: every hop on the path (relays
    /// and `dst`) must understand `TYPE_ONION_SPHINX`, so callers must negotiate
    /// support before using this (a capability bit in CoordAnnounce is the planned
    /// signal). `relays.len() + 1` must be ≤ `sphinx::MAX_HOPS`, and the
    /// session-encrypted Traffic must fit `sphinx::MAX_TRAFFIC_LEN`.
    ///
    /// The session-setup + Traffic-build prefix mirrors `write_to_onion`
    /// deliberately (kept separate so the proven legacy path is untouched).
    #[mutants::skip]
    #[cfg(feature = "sphinx")]
    pub async fn write_to_onion_sphinx(
        &self,
        payload: &[u8],
        dst: &[u8; 32],
        relays: &[crate::onion::OnionHop],
    ) -> Result<()> {
        if relays.is_empty() {
            return self.write_to(payload, dst).await;
        }
        if relays.len() + 1 > crate::sphinx::MAX_HOPS {
            bail!(
                "sphinx onion: {} relays + dst exceeds MAX_HOPS {}",
                relays.len(), crate::sphinx::MAX_HOPS
            );
        }
        let dest_hop = self.onion_hop_for(dst).ok_or_else(|| {
            anyhow::anyhow!(
                "no onion ephemeral pub known for dst {:?}; wait for CoordAnnounce or use write_to",
                &dst[..4]
            )
        })?;

        // Session must be established (else kick off the handshake and bail).
        {
            let established = {
                let state = self.inner.lock_or_recover();
                state.sessions.read_or_recover().is_established(dst)
            };
            if !established {
                let init_data = {
                    let state = self.inner.lock_or_recover();
                    let mut sm = state.sessions.write_or_recover();
                    sm.get_or_initiate_bytes(dst).unwrap_or_default()
                };
                if !init_data.is_empty() {
                    self.inner.lock_or_recover().send_traffic_to(dst, init_data);
                }
                bail!("session not established with {:?}", &dst[..4]);
            }
        }

        let padded = pad_payload(payload);
        let ciphertext = {
            let state = self.inner.lock_or_recover();
            state.sessions.read_or_recover().encrypt(dst, &padded)?
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
        let traffic_bytes = traffic.encode();
        if traffic_bytes.len() > crate::sphinx::MAX_TRAFFIC_LEN {
            bail!(
                "sphinx onion: Traffic {} B exceeds payload budget {} B (use fewer hops or smaller payload)",
                traffic_bytes.len(), crate::sphinx::MAX_TRAFFIC_LEN
            );
        }

        // Map (relays.., dst) → Sphinx hops. Each hop's tag is BLAKE2b of its
        // identity; its onion_pub is the advertised ephemeral (FS) or the
        // identity-derived fallback (see onion_hop_for).
        let mut hops: Vec<crate::sphinx::SphinxHop> = relays
            .iter()
            .map(|h| crate::sphinx::SphinxHop {
                routing_tag: routing_tag(&h.identity_ed_pub),
                onion_pub: h.ephemeral_x_pub,
            })
            .collect();
        hops.push(crate::sphinx::SphinxHop {
            routing_tag: routing_tag(&dest_hop.identity_ed_pub),
            onion_pub: dest_hop.ephemeral_x_pub,
        });

        let cell = crate::sphinx::build_sphinx(&hops, &traffic_bytes)
            .map_err(|e| anyhow::anyhow!("build sphinx cell: {e}"))?;

        let first_relay = relays[0].identity_ed_pub;
        let next_hop = self.inner.lock_or_recover().lookup(&first_relay);
        if let Some(next) = next_hop {
            self.inner.lock_or_recover().send_to_peer(&next, cell);
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

    /// Inject ground-truth link statistics measured by the transport layer
    /// (e.g. Linux `SO_TCP_INFO`, or quinn's connection.rtt() / lost_packets).
    /// `rtt` overrides the EWMA `lag`; `loss_rate` is blended into the
    /// running EWMA. Both are far more accurate than the application-layer
    /// `SIG_REQ`/`SIG_RES` probe because they're not contaminated by
    /// head-of-line blocking or by ACK coalescing.
    ///
    /// Safe to call from any thread. No-op if `peer` is not currently in our
    /// peer table (concurrent disconnect race).
    pub fn record_kernel_link_stats(
        &self,
        peer: &[u8; 32],
        rtt: std::time::Duration,
        loss_rate: f32,
    ) {
        let mut state = self.inner.lock_or_recover();
        if let Some(p) = state.peers.get_mut(peer) {
            // Direct replace — kernel telemetry is authoritative for this
            // sample; the EWMA is only there to smooth one-shot jitter.
            p.lag = rtt;
            // Blend loss_rate with existing EWMA at α=0.25 to avoid a single
            // burst spiking the cost — same smoothing as the SIG_RES path.
            let clamped = loss_rate.clamp(0.0, 1.0);
            p.loss_rate = p.loss_rate * 0.75 + clamped * 0.25;
        }
    }

    /// Snapshot the per-tree state for all K spanning trees. Exposed via
    /// `/metrics` so a cluster-wide scraper can reconstruct the global
    /// shape of every tree (root, parent edges, depths) — basically
    /// "what would a graph viewer plot if it asked every node".
    ///
    /// `depth` is only tracked for tree 0 (`own_depth`); the other trees
    /// return 0 there. That's a known shortcoming of the current
    /// implementation, not a metric exposure issue.
    pub fn get_tree_state(&self) -> Vec<TreeStat> {
        let state = self.inner.lock_or_recover();
        let mut out = Vec::with_capacity(K);
        for (tree_id, tree) in state.trees.iter().enumerate() {
            let is_root = tree.parent.is_none();
            out.push(TreeStat {
                tree_id: tree_id as u8,
                root: tree.root,
                parent: tree.parent,
                depth: if tree_id == 0 { state.own_depth } else { 0 },
                parent_cost: tree.parent_cost,
                is_root,
            });
        }
        out
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
            trust: p.trust,
        }).collect()
    }

    // Skip mutations: stores closure in mutex — verifying the callback fires requires
    // a live handle_path_notify invocation from a peer.
    #[mutants::skip]
    pub async fn set_path_notify<F: Fn([u8; 32]) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock_or_recover().path_notify = Some(Arc::new(f));
    }

    /// Install a callback fired when a HolePunch frame is received with us
    /// as the target. The transport layer wires this to issue a
    /// simultaneous outbound QUIC connect for symmetric-NAT traversal.
    #[mutants::skip]
    pub fn set_on_hole_punch<F: Fn([u8; 32], String) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock_or_recover().hole_punch_cb = Some(Arc::new(f));
    }

    /// Send a signed HolePunch frame to one of our peers, asking them to
    /// relay our endpoint to `target`. `endpoint` is the address we'd like
    /// `target` to dial back (usually our observed public IP:port from a
    /// STUN-like query or operator knowledge).
    #[mutants::skip]
    pub fn send_hole_punch(&self, rendezvous: &[u8; 32], target: [u8; 32], endpoint: String) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64).unwrap_or(0);
        let initiator = self.pub_key;
        let unsigned = HolePunch {
            initiator, target, valid_from_ms: now_ms, endpoint,
            sig: [0u8; 64],
        };
        let sig = self.signing_key.sign(&unsigned.sign_bytes()).to_bytes();
        let hp = HolePunch { sig, ..unsigned };
        let encoded = hp.encode();
        self.inner.lock_or_recover().send_to_peer(rendezvous, encoded);
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
mod tests;
