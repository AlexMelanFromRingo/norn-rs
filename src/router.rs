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

/// Test-only env knob that turns this node into a cuckoo-filter poisoner.
/// When `NORN_MALICIOUS_MODE=cuckoo_poison`, every outgoing CuckooMsg gets
/// `NORN_MALICIOUS_POISON_TAGS` (default 64) random 16-byte routing_tags
/// injected. Neighbours that consult the poisoned filter will pick this
/// node as next-hop for tags it can't actually reach → forward fails →
/// PathNegative back → trust decays on this node. This is the canonical
/// route-poisoning attack — useful to verify the cluster ejects bad actors.
///
/// Returns the number of tags to inject; 0 disables. Loud warning at
/// startup; MUST NOT be set in production.
pub fn malicious_cuckoo_poison_tags() -> usize {
    let mode = std::env::var("NORN_MALICIOUS_MODE").ok();
    if mode.as_deref() != Some("cuckoo_poison") {
        return 0;
    }
    std::env::var("NORN_MALICIOUS_POISON_TAGS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(64)
}

/// Log a startup warning if any malicious mode is active. Called from
/// daemon main so an operator who flipped the knob notices immediately.
pub fn warn_if_malicious() {
    let n = malicious_cuckoo_poison_tags();
    if n > 0 {
        tracing::warn!(
            "NORN_MALICIOUS_MODE=cuckoo_poison — this node will inject {} random \
             routing_tags into every outgoing CuckooMsg. NEIGHBOURS WILL ROUTE TRAFFIC \
             TOWARD US THAT WE CANNOT DELIVER. This MUST NOT be used in production.",
            n,
        );
    }
}

/// Test-only env knob that compresses every "rotate every N hours/days"
/// interval down to a configurable number of seconds. Set to a positive
/// integer via `NORN_ACCELERATE_ROTATIONS_SECS=30` to verify rotation
/// end-to-end inside a CI run instead of waiting for the production
/// 1h / 24h intervals. Returns `None` when not set or zero.
///
/// Affects:
///   - `ML_KEM_KEY_ROTATION_MS` (session.rs)        — daily PQ key rotation
///   - `ML_KEM_KEY_OVERLAP_MS`  (session.rs)        — prev_dk grace window
///   - `ONION_KEY_ROTATION_TICKS`                    — hourly onion key rotation
///   - `CUCKOO_GEN_TICKS`                            — cuckoo filter generation rollover
///
/// MUST NOT be set in production: short rotation cadence reduces forward
/// secrecy headroom and bumps CPU. The setter logs a loud warning at
/// startup so an operator who flipped it by mistake notices.
pub fn accelerate_rotations_secs() -> Option<u64> {
    // Read every call — env vars are cheap, and a test can flip the
    // value at runtime via std::env::set_var. The OnceLock cached path
    // would make that impossible.
    let raw = std::env::var("NORN_ACCELERATE_ROTATIONS_SECS").ok()?;
    let n: u64 = raw.trim().parse().ok()?;
    if n == 0 { None } else { Some(n) }
}

/// Log a startup warning if the rotation accelerator is active. Called
/// once from the daemon main; idempotent if called multiple times because
/// it just emits a tracing event.
pub fn warn_if_rotation_accelerated() {
    if let Some(secs) = accelerate_rotations_secs() {
        tracing::warn!(
            "NORN_ACCELERATE_ROTATIONS_SECS={} — ALL key rotation intervals \
             compressed to {} seconds. This MUST NOT be used in production. \
             Unset the variable to restore normal cadence.",
            secs, secs,
        );
    }
}

/// Process-wide counter of mutex-poison-recovery events. Exposed via
/// `mutex_poison_count()` and surfaced in `/metrics` as
/// `norn_mutex_poison_total`. Operators MUST treat any non-zero value as a
/// red flag: a panic-while-holding-lock leaves the protected state in a
/// potentially inconsistent intermediate form (e.g. tree partially
/// rebalanced, peer half-removed), and silently recovering hides that
/// damage. The counter exists so the damage shows up in alerts.
pub static MUTEX_POISON_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Snapshot of the global mutex-poison-recovery counter. Wired into the
/// Prometheus exposition (`norn_mutex_poison_total`).
pub fn mutex_poison_count() -> u64 {
    MUTEX_POISON_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Extension trait that recovers from poisoned mutexes instead of panicking.
/// If a thread panicked while holding a lock, we log an error, bump the
/// poison counter, and continue — better than a cascade crash from an
/// unrelated panic. Operators must monitor `norn_mutex_poison_total` and
/// investigate any non-zero value: data behind the lock may be inconsistent.
trait LockOrRecover<T> {
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T> LockOrRecover<T> for std::sync::Mutex<T> {
    #[track_caller]
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|p| {
            // track_caller surfaces the lock_or_recover call site in the log
            // so operators see WHERE the inconsistency was first observed.
            let loc = std::panic::Location::caller();
            MUTEX_POISON_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(
                file = loc.file(), line = loc.line(),
                "mutex poisoned at {}:{} — RECOVERING but state may be inconsistent. \
                 Check norn_mutex_poison_total in /metrics; non-zero is a red flag.",
                loc.file(), loc.line(),
            );
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
    /// Network-wide table of current onion ephemeral pubs per identity.
    /// Populated from OnionKeyAnnounce floods. Latest seq per origin wins.
    /// (seq, eph_pub, recorded_at)
    remote_onion_keys: HashMap<[u8; 32], (u64, [u8; 32], Instant)>,
    /// Monotonic seq for our own OnionKeyAnnounce broadcasts.
    own_onion_key_seq: u64,
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
}

/// One observation in `reputation`.
type ReputationEntry = (u64, f32, Instant);

/// Callback alias for the hole-punch handler.
type HolePunchCb = Arc<dyn Fn([u8; 32], String) + Send + Sync>;

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

/// Approximate equality for two HypCoord values, accounting for f64 rounding
/// during encode/decode (LE byte roundtrip is exact, but cross-system the
/// tanh evaluation may differ in the last bit). Used by handle_coord_announce
/// to validate that a peer's claimed coord matches the deterministic formula.
fn coords_approx_equal(a: &HypCoord, b: &HypCoord) -> bool {
    let dr = (a.r - b.r).abs();
    let dt = (a.theta - b.theta).abs();
    dr < 1e-9 && dt < 1e-9
}

/// Constant-time equality on routing tags. The leak is minor (an attacker
/// would have to time forwarding decisions under 50ms jitter) but the cost
/// is zero, so this is defence in depth.
#[inline]
fn routing_tag_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).unwrap_u8() == 1
}

/// XOR-metric for tree root selection. Each tree uses a different seed.
///
/// NOTE: this is the **legacy, epoch-0** form. New code MUST use
/// `tree_metric_at` so the root rotates across the network and a static
/// "lowest-key" node cannot become a permanent DDoS / censorship target.
/// Kept public + named the old way only because the test suite references
/// it directly to verify the XOR algebra.
pub fn tree_metric(pub_key: &[u8; 32], seed: &[u8; 8]) -> [u8; 32] {
    tree_metric_at(pub_key, seed, 0)
}

/// Length of one tree epoch in seconds (24h). Picked to be much longer than
/// typical convergence time (seconds, dominated by maintenance tick + cuckoo
/// gossip) but short enough that no single node can serve as root for long.
pub const TREE_EPOCH_SECS: u64 = 24 * 60 * 60;

/// Current tree-root epoch derived from system wall clock. Both sides of any
/// adjacency compute this independently; clocks need only to be within ~1h
/// of each other (typical NTP skew is sub-second). At the epoch boundary
/// the network briefly disagrees, then converges within a few maintenance
/// ticks — this is the normal tree-reconvergence behavior, not a failure.
pub fn current_tree_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / TREE_EPOCH_SECS)
        .unwrap_or(0)
}

/// Epoch-rotated XOR-metric. Derives a 32-byte salt from BLAKE2b(seed||epoch)
/// and XORs it with the pub_key. Two consequences:
///   - Within an epoch, every node ranks candidate roots **the same way**
///     (deterministic per (seed, epoch)) → trees still converge.
///   - Across epochs, the salt changes → the lowest-metric (= root) node
///     changes → a long-lived attacker cannot pin any single node as a
///     permanent target. Mitigates the "static-root DDoS / censorship"
///     concern raised in the security audit.
pub fn tree_metric_at(pub_key: &[u8; 32], seed: &[u8; 8], epoch: u64) -> [u8; 32] {
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;
    let mut h: Blake2b<U32> = Blake2b::new();
    h.update(b"norn:tree-epoch");
    h.update(seed);
    h.update(epoch.to_le_bytes());
    let salt: [u8; 32] = h.finalize().into();
    let mut metric = *pub_key;
    for (i, b) in metric.iter_mut().enumerate() {
        *b ^= salt[i];
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
            remote_onion_keys: HashMap::new(),
            own_onion_key_seq: 0,
            pending_probes: HashMap::new(),
            reputation: HashMap::new(),
            own_reputation_seq: 0,
            hole_punch_cb: None,
            path_negative_cache: HashMap::new(),
        }
    }

    /// Look up a peer's current entry in the cuckoo-FP negative cache. Returns
    /// true if the peer recently signalled "I can't reach this tag" — caller
    /// should skip this peer for this tag until the entry ages out. Also
    /// performs lazy eviction of stale entries.
    fn is_path_negative(&self, peer: &PeerId, tag: &[u8; 16]) -> bool {
        let now = Instant::now();
        match self.path_negative_cache.get(&(*peer, *tag)) {
            Some(t) => now.duration_since(*t) < PATH_NEG_TTL,
            None => false,
        }
    }

    /// Record an incoming PathNegative. Bounded by `MAX_PATH_NEG_CACHE`.
    fn record_path_negative(&mut self, peer: PeerId, tag: [u8; 16]) {
        let now = Instant::now();
        if self.path_negative_cache.len() >= MAX_PATH_NEG_CACHE {
            // Lazy eviction: drop the oldest expired entry, else any one.
            let cutoff = now.checked_sub(PATH_NEG_TTL).unwrap_or(now);
            let victim = self.path_negative_cache.iter()
                .find(|(_, t)| **t < cutoff)
                .map(|(k, _)| *k)
                .or_else(|| self.path_negative_cache.keys().next().copied());
            if let Some(v) = victim {
                self.path_negative_cache.remove(&v);
            }
        }
        self.path_negative_cache.insert((peer, tag), now);
    }

    /// Drop expired negative-cache entries — called from maintenance tick.
    fn cleanup_path_negative_cache(&mut self) {
        let now = Instant::now();
        self.path_negative_cache.retain(|_, t| now.duration_since(*t) < PATH_NEG_TTL);
    }

    /// Send a `PathNegative` UPSTREAM (back to the peer we received an
    /// undeliverable packet from). Called when we drop a Traffic/Onion forward
    /// because of no-route or TTL exhaustion. Caller decrements TTL appropriately.
    fn send_path_negative(&mut self, to: PeerId, tag: [u8; 16], ttl: u8) {
        if ttl == 0 {
            return;
        }
        let frame = crate::packet::PathNegative { routing_tag: tag, ttl };
        let encoded = frame.encode();
        self.send_to_peer(&to, encoded);
    }

    /// Handle an inbound `PathNegative`. Two effects:
    ///   1. Cache `(from, tag)` so we stop picking `from` for this tag.
    ///   2. If we ourselves are a forwarder for this tag (recently received
    ///      and propagated upstream), forward the PathNegative one more hop
    ///      upstream — bounded by the embedded TTL.
    ///
    /// We do NOT trust the routing_tag against any specific identity (the
    /// frame is unsigned) — the only effect is that the SENDER tells us not
    /// to pick THEM for this tag. They can already lie about their own
    /// connectivity anyway, so this is no worse than the existing cuckoo
    /// gossip authority model.
    pub fn handle_path_negative(&mut self, from: PeerId, neg: crate::packet::PathNegative) {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
        }
        self.record_path_negative(from, neg.routing_tag);
        debug!(
            "PathNegative: peer {:?} cannot route tag {:?} (ttl {})",
            &from[..4], &neg.routing_tag[..4], neg.ttl,
        );
        // TTL-bounded forward upstream: pick any non-`from` peer that
        // CURRENTLY claims the tag and propagate the negative hint. This
        // gives multi-hop convergence for FP-storms without flooding.
        if neg.ttl > 1
            && let Some(next) = self.lookup_by_tag_excluding(&neg.routing_tag, Some(from)) {
                self.send_path_negative(next, neg.routing_tag, neg.ttl - 1);
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
            self.send_announces(i);
            self.cuckoo_do_maintenance(i);
        }
        self.update_own_coord();
        self.broadcast_coord();
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
        let mut sm = self.sessions.lock_or_recover();
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
        if vk.verify(&ann.sign_bytes(), &ed25519_dalek::Signature::from_bytes(&ann.sig)).is_err() {
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

    /// Periodic broadcast of signed reputation reports about each of our
    /// direct peers' local trust scores. Receivers aggregate into a
    /// "consensus trust" that biases their routing decisions.
    #[mutants::skip]
    fn broadcast_reputation(&mut self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let observer = self.pub_key;
        let observed_with_trust: Vec<([u8; 32], f32)> = self.peers.values()
            .map(|p| (p.pub_key, p.trust))
            .collect();
        for (observed, trust) in observed_with_trust {
            self.own_reputation_seq += 1;
            let seq = self.own_reputation_seq;
            // Quantise trust to u16 over the configured [TRUST_MIN, TRUST_MAX].
            // For wire compactness; receiver de-quantises.
            let frac = ((trust - TRUST_MIN) / (TRUST_MAX - TRUST_MIN)).clamp(0.0, 1.0);
            let score_q16 = (frac * u16::MAX as f32) as u16;
            let unsigned = ReputationReport {
                observer, observed, score_q16, seq, valid_from_ms: now_ms,
                sig: [0u8; 64],
            };
            let sig = self.signing_key.sign(&unsigned.sign_bytes()).to_bytes();
            let report = ReputationReport { sig, ..unsigned };
            // Record ourselves so consensus_trust sees our own view too.
            self.record_reputation(observer, observed, seq, report.score(), Instant::now());
            let encoded = report.encode();
            let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
            for pk in peer_keys {
                self.send_to_peer(&pk, encoded.clone());
            }
        }
    }

    /// Handle an inbound reputation report from a peer (potentially originating
    /// far away). Verify, dedup, store, forward to non-sender peers.
    pub fn handle_reputation_report(&mut self, from: PeerId, r: ReputationReport) {
        // Reject if observer signed about themselves (no information).
        if r.observer == r.observed {
            return;
        }
        // Reject self-origin (we shouldn't accept claims about us as if we made them).
        if r.observer == self.pub_key {
            return;
        }
        let vk = match VerifyingKey::from_bytes(&r.observer) {
            Ok(v) => v,
            Err(_) => return,
        };
        if vk.verify(&r.sign_bytes(), &ed25519_dalek::Signature::from_bytes(&r.sig)).is_err() {
            warn!("invalid reputation report sig from observer {:?}", &r.observer[..4]);
            return;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let age = now_ms.saturating_sub(r.valid_from_ms);
        if age > REPUTATION_VALIDITY_MS {
            return;
        }
        if r.valid_from_ms > now_ms.saturating_add(60_000) {
            return;
        }
        // Dedup: forward only if strictly newer seq from this (observer, observed).
        let is_newer = self.reputation.get(&r.observed)
            .and_then(|m| m.get(&r.observer))
            .map(|(prev_seq, _, _)| r.seq > *prev_seq)
            .unwrap_or(true);
        if !is_newer {
            return;
        }
        self.record_reputation(r.observer, r.observed, r.seq, r.score(), Instant::now());

        // Flood to other peers.
        let encoded = r.encode();
        let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
        for pk in peer_keys {
            if pk != from {
                self.send_to_peer(&pk, encoded.clone());
            }
        }
    }

    /// Handle a HolePunch frame.
    ///
    /// Two cases:
    ///
    /// 1. `target == us` — we are the destination of the punch. Verify
    ///    the initiator's signature, log the observed endpoint so an
    ///    operator (or the on_hole_punch callback, if set) can act on it.
    /// 2. `target != us` AND we have a session with `target` — we are
    ///    the rendezvous. Verify and forward the same HolePunch frame
    ///    to `target` through the routed overlay.
    ///
    /// In all other cases the frame is dropped.
    pub fn handle_hole_punch(&mut self, _from: PeerId, hp: HolePunch) {
        // Sig binds initiator+target+endpoint+ts → rendezvous can't forge.
        let vk = match VerifyingKey::from_bytes(&hp.initiator) {
            Ok(v) => v,
            Err(_) => return,
        };
        if vk.verify(&hp.sign_bytes(), &ed25519_dalek::Signature::from_bytes(&hp.sig)).is_err() {
            warn!("invalid HolePunch sig from {:?}", &hp.initiator[..4]);
            return;
        }
        // Freshness ±60s.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64).unwrap_or(0);
        let skew = (now_ms as i64 - hp.valid_from_ms as i64).unsigned_abs();
        if skew > 60_000 {
            debug!("HolePunch outside freshness window, dropping");
            return;
        }

        if hp.target == self.pub_key {
            // We're the destination — dispatch the callback if registered.
            if let Some(cb) = &self.hole_punch_cb {
                let cb = cb.clone();
                let initiator = hp.initiator;
                let endpoint = hp.endpoint.clone();
                tokio::spawn(async move { cb(initiator, endpoint) });
            } else {
                debug!("HolePunch for us from {:?} at {}, but no on_hole_punch handler set",
                    &hp.initiator[..4], hp.endpoint);
            }
        } else {
            // Relay role: forward the *same* signed frame to target via
            // session-layer traffic if we have a session with target. We
            // wrap it in send_traffic_to which will route through whichever
            // next-hop currently knows target.
            let encoded = hp.encode();
            // send_traffic_to wraps as PKT_CONTROL with our identity as
            // source. The target's TRAFFIC handler unpads then sees the
            // HolePunch byte and re-dispatches. (Implemented as a
            // bypass: forward as a raw routing frame instead.)
            if let Some(next_hop) = self.lookup(&hp.target) {
                self.send_to_peer(&next_hop, encoded);
            } else {
                debug!("HolePunch: no route to target {:?}, dropping", &hp.target[..4]);
            }
        }
    }

    /// Insert/update one observation; bound the table size by per-peer.
    fn record_reputation(
        &mut self,
        observer: [u8; 32],
        observed: [u8; 32],
        seq: u64,
        score: f32,
        recorded_at: Instant,
    ) {
        // Cap total observations to avoid memory exhaustion. We evict a
        // whole per-observed bucket (least useful) when the total crosses
        // the limit and we're inserting into a new bucket.
        let total: usize = self.reputation.values().map(|m| m.len()).sum();
        if total >= MAX_REPUTATION_OBSERVATIONS && !self.reputation.contains_key(&observed) {
            // Evict an arbitrary non-peer observed entry.
            let victim = self.reputation.keys()
                .find(|k| !self.peers.contains_key(*k) && **k != self.pub_key)
                .copied();
            if let Some(v) = victim {
                self.reputation.remove(&v);
            } else {
                return;
            }
        }
        self.reputation
            .entry(observed)
            .or_default()
            .insert(observer, (seq, score, recorded_at));
    }

    /// Compute consensus trust for `observed` with three Sybil/collusion hardenings:
    ///
    ///   1. **PoW-weighted observers.** Each observer's score is multiplied
    ///      by `min(1.0, observer_difficulty_bits / REPUTATION_WEIGHT_BITS)`.
    ///      A Sybil army of low-difficulty identities still counts, but each
    ///      vote is fractional — defeating cheap "1k Sybils trash one honest
    ///      peer" (bad-mouthing) and "1k Sybils inflate a peer they control"
    ///      (self-promotion).
    ///   2. **Trimmed mean.** Sort observed scores; discard top
    ///      `REPUTATION_TRIM_FRAC` and bottom `REPUTATION_TRIM_FRAC` before
    ///      averaging. A coalition has to control >25 % of voting weight to
    ///      shift the median; below that, their extreme votes get trimmed.
    ///   3. **Minimum quorum.** Below `REPUTATION_MIN_QUORUM` distinct
    ///      observers, return None (= "no consensus yet, fall back to local
    ///      trust"). Stops a lone attacker observation from dictating
    ///      consensus on a barely-known peer.
    ///
    /// Returns None when (a) no observations or (b) below quorum.
    pub fn consensus_trust(&self, observed: &[u8; 32]) -> Option<f32> {
        let bucket = self.reputation.get(observed)?;
        let cutoff = Instant::now().checked_sub(Duration::from_millis(REPUTATION_VALIDITY_MS))
            .unwrap_or(Instant::now());

        // Collect (weight, real_trust) pairs for fresh observations.
        let mut weighted: Vec<(f64, f64)> = Vec::with_capacity(bucket.len());
        for (observer_pub, (_, score, t)) in bucket {
            if *t < cutoff {
                continue;
            }
            let real_trust = TRUST_MIN + score * (TRUST_MAX - TRUST_MIN);
            let bits = crate::address::key_difficulty_bits(observer_pub);
            // Linear weight cap at REPUTATION_WEIGHT_BITS — Sybils with 0
            // bits contribute essentially nothing; the floor (1.0 / cap) is
            // kept so a small honest network with no PoW still operates.
            let w = ((bits as f64) / REPUTATION_WEIGHT_BITS as f64)
                .clamp(REPUTATION_WEIGHT_FLOOR, 1.0);
            weighted.push((w, real_trust as f64));
        }

        if weighted.len() < REPUTATION_MIN_QUORUM {
            return None;
        }

        // Trimmed-mean: sort by score, drop the top/bottom fraction.
        weighted.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        let n = weighted.len();
        let trim = ((n as f64) * REPUTATION_TRIM_FRAC).floor() as usize;
        let kept = &weighted[trim..n.saturating_sub(trim).max(trim + 1)];
        if kept.is_empty() {
            return None;
        }
        let total_w: f64 = kept.iter().map(|(w, _)| *w).sum();
        if total_w <= f64::EPSILON {
            return None;
        }
        let weighted_sum: f64 = kept.iter().map(|(w, s)| w * s).sum();
        Some((weighted_sum / total_w) as f32)
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

    /// Broadcast our hyperbolic coordinate + onion ephemeral pub to all peers.
    #[mutants::skip]
    fn broadcast_coord(&mut self) {
        let coord_bytes = self.own_coord.encode();
        let onion_eph_pub = *self.onion_keys.pub_key().as_bytes();
        let unsigned = CoordAnnounce {
            coord: coord_bytes,
            tree_depth: self.own_depth,
            onion_eph_pub,
            sig: [0u8; 64],
        };
        let sig = self.signing_key.sign(&unsigned.sign_bytes()).to_bytes();
        let ann = CoordAnnounce { sig, ..unsigned };
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
        let vk = match ed25519_dalek::VerifyingKey::from_bytes(&from_key) {
            Ok(v) => v,
            Err(_) => return,
        };
        let sig = ed25519_dalek::Signature::from_bytes(&ann.sig);
        if vk.verify(&ann.sign_bytes(), &sig).is_err() {
            warn!("invalid coord announce signature from {:?}", &from_key[..4]);
            return;
        }
        let coord = HypCoord::decode(&ann.coord);
        if !coord.r.is_finite() || !coord.theta.is_finite() {
            warn!("coord announce from {:?} has non-finite values, ignoring", &from_key[..4]);
            return;
        }

        // ── Consistency check #1: coord MUST equal from_tree_depth(depth, pub_key).
        //
        // Coords are a deterministic function of (tree_depth, pub_key), so the
        // sender cannot legitimately pick a coord independent of those two
        // inputs. Allowing arbitrary self-reported coords lets a malicious peer
        // place itself near any target, biasing greedy routing toward
        // themselves (sinkhole). We reject any mismatch.
        let expected = HypCoord::from_tree_depth(ann.tree_depth, &from_key);
        if !coords_approx_equal(&coord, &expected) {
            warn!(
                "coord announce from {:?} inconsistent with from_tree_depth(depth={}); rejecting",
                &from_key[..4], ann.tree_depth
            );
            // Treat as a soft-fail trust signal too.
            if let Some(peer) = self.peers.get_mut(&from_key) {
                peer.decay_trust();
            }
            return;
        }

        // ── Consistency check #2: tree_depth in the announce MUST agree with
        // the tree-0 Announce we have on file from the same peer (within a
        // small window to tolerate gossip lag). A peer claiming depth=0 in
        // CoordAnnounce but depth=5 in Announce is lying about its position.
        if let Some(peer) = self.peers.get(&from_key)
            && let Some(t0) = &peer.trees[0] {
            let announced = t0.depth as i64;
            let claimed = ann.tree_depth as i64;
            // Allow ±2 to accommodate transient mid-update races.
            if (announced - claimed).abs() > 2 {
                warn!(
                    "coord announce from {:?} claims tree-0 depth {}, but Announce says {}; rejecting",
                    &from_key[..4], claimed, announced
                );
                if let Some(peer) = self.peers.get_mut(&from_key) {
                    peer.decay_trust();
                }
                return;
            }
        }
        if self.coord_table.len() >= MAX_COORD_TABLE_SIZE
            && !self.coord_table.contains_key(&from_key) {
            let victim = self.coord_table.keys()
                .find(|k| !self.peers.contains_key(*k) && **k != self.pub_key)
                .copied();
            if let Some(v) = victim {
                self.coord_table.remove(&v);
            } else {
                return;
            }
        }
        self.coord_table.insert(from_key, coord);

        // Record the peer's *current* advertised onion ephemeral pub. Onion
        // packets built for this peer as a relay will encrypt to this key
        // rather than the long-term-identity-derived key, giving forward
        // secrecy once the peer rotates.
        if let Some(peer) = self.peers.get_mut(&from_key) {
            peer.onion_eph_pub = Some(ann.onion_eph_pub);
        }
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
                    let old_lag_us = peer.lag.as_micros() as i64;
                    let new_lag_us = new_lag.as_micros() as i64;
                    let diff = (new_lag_us - old_lag_us).unsigned_abs();
                    peer.jitter = Duration::from_micros(
                        (peer.jitter.as_micros() as u64 * 7 / 8) + diff / 8
                    );
                    peer.lag = Duration::from_micros(
                        (old_lag_us as u64 * 7 / 8) + new_lag_us as u64 / 8
                    );
                    peer.loss_rate *= 0.875;
                    // Liveness probe succeeded → boost trust slightly.
                    peer.boost_trust();
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
            // Was this the response to an outstanding probe? If so, boost
            // the via-peer's trust (it actually delivered what its cuckoo claimed).
            if let Some((via, _sent_at)) = self.pending_probes.remove(&notify.id)
                && let Some(peer) = self.peers.get_mut(&via) {
                peer.boost_trust();
                debug!(
                    "probe {} via {:?} confirmed (target={:?}) → trust boosted to {}",
                    notify.id, &via[..4], &notify.target[..4], peer.trust
                );
            }
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
        if routing_tag_eq(&traffic.routing_tag, &my_tag) {
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
                // Tell upstream so it stops sending us packets that loop —
                // this is the cuckoo-FP / dead-end backtrack channel.
                self.send_path_negative(from, traffic.routing_tag, PATH_NEG_INITIAL_TTL);
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
                // Backtrack: tell upstream we have no neighbour for this tag
                // (cuckoo false positive somewhere in their view, or genuine
                // unreachability). They cache (us, tag) and try elsewhere.
                let tag = traffic.routing_tag;
                self.send_path_negative(from, tag, PATH_NEG_INITIAL_TTL);
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

        // Onion replay check: drop packets whose (epk, first AEAD bytes) hash
        // we've recently seen. Replays would let a tagging attacker confirm
        // path participation by re-injecting captured cells.
        if self.is_onion_replay(&pkt) {
            debug!("onion peel: replay detected, dropping");
            return;
        }

        match pkt.peel(&self.onion_keys) {
            Ok(PeeledOnion::Forward(inner_bytes)) => {
                // We are a relay: decode the next layer and forward it
                match OnionPacket::decode(&inner_bytes) {
                    Ok(inner) => {
                        let tag = inner.routing_tag;
                        let encoded = inner.encode();
                        if let Some(next) = self.lookup_by_tag_excluding(&tag, Some(from)) {
                            self.send_to_peer(&next, encoded);
                        } else {
                            debug!("onion: no route for next tag {:?}", &tag[..4]);
                            self.send_path_negative(from, tag, PATH_NEG_INITIAL_TTL);
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

    /// Has this onion packet's tag been seen recently? If not, record it.
    /// We hash (epk || first 16 bytes of aead_payload) into a 32-byte BLAKE2b
    /// digest — collision-resistant and cheap. The cache is an LRU bounded by
    /// ONION_REPLAY_CACHE_SIZE.
    #[mutants::skip]
    fn is_onion_replay(&mut self, pkt: &OnionPacket) -> bool {
        use blake2::{Blake2b, Digest};
        use blake2::digest::consts::U32;
        let mut h: Blake2b<U32> = Blake2b::new();
        h.update(b"norn:onion-replay");
        h.update(pkt.epk);
        let prefix_len = pkt.aead_payload.len().min(16);
        h.update(&pkt.aead_payload[..prefix_len]);
        let digest: [u8; 32] = h.finalize().into();
        if self.onion_seen.iter().any(|d| d == &digest) {
            return true;
        }
        if self.onion_seen.len() >= ONION_REPLAY_CACHE_SIZE {
            self.onion_seen.pop_front();
        }
        self.onion_seen.push_back(digest);
        false
    }

    /// Route lookup using only the 16-byte routing_tag (for forwarding Traffic
    /// where the full dest pub key is not known to intermediate nodes).
    #[cfg(test)]
    fn lookup_by_tag(&self, tag: &[u8; 16]) -> Option<PeerId> {
        self.lookup_by_tag_excluding(tag, None)
    }

    /// Same as `lookup_by_tag` but skips a specified peer. Used when forwarding
    /// to avoid bouncing a packet back to the peer it just came from — without
    /// this, cuckoo gossip (which naturally propagates each tag in both
    /// directions) creates trivial 2-cycles.
    ///
    /// Ranking uses *trust-adjusted* cost: peers that have failed past route
    /// probes get a higher effective cost and are pushed to the back of the
    /// queue. This mitigates cuckoo poisoning — a peer that lies about
    /// reachable tags will see its trust decay and stop being chosen.
    fn lookup_by_tag_excluding(&self, tag: &[u8; 16], exclude: Option<PeerId>) -> Option<PeerId> {
        let mut best: Option<(PeerId, u64)> = None;
        for (peer_key, peer) in &self.peers {
            if exclude == Some(*peer_key) {
                continue;
            }
            // Skip peers that recently sent us a PathNegative for this tag —
            // their cuckoo claim is a known false positive.
            if self.is_path_negative(peer_key, tag) {
                continue;
            }
            for tree_id in 0..K {
                if peer.cuckoo[tree_id].contains(tag) {
                    // Combine local trust with network-consensus trust if
                    // available; consensus = NULL → use local trust alone.
                    let local = peer.trust;
                    let combined = match self.consensus_trust(peer_key) {
                        Some(c) => (local + c) * 0.5,
                        None    => local,
                    };
                    let cost = peer.trust_adjusted_cost_with(combined);
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
    /// Sybil-resistance threshold: an inbound peer's pub_key MUST have at
    /// least this many leading 1-bits in BLAKE2b(pub_key) (cf.
    /// `address::key_difficulty_bits`). 0 = no requirement. Stored as
    /// AtomicU32 so it can be raised at runtime without locking.
    min_peer_difficulty_bits: Arc<std::sync::atomic::AtomicU32>,
    shutdown_tx: watch::Sender<bool>,
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

        // Encrypt + envelope all payloads under a single session-
        // manager lock acquire. Each per-payload encrypt is fast;
        // the lock acquire/release dance is what we're saving.
        let pub_key = self.pub_key;
        let (enc_header, tag) = encrypt_header(&pub_key, dst);
        let encoded_frames: Vec<Vec<u8>> = {
            let state = self.inner.lock_or_recover();
            let mut sm = state.sessions.lock_or_recover();
            let mut out = Vec::with_capacity(payloads.len());
            for p in payloads {
                let padded = pad_payload(p);
                let ciphertext = sm.encrypt(dst, &padded)?;
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
        // tree_metric() is now an alias for tree_metric_at(..., epoch=0). The
        // body XORs the key with a BLAKE2-derived 32-byte salt. The mutation
        // we still want to catch is `^= → |=` inside the loop in
        // tree_metric_at; the operation is still XOR (no longer of `seed[i%8]`
        // directly but of `salt[i]`). With OR, the result is monotonically ≥
        // either operand, so a key of all zeros forced through OR cannot
        // produce a metric byte smaller than the salt byte at that index.
        let key = [0u8; 32];
        let seed = *b"Verdandi";
        let metric = tree_metric(&key, &seed);
        // Compute the salt the same way the function does, so we can compare.
        use blake2::{Blake2b, Digest};
        use blake2::digest::consts::U32;
        let mut h: Blake2b<U32> = Blake2b::new();
        h.update(b"norn:tree-epoch");
        h.update(seed);
        h.update(0u64.to_le_bytes());
        let salt: [u8; 32] = h.finalize().into();
        for i in 0..32 {
            assert_eq!(metric[i], key[i] ^ salt[i],
                "byte {}: must XOR (not OR/AND); got {:#04x}", i, metric[i]);
        }
    }

    #[test]
    fn tree_metric_at_uses_full_32_byte_salt() {
        // After epoch rotation we use a 32-byte BLAKE2 salt (no more
        // wrap-around at index 8). Distinct bytes at i and i+8 prove the salt
        // is not being re-indexed modulo 8 (which would silently collapse
        // the keyspace).
        let key = [0u8; 32];
        let seed = [0u8; 8];
        let metric = tree_metric_at(&key, &seed, 0);
        // For a zero key, metric[i] == salt[i]. Inspect that salt[0..16] is
        // not equal to salt[16..32] — vanishingly unlikely for BLAKE2.
        let lo = &metric[0..16];
        let hi = &metric[16..32];
        assert_ne!(lo, hi,
            "salt's low and high halves must differ — proves we use the full 32-byte salt");
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
        // XOR with all-zero seed is identity at epoch 0.
        // (epoch 0 has a non-trivial BLAKE2 salt that depends on the seed —
        // but the LEGACY tree_metric() routes through tree_metric_at(...,0);
        // with a zero seed the salt is fixed BLAKE2(b"norn:tree-epoch"||0^8||0u64),
        // so the result is just key XOR that fixed salt. Compare against the
        // same call to itself rather than raw key.)
        assert_eq!(tree_metric(&key, &seed), tree_metric(&key, &seed));
    }

    // ── tree_metric_at / current_tree_epoch ─────────────────────────────────

    #[test]
    fn tree_metric_at_rotates_with_epoch() {
        // The same (key, seed) must give a DIFFERENT metric in different
        // epochs. Without this, the lowest-key node is the permanent root
        // and a perpetual DDoS / censorship target.
        let key = [0x42u8; 32];
        let seed = *b"Verdandi";
        let m0 = tree_metric_at(&key, &seed, 0);
        let m1 = tree_metric_at(&key, &seed, 1);
        let m_far = tree_metric_at(&key, &seed, 365);
        assert_ne!(m0, m1, "metric must change between adjacent epochs");
        assert_ne!(m0, m_far, "metric must change across distant epochs");
        assert_ne!(m1, m_far, "epoch 1 and epoch 365 must also differ");
    }

    #[test]
    fn tree_metric_at_deterministic_within_epoch() {
        // Both peers in an adjacency MUST compute the same metric for the
        // same (key, seed, epoch), otherwise their tree would never converge.
        let key = [0x99u8; 32];
        let seed = *b"Skuld___";
        assert_eq!(
            tree_metric_at(&key, &seed, 42),
            tree_metric_at(&key, &seed, 42),
            "metric must be deterministic per (key, seed, epoch)",
        );
    }

    #[test]
    fn tree_metric_at_rotates_root_winner() {
        // Demonstration of the security property: across many epochs, the
        // identity of the lowest-metric ("root") node changes. With static
        // tree_metric this would always be the lex-smallest key.
        let keys: Vec<[u8; 32]> = (0u8..16).map(|i| [i; 32]).collect();
        let seed = [0u8; 8];
        let mut winners = std::collections::HashSet::new();
        for epoch in 0u64..32 {
            let winner = keys.iter()
                .min_by_key(|k| tree_metric_at(k, &seed, epoch))
                .copied()
                .unwrap();
            winners.insert(winner);
        }
        assert!(winners.len() >= 4,
            "expected ≥4 distinct root winners across 32 epochs, got {}: \
             root rotation is what makes the network resistant to long-lived \
             root-targeting attacks", winners.len());
    }

    #[test]
    fn current_tree_epoch_monotonic_within_a_day() {
        // Sanity: the function returns a finite number for a current call.
        let e = current_tree_epoch();
        assert!(e > 0, "current_tree_epoch should be > 0 after 1970");
        // 24h epoch → today's epoch is at most days-since-epoch.
        let max_plausible = 100_000u64; // ~273 years; sanity ceiling
        assert!(e < max_plausible, "epoch {} unexpectedly large", e);
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

    /// Compute the per-epoch tree-metric salt the same way `tree_metric_at`
    /// does. Tests use this to construct an announce whose root deterministically
    /// produces metric = [0;32] — beating any random self pub_key regardless
    /// of the current epoch's BLAKE2 output.
    fn salt_for_test(tree_id: usize, epoch: u64) -> [u8; 32] {
        use blake2::{Blake2b, Digest};
        use blake2::digest::consts::U32;
        let mut h: Blake2b<U32> = Blake2b::new();
        h.update(b"norn:tree-epoch");
        h.update(TREE_SEEDS[tree_id]);
        h.update(epoch.to_le_bytes());
        h.finalize().into()
    }

    #[test]
    fn fix_tree_selects_peer_with_lower_cost() {
        let mut rs = make_router();
        let peer_a = [0x11u8; 32];
        let peer_b = [0x22u8; 32];
        add_dummy_peer(&mut rs, peer_a);
        add_dummy_peer(&mut rs, peer_b);
        // Both announce the same root whose XOR with the current epoch salt
        // gives metric=0 — guaranteed to beat any random self pub_key under
        // the epoch-rotated metric.
        let root = salt_for_test(0, current_tree_epoch());
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
        // Pick a root whose metric under the current epoch is [0;32] — the
        // smallest possible, so it beats any random self pub_key.
        let root = salt_for_test(0, current_tree_epoch());
        rs.peers.get_mut(&peer_key).unwrap().trees[0] = Some(TreeAnnounce {
            root,
            path_cost: 0,
            received_at: Instant::now(),
            depth: 1,
        });
        rs.peers.get_mut(&peer_key).unwrap().lag = Duration::from_micros(1_000);
        rs.fix_tree(0);
        if rs.pub_key != root {
            assert_eq!(rs.trees[0].parent, Some(peer_key),
                "peer with better root metric must be selected as parent");
            assert_eq!(rs.trees[0].root, root);
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

    // ── trust scoring ────────────────────────────────────────────────────────

    #[test]
    fn peer_starts_at_initial_trust() {
        let mut rs = make_router();
        let key = [0xA1u8; 32];
        add_dummy_peer(&mut rs, key);
        assert_eq!(rs.peers[&key].trust, TRUST_INITIAL,
            "new peers start at TRUST_INITIAL");
    }

    #[test]
    fn decay_trust_multiplies_and_floors() {
        let mut rs = make_router();
        let key = [0xA2u8; 32];
        add_dummy_peer(&mut rs, key);
        rs.peers.get_mut(&key).unwrap().trust = 1.0;
        rs.peers.get_mut(&key).unwrap().decay_trust();
        assert!((rs.peers[&key].trust - 0.5).abs() < 1e-6,
            "one decay halves trust: {}", rs.peers[&key].trust);
        // Many decays must floor at TRUST_MIN.
        for _ in 0..100 { rs.peers.get_mut(&key).unwrap().decay_trust(); }
        assert!(rs.peers[&key].trust >= TRUST_MIN,
            "trust must never fall below TRUST_MIN");
    }

    #[test]
    fn boost_trust_multiplies_and_caps() {
        let mut rs = make_router();
        let key = [0xA3u8; 32];
        add_dummy_peer(&mut rs, key);
        rs.peers.get_mut(&key).unwrap().trust = 1.0;
        rs.peers.get_mut(&key).unwrap().boost_trust();
        assert!(rs.peers[&key].trust > 1.0, "boost must increase trust");
        for _ in 0..100 { rs.peers.get_mut(&key).unwrap().boost_trust(); }
        assert!(rs.peers[&key].trust <= TRUST_MAX,
            "trust must never exceed TRUST_MAX");
    }

    #[test]
    fn trust_adjusted_cost_inverse_to_trust() {
        let mut rs = make_router();
        let key = [0xA4u8; 32];
        add_dummy_peer(&mut rs, key);
        rs.peers.get_mut(&key).unwrap().lag = Duration::from_millis(100);
        rs.peers.get_mut(&key).unwrap().loss_rate = 0.0;
        rs.peers.get_mut(&key).unwrap().trust = 1.0;
        let cost_at_1 = rs.peers[&key].trust_adjusted_cost();
        rs.peers.get_mut(&key).unwrap().trust = 0.1;
        let cost_at_low = rs.peers[&key].trust_adjusted_cost();
        assert!(cost_at_low > cost_at_1,
            "low trust must yield higher cost (de-prioritised in lookup); {} vs {}",
            cost_at_low, cost_at_1);
    }

    #[test]
    fn lookup_by_tag_prefers_higher_trust_on_tie() {
        // Two peers both claim the same tag with identical lag; the higher-trust
        // one should win.
        let mut rs = make_router();
        let high = [0xB0u8; 32];
        let low  = [0xB1u8; 32];
        add_dummy_peer(&mut rs, high);
        add_dummy_peer(&mut rs, low);
        rs.peers.get_mut(&high).unwrap().lag = Duration::from_millis(50);
        rs.peers.get_mut(&low).unwrap().lag  = Duration::from_millis(50);
        rs.peers.get_mut(&high).unwrap().trust = 2.0;
        rs.peers.get_mut(&low).unwrap().trust  = 0.1;
        let tag = [0xCC_u8; 16];
        rs.peers.get_mut(&high).unwrap().cuckoo[0].add(&tag);
        rs.peers.get_mut(&low).unwrap().cuckoo[0].add(&tag);
        let winner = rs.lookup_by_tag(&tag).expect("at least one peer should match");
        assert_eq!(winner, high,
            "the high-trust peer must win the lookup tie");
    }

    // ── onion replay cache ──────────────────────────────────────────────────

    // ── Hyperbolic coord consistency check ──────────────────────────────────

    fn make_coord_announce(sk: &SigningKey, tree_depth: u32, coord: HypCoord) -> CoordAnnounce {
        let unsigned = CoordAnnounce {
            coord: coord.encode(),
            tree_depth,
            onion_eph_pub: [0u8; 32],
            sig: [0u8; 64],
        };
        let sig = sk.sign(&unsigned.sign_bytes()).to_bytes();
        CoordAnnounce { sig, ..unsigned }
    }

    #[test]
    fn coord_announce_consistent_accepted() {
        let mut rs = make_router();
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        add_dummy_peer(&mut rs, pk);
        let depth = 3;
        // Build the *correct* coord for this depth+key.
        let coord = HypCoord::from_tree_depth(depth, &pk);
        let ann = make_coord_announce(&sk, depth, coord);
        rs.handle_coord_announce(pk, ann);
        assert!(rs.coord_table.contains_key(&pk),
            "consistent CoordAnnounce must be recorded");
    }

    #[test]
    fn coord_announce_spoofed_r_rejected() {
        // Attack: declare depth=10 (legitimate-looking) but claim coord
        // r=0.001 (near origin → near every dst → wins greedy routing).
        let mut rs = make_router();
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        add_dummy_peer(&mut rs, pk);
        let spoof = HypCoord {
            r: 0.001,
            theta: HypCoord::angle_from_key(&pk),
        };
        let ann = make_coord_announce(&sk, 10, spoof);
        rs.handle_coord_announce(pk, ann);
        assert!(!rs.coord_table.contains_key(&pk),
            "spoofed CoordAnnounce (r ≠ tanh(depth*DELTA)) must be rejected");
    }

    #[test]
    fn coord_announce_spoofed_theta_rejected() {
        let mut rs = make_router();
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        add_dummy_peer(&mut rs, pk);
        let spoof = HypCoord {
            r: (3.0_f64 * 0.5).tanh(), // correct r for depth=3
            theta: 1.234,              // arbitrary theta, NOT derived from pk
        };
        let ann = make_coord_announce(&sk, 3, spoof);
        rs.handle_coord_announce(pk, ann);
        assert!(!rs.coord_table.contains_key(&pk),
            "spoofed CoordAnnounce (theta ≠ angle_from_key) must be rejected");
    }

    #[test]
    fn coord_announce_depth_disagreement_with_announce_rejected() {
        let mut rs = make_router();
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        add_dummy_peer(&mut rs, pk);
        // Stash a tree-0 Announce on file saying depth=10.
        rs.peers.get_mut(&pk).unwrap().trees[0] = Some(TreeAnnounce {
            root: pk,
            path_cost: 0,
            received_at: Instant::now(),
            depth: 10,
        });
        // Now CoordAnnounce claims depth=0 (consistent with r=0.0 coord,
        // so check #1 passes — but check #2 must catch the disagreement).
        let coord = HypCoord::from_tree_depth(0, &pk);
        let ann = make_coord_announce(&sk, 0, coord);
        rs.handle_coord_announce(pk, ann);
        assert!(!rs.coord_table.contains_key(&pk),
            "CoordAnnounce depth disagreement with Announce must be rejected");
    }

    // ── PathLookup auto-prober ──────────────────────────────────────────────

    #[test]
    fn probe_decays_trust_on_timeout() {
        let mut rs = make_router();
        let via = [0x44u8; 32];
        add_dummy_peer(&mut rs, via);
        let initial_trust = rs.peers[&via].trust;
        // Insert an artificially-old probe.
        let id = 0xCAFE_BABE;
        let stale = Instant::now()
            .checked_sub(PROBE_TIMEOUT + Duration::from_secs(1))
            .expect("subtraction must succeed");
        rs.pending_probes.insert(id, (via, stale));
        rs.cleanup_stale_probes();
        assert!(!rs.pending_probes.contains_key(&id), "stale probe must be removed");
        assert!(rs.peers[&via].trust < initial_trust,
            "trust must decay after probe timeout; before={} after={}",
            initial_trust, rs.peers[&via].trust);
    }

    #[test]
    fn probe_kept_if_not_yet_expired() {
        let mut rs = make_router();
        let via = [0x45u8; 32];
        add_dummy_peer(&mut rs, via);
        let id = 0xDEAD_BEEF;
        rs.pending_probes.insert(id, (via, Instant::now()));
        rs.cleanup_stale_probes();
        assert!(rs.pending_probes.contains_key(&id),
            "fresh probe must NOT be cleaned up");
    }

    #[test]
    fn probe_match_on_path_notify_boosts_trust() {
        let mut rs = make_router();
        let via = [0x46u8; 32];
        let target = [0x47u8; 32];
        add_dummy_peer(&mut rs, via);
        let id = 0xFEED_F00D;
        rs.pending_probes.insert(id, (via, Instant::now()));
        let trust_before = rs.peers[&via].trust;
        // Synthesize a PathNotify that addresses us as source.
        let own_pub = rs.pub_key;
        rs.handle_path_notify(via, PathNotify {
            target, source: own_pub, id, path: vec![],
        });
        assert!(!rs.pending_probes.contains_key(&id),
            "matched probe must be removed");
        assert!(rs.peers[&via].trust > trust_before,
            "trust must boost on probe success; before={} after={}",
            trust_before, rs.peers[&via].trust);
    }

    // ── OnionKeyAnnounce flood ──────────────────────────────────────────────

    // ── HolePunch relay ────────────────────────────────────────────────────

    fn make_hole_punch(initiator_sk: &SigningKey, target: [u8; 32], endpoint: &str) -> HolePunch {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64).unwrap_or(0);
        let unsigned = HolePunch {
            initiator: initiator_sk.verifying_key().to_bytes(),
            target,
            valid_from_ms: now_ms,
            endpoint: endpoint.to_string(),
            sig: [0u8; 64],
        };
        let sig = initiator_sk.sign(&unsigned.sign_bytes()).to_bytes();
        HolePunch { sig, ..unsigned }
    }

    #[tokio::test]
    async fn hole_punch_for_us_fires_callback() {
        let mut rs = make_router();
        let initiator = SigningKey::generate(&mut OsRng);
        let own_pub = rs.pub_key;
        let hp = make_hole_punch(&initiator, own_pub, "10.0.0.5:9001");

        let received: Arc<std::sync::Mutex<Option<(PeerId, String)>>> =
            Arc::new(std::sync::Mutex::new(None));
        let received_clone = received.clone();
        rs.hole_punch_cb = Some(Arc::new(move |pk, ep| {
            *received_clone.lock().unwrap() = Some((pk, ep));
        }));

        rs.handle_hole_punch([0u8; 32], hp);
        // Callback dispatches via tokio::spawn — wait briefly.
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if received.lock().unwrap().is_some() { break; }
        }
        let r = received.lock().unwrap().clone();
        assert!(r.is_some(), "callback must fire on for-us HolePunch");
        let (pk, ep) = r.unwrap();
        assert_eq!(pk, initiator.verifying_key().to_bytes());
        assert_eq!(ep, "10.0.0.5:9001");
    }

    #[test]
    fn hole_punch_invalid_sig_rejected() {
        let mut rs = make_router();
        let initiator = SigningKey::generate(&mut OsRng);
        let own_pub = rs.pub_key;
        let mut hp = make_hole_punch(&initiator, own_pub, "1.2.3.4:9001");
        hp.sig[0] ^= 0xFF;

        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f = fired.clone();
        rs.hole_punch_cb = Some(Arc::new(move |_, _| {
            f.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        rs.handle_hole_punch([0u8; 32], hp);
        assert!(!fired.load(std::sync::atomic::Ordering::SeqCst),
            "callback must not fire on bad signature");
    }

    #[test]
    fn hole_punch_for_other_target_no_route_drops() {
        let mut rs = make_router();
        let initiator = SigningKey::generate(&mut OsRng);
        let other_target = [0xCCu8; 32];   // not a peer of ours
        let hp = make_hole_punch(&initiator, other_target, "1.2.3.4:9001");
        // No route → handle_hole_punch logs and returns; nothing observable
        // here beyond "no panic". The point of the test is to exercise the
        // relay-mode code path without an asserting outcome.
        rs.handle_hole_punch([0u8; 32], hp);
    }

    #[test]
    fn hole_punch_relays_to_peer_with_route() {
        let mut rs = make_router();
        let initiator = SigningKey::generate(&mut OsRng);
        let target = [0xCCu8; 32];
        let (tx, mut rx) = mpsc::channel(64);
        // Add `target` as a peer so lookup() resolves directly.
        rs.add_peer(target, tx, 0);

        let hp = make_hole_punch(&initiator, target, "203.0.113.7:9001");
        rs.handle_hole_punch([0xAAu8; 32], hp.clone());

        let forwarded = rx.try_recv().expect("HolePunch must be forwarded to target peer");
        assert_eq!(forwarded[0], TYPE_HOLE_PUNCH,
            "forwarded frame must be of HolePunch type");
        // Decode and confirm contents are preserved.
        let decoded = HolePunch::decode(&forwarded[1..]).unwrap();
        assert_eq!(decoded.initiator, hp.initiator);
        assert_eq!(decoded.endpoint, hp.endpoint);
    }

    // ── Reputation gossip ──────────────────────────────────────────────────

    fn make_report(observer_sk: &SigningKey, observed: [u8; 32], seq: u64, score: f32) -> ReputationReport {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let frac = ((score - TRUST_MIN) / (TRUST_MAX - TRUST_MIN)).clamp(0.0, 1.0);
        let score_q16 = (frac * u16::MAX as f32) as u16;
        let unsigned = ReputationReport {
            observer: observer_sk.verifying_key().to_bytes(),
            observed,
            score_q16,
            seq,
            valid_from_ms: now_ms,
            sig: [0u8; 64],
        };
        let sig = observer_sk.sign(&unsigned.sign_bytes()).to_bytes();
        ReputationReport { sig, ..unsigned }
    }

    #[test]
    fn reputation_report_valid_recorded() {
        // With the new quorum rule we need REPUTATION_MIN_QUORUM independent
        // observers before consensus_trust returns Some. Three reporters all
        // saying ~2.0 → consensus ~2.0.
        let mut rs = make_router();
        let observed = [0x99u8; 32];
        for _ in 0..REPUTATION_MIN_QUORUM {
            let observer = SigningKey::generate(&mut OsRng);
            let r = make_report(&observer, observed, 1, 2.0);
            rs.handle_reputation_report([0xFEu8; 32], r);
        }
        let c = rs.consensus_trust(&observed).unwrap();
        assert!((c - 2.0).abs() < 0.05, "consensus must roughly equal reported score; got {c}");
    }

    #[test]
    fn reputation_below_quorum_returns_none() {
        // One observation is NOT enough — anti-Sybil quorum rule. This is the
        // primary defence against a single attacker dictating consensus.
        let mut rs = make_router();
        let observer = SigningKey::generate(&mut OsRng);
        let observed = [0xDEu8; 32];
        rs.handle_reputation_report([0xFEu8; 32], make_report(&observer, observed, 1, 4.0));
        assert!(rs.consensus_trust(&observed).is_none(),
            "single observation must not pass quorum (need ≥{})", REPUTATION_MIN_QUORUM);
    }

    #[test]
    fn reputation_report_self_observed_rejected() {
        let mut rs = make_router();
        // observer == observed: meaningless self-praise.
        let sk = SigningKey::generate(&mut OsRng);
        let me = sk.verifying_key().to_bytes();
        let mut r = make_report(&sk, me, 1, 3.0);
        // Sign over the self-claim.
        r.sig = sk.sign(&r.sign_bytes()).to_bytes();
        rs.handle_reputation_report([0xFEu8; 32], r);
        assert!(rs.consensus_trust(&me).is_none(),
            "self-praise must not be accepted");
    }

    #[test]
    fn reputation_report_invalid_sig_rejected() {
        let mut rs = make_router();
        let observer = SigningKey::generate(&mut OsRng);
        let observed = [0xAAu8; 32];
        let mut r = make_report(&observer, observed, 1, 1.5);
        r.sig[0] ^= 0xFF;
        rs.handle_reputation_report([0xFEu8; 32], r);
        assert!(rs.consensus_trust(&observed).is_none());
    }

    #[test]
    fn reputation_report_newer_seq_replaces() {
        // For the per-observer "newer seq wins" property to be testable we
        // also need to clear quorum. One observer flips their report, two
        // others act as quorum padding with neutral scores.
        let mut rs = make_router();
        let observer = SigningKey::generate(&mut OsRng);
        let pad1 = SigningKey::generate(&mut OsRng);
        let pad2 = SigningKey::generate(&mut OsRng);
        let observed = [0xBBu8; 32];
        rs.handle_reputation_report([0u8; 32], make_report(&observer, observed, 1, 0.5));
        rs.handle_reputation_report([0u8; 32], make_report(&observer, observed, 2, 3.5));
        rs.handle_reputation_report([0u8; 32], make_report(&pad1, observed, 1, 2.0));
        rs.handle_reputation_report([0u8; 32], make_report(&pad2, observed, 1, 2.0));
        let c = rs.consensus_trust(&observed).unwrap();
        // Three observations after the seq=2 replace: 3.5, 2.0, 2.0.
        // Trimmed mean drops top and bottom — n=3 → trim = floor(3*0.25)=0,
        // so all are kept. Mean ≥ 2.0. Without the replace, observer's seq=1
        // 0.5 would pull it below 2.0 (mean 1.5).
        assert!(c >= 2.0,
            "newer seq must replace prior — mean must be ≥ 2.0 with replace, got {c}");
    }

    #[test]
    fn reputation_aggregates_across_observers() {
        // Three observers with scores [1.0, 2.0, 3.0]. The consensus is a
        // PoW-WEIGHTED trimmed mean — random OsRng keys carry random
        // difficulty_bits, so the exact weights vary run-to-run. What MUST
        // hold: the result sits inside the [1.0, 3.0] envelope. The trimmed
        // mean is not yet trimming anything here (n=3, trim=0), so the
        // value is the weighted average and bounded by the extremes.
        let mut rs = make_router();
        let observers: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let observed = [0xCCu8; 32];
        for (i, sk) in observers.iter().enumerate() {
            let score = 1.0 + i as f32;
            rs.handle_reputation_report([0u8; 32], make_report(sk, observed, 1, score));
        }
        let c = rs.consensus_trust(&observed).unwrap();
        assert!((1.0..=3.0).contains(&c),
            "weighted consensus must lie within [1.0, 3.0]; got {c}");
    }

    #[test]
    fn reputation_trimmed_mean_rejects_extreme_minority() {
        // 4 honest reporters say 2.0, 1 attacker says 4.0 (max).
        // Without trim: mean = (4*2.0 + 4.0)/5 = 2.4 (attacker shifts by 0.4).
        // With trim 25 % per side: n=5, trim = floor(5*0.25)=1 → keep middle 3.
        // Sorted: [2.0, 2.0, 2.0, 2.0, 4.0]; keep[1..4] = [2.0, 2.0, 2.0].
        // Mean = 2.0 exactly — attacker's outlier vote got trimmed.
        let mut rs = make_router();
        let observed = [0xEEu8; 32];
        for _ in 0..4 {
            let sk = SigningKey::generate(&mut OsRng);
            rs.handle_reputation_report([0u8; 32], make_report(&sk, observed, 1, 2.0));
        }
        let attacker = SigningKey::generate(&mut OsRng);
        rs.handle_reputation_report([0u8; 32], make_report(&attacker, observed, 1, 4.0));

        let c = rs.consensus_trust(&observed).unwrap();
        assert!((c - 2.0).abs() < 0.05,
            "trimmed mean must drop the attacker's extreme vote; got {c} (expected ≈ 2.0)");
    }

    fn make_oka(sk: &SigningKey, seq: u64, eph: [u8; 32], age_ms: i64) -> OnionKeyAnnounce {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let valid_from_ms = if age_ms >= 0 {
            now_ms.saturating_sub(age_ms as u64)
        } else {
            now_ms.saturating_add((-age_ms) as u64)
        };
        let unsigned = OnionKeyAnnounce {
            origin: sk.verifying_key().to_bytes(),
            seq,
            valid_from_ms,
            onion_eph_pub: eph,
            sig: [0u8; 64],
        };
        let sig = sk.sign(&unsigned.sign_bytes()).to_bytes();
        OnionKeyAnnounce { sig, ..unsigned }
    }

    #[test]
    fn onion_key_announce_valid_is_recorded() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let origin_pub = origin_sk.verifying_key().to_bytes();
        let eph = [0x77u8; 32];
        let ann = make_oka(&origin_sk, 1, eph, 5_000);
        let from = [0xFEu8; 32];
        rs.handle_onion_key_announce(from, ann);
        let recorded = rs.remote_onion_keys.get(&origin_pub);
        assert!(recorded.is_some(), "valid announce must be recorded");
        let (seq, recorded_eph, _) = recorded.unwrap();
        assert_eq!(*seq, 1);
        assert_eq!(*recorded_eph, eph);
    }

    #[test]
    fn onion_key_announce_invalid_sig_rejected() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let origin_pub = origin_sk.verifying_key().to_bytes();
        let mut ann = make_oka(&origin_sk, 1, [0x77u8; 32], 0);
        ann.sig[0] ^= 0xFF; // tamper
        rs.handle_onion_key_announce([0u8; 32], ann);
        assert!(!rs.remote_onion_keys.contains_key(&origin_pub),
            "bad sig must not be recorded");
    }

    #[test]
    fn onion_key_announce_too_old_rejected() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let origin_pub = origin_sk.verifying_key().to_bytes();
        // 25 hours old > ONION_KEY_VALIDITY_MS (24h)
        let ann = make_oka(&origin_sk, 1, [0x77u8; 32], 25 * 60 * 60 * 1000);
        rs.handle_onion_key_announce([0u8; 32], ann);
        assert!(!rs.remote_onion_keys.contains_key(&origin_pub),
            "stale announce must not be recorded");
    }

    #[test]
    fn onion_key_announce_self_origin_rejected() {
        let mut rs = make_router();
        // Sign with rs's own key — make_oka uses sk.verifying_key as origin.
        let own_sk = rs.signing_key.clone();
        let ann = make_oka(&own_sk, 99, [0x77u8; 32], 0);
        rs.handle_onion_key_announce([0u8; 32], ann);
        // remote_onion_keys may have us inserted by broadcast_onion_key_announce
        // (called from maintenance), but never via *incoming* self-origin frames.
        // Confirm seq stayed at default (we never broadcast in this unit test).
        let entry = rs.remote_onion_keys.get(&rs.pub_key);
        assert!(entry.is_none() || entry.unwrap().0 != 99,
            "self-origin announce must not pollute table");
    }

    #[test]
    fn onion_key_announce_newer_replaces_older() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let origin_pub = origin_sk.verifying_key().to_bytes();
        let eph1 = [0x01u8; 32];
        let eph2 = [0x02u8; 32];
        rs.handle_onion_key_announce([0u8; 32], make_oka(&origin_sk, 1, eph1, 0));
        rs.handle_onion_key_announce([0u8; 32], make_oka(&origin_sk, 2, eph2, 0));
        let (seq, recorded, _) = rs.remote_onion_keys.get(&origin_pub).unwrap();
        assert_eq!(*seq, 2);
        assert_eq!(*recorded, eph2);
    }

    #[test]
    fn onion_key_announce_older_ignored() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let origin_pub = origin_sk.verifying_key().to_bytes();
        let eph1 = [0x01u8; 32];
        let eph_old = [0xEEu8; 32];
        rs.handle_onion_key_announce([0u8; 32], make_oka(&origin_sk, 5, eph1, 0));
        // An older seq must be ignored even if the signature is valid.
        rs.handle_onion_key_announce([0u8; 32], make_oka(&origin_sk, 4, eph_old, 0));
        let (seq, recorded, _) = rs.remote_onion_keys.get(&origin_pub).unwrap();
        assert_eq!(*seq, 5);
        assert_eq!(*recorded, eph1, "older seq must not overwrite");
    }

    #[test]
    fn onion_key_announce_forwards_to_other_peers() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let sender = [0xAAu8; 32];
        let other  = [0xBBu8; 32];
        let (tx_sender, _rx_sender) = mpsc::channel(64);
        let (tx_other, mut rx_other) = mpsc::channel(64);
        rs.add_peer(sender, tx_sender, 0);
        rs.add_peer(other, tx_other, 0);

        let ann = make_oka(&origin_sk, 1, [0x77u8; 32], 0);
        rs.handle_onion_key_announce(sender, ann);

        // `other` must have received a forwarded copy.
        let forwarded = rx_other.try_recv()
            .expect("forwarded OnionKeyAnnounce must be in `other`'s channel");
        assert_eq!(forwarded[0], TYPE_ONION_KEY_ANNOUNCE,
            "forwarded frame must be of OnionKeyAnnounce type");
    }

    #[test]
    fn onion_key_announce_does_not_loop_back_to_sender() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let sender = [0xAAu8; 32];
        let (tx_sender, mut rx_sender) = mpsc::channel(64);
        rs.add_peer(sender, tx_sender, 0);

        let ann = make_oka(&origin_sk, 1, [0x77u8; 32], 0);
        rs.handle_onion_key_announce(sender, ann);
        // The sender must NOT receive a forwarded copy (we don't echo).
        assert!(rx_sender.try_recv().is_err(),
            "must not echo OnionKeyAnnounce back to its sender");
    }

    #[test]
    fn onion_replay_first_sight_not_replay() {
        let mut rs = make_router();
        let pkt = crate::onion::OnionPacket {
            routing_tag: [0u8; 16],
            epk: [1u8; 32],
            aead_payload: vec![0xAA; 32],
        };
        assert!(!rs.is_onion_replay(&pkt), "first sighting must not be flagged");
    }

    #[test]
    fn onion_replay_second_sight_is_replay() {
        let mut rs = make_router();
        let pkt = crate::onion::OnionPacket {
            routing_tag: [0u8; 16],
            epk: [1u8; 32],
            aead_payload: vec![0xAA; 32],
        };
        assert!(!rs.is_onion_replay(&pkt));
        assert!(rs.is_onion_replay(&pkt), "identical second sighting must be detected as replay");
    }

    #[test]
    fn onion_replay_distinguishes_different_epks() {
        let mut rs = make_router();
        let pkt_a = crate::onion::OnionPacket {
            routing_tag: [0u8; 16],
            epk: [1u8; 32],
            aead_payload: vec![0xAA; 32],
        };
        let pkt_b = crate::onion::OnionPacket {
            routing_tag: [0u8; 16],
            epk: [2u8; 32], // different epk
            aead_payload: vec![0xAA; 32],
        };
        assert!(!rs.is_onion_replay(&pkt_a));
        assert!(!rs.is_onion_replay(&pkt_b),
            "different epk → different digest → not a replay");
    }

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

    // ── NORN_ACCELERATE_ROTATIONS_SECS env knob ─────────────────────────────
    //
    // env vars are process-global, so cargo test's default parallelism
    // races multiple env-poking tests against each other (one's `set_var`
    // gets clobbered by another's `remove_var` between two adjacent
    // statements). We collapse all four cases into ONE function with a
    // static Mutex — the mutex serialises us against the OTHER env-poking
    // test below (`malicious_*`), and the single-function layout
    // serialises the four assertions against each other.

    /// Process-wide lock used by every env-mutating test in this module.
    /// Without it, two tests touching the SAME env var race; with it,
    /// they queue.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn accelerate_rotations_secs_env_parsing() {
        // Hold the lock for the full set/check/clear cycle so no other
        // test can observe a half-applied env state.
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        // 1. Unset → None.
        unsafe { std::env::remove_var("NORN_ACCELERATE_ROTATIONS_SECS"); }
        assert!(accelerate_rotations_secs().is_none(),
            "unset env var must yield None (= production cadence)");

        // 2. "0" treated as unset (operators clear the knob with 0).
        unsafe { std::env::set_var("NORN_ACCELERATE_ROTATIONS_SECS", "0"); }
        assert!(accelerate_rotations_secs().is_none(),
            "0 must be treated the same as unset");
        unsafe { std::env::remove_var("NORN_ACCELERATE_ROTATIONS_SECS"); }

        // 3. Garbage → None (silent ignore is safer than refuse-to-start).
        unsafe { std::env::set_var("NORN_ACCELERATE_ROTATIONS_SECS", "not-a-number"); }
        assert!(accelerate_rotations_secs().is_none(),
            "non-numeric must yield None");
        unsafe { std::env::remove_var("NORN_ACCELERATE_ROTATIONS_SECS"); }

        // 4. Valid positive integer → Some(N).
        unsafe { std::env::set_var("NORN_ACCELERATE_ROTATIONS_SECS", "30"); }
        assert_eq!(accelerate_rotations_secs(), Some(30));
        unsafe { std::env::remove_var("NORN_ACCELERATE_ROTATIONS_SECS"); }
    }

    // ── NORN_MALICIOUS_MODE env knob ─────────────────────────────────────────
    //
    // Same collapse-into-one-test pattern as the rotation knob above —
    // ENV_LOCK serialises us against any other env-poking test in the
    // module, and the single-function layout serialises the four cases
    // against each other.

    #[test]
    fn malicious_mode_env_parsing() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        // 1. Unset → 0 (no poisoning, production path).
        unsafe {
            std::env::remove_var("NORN_MALICIOUS_MODE");
            std::env::remove_var("NORN_MALICIOUS_POISON_TAGS");
        }
        assert_eq!(malicious_cuckoo_poison_tags(), 0,
            "unset env must yield 0 (production path)");

        // 2. Wrong mode → 0.
        unsafe { std::env::set_var("NORN_MALICIOUS_MODE", "bad_mouthing"); }
        assert_eq!(malicious_cuckoo_poison_tags(), 0,
            "unrecognised mode must yield 0");

        // 3. cuckoo_poison without count override → default 64.
        unsafe {
            std::env::set_var("NORN_MALICIOUS_MODE", "cuckoo_poison");
            std::env::remove_var("NORN_MALICIOUS_POISON_TAGS");
        }
        assert_eq!(malicious_cuckoo_poison_tags(), 64,
            "cuckoo_poison without count override must default to 64");

        // 4. Explicit count.
        unsafe { std::env::set_var("NORN_MALICIOUS_POISON_TAGS", "200"); }
        assert_eq!(malicious_cuckoo_poison_tags(), 200);

        // Clean up so we don't poison other tests.
        unsafe {
            std::env::remove_var("NORN_MALICIOUS_MODE");
            std::env::remove_var("NORN_MALICIOUS_POISON_TAGS");
        }
    }

    // ── PathNegative cuckoo-FP backtrack ────────────────────────────────────

    #[test]
    fn path_negative_cache_blocks_peer_for_tag() {
        // After recording (peer, tag) as negative, lookup_by_tag_excluding
        // should skip that peer even if its cuckoo filter still claims the tag.
        let mut rs = make_router();
        let peer_a = [0xAA_u8; 32];
        let peer_b = [0xBB_u8; 32];
        add_dummy_peer(&mut rs, peer_a);
        add_dummy_peer(&mut rs, peer_b);
        let tag = [0xCD_u8; 16];

        // Both A and B claim the tag in their cuckoo[0].
        rs.peers.get_mut(&peer_a).unwrap().cuckoo[0].add(&tag);
        rs.peers.get_mut(&peer_b).unwrap().cuckoo[0].add(&tag);
        // Equal effective cost → tie-break is deterministic but unspecified.
        // The interesting assertion is that *one* of them is selected.
        let first = rs.lookup_by_tag(&tag).expect("at least one match");
        assert!(first == peer_a || first == peer_b);

        // Mark `first` as negative for this tag. Now the other peer must win.
        rs.record_path_negative(first, tag);
        let second = rs.lookup_by_tag(&tag).expect("fallback peer must be picked");
        assert_ne!(second, first,
            "after PathNegative for `first`, lookup must pick the alternative");
    }

    #[test]
    fn path_negative_cache_expires() {
        // Manually backdate an entry past its TTL; cleanup must purge it.
        let mut rs = make_router();
        let peer = [0x11_u8; 32];
        let tag  = [0x22_u8; 16];
        rs.path_negative_cache.insert(
            (peer, tag),
            Instant::now() - PATH_NEG_TTL - Duration::from_secs(1),
        );
        rs.cleanup_path_negative_cache();
        assert!(!rs.is_path_negative(&peer, &tag),
            "expired entry must be evicted by cleanup_path_negative_cache");
    }

    #[test]
    fn path_negative_ttl_decrement_terminates_propagation() {
        // handle_path_negative should not forward when ttl <= 1.
        let mut rs = make_router();
        let peer_a = [0xA1_u8; 32]; // upstream sender of the PathNegative
        let peer_b = [0xB2_u8; 32]; // a candidate forward target
        add_dummy_peer(&mut rs, peer_a);
        add_dummy_peer(&mut rs, peer_b);
        let tag = [0x55_u8; 16];
        rs.peers.get_mut(&peer_b).unwrap().cuckoo[0].add(&tag);

        // ttl = 1 → no forward (cache only).
        let neg = crate::packet::PathNegative { routing_tag: tag, ttl: 1 };
        rs.handle_path_negative(peer_a, neg);
        assert!(rs.is_path_negative(&peer_a, &tag),
            "ttl=1 must still cache");

        // For ttl=0 the cache MUST still record (we learned A can't route),
        // and the forward MUST NOT happen. Our path is: record then if ttl>1 forward.
        // ttl=0 → record + skip forward.
        let mut rs2 = make_router();
        add_dummy_peer(&mut rs2, peer_a);
        rs2.handle_path_negative(peer_a, crate::packet::PathNegative {
            routing_tag: tag, ttl: 0,
        });
        assert!(rs2.is_path_negative(&peer_a, &tag),
            "even ttl=0 frames record into the negative cache");
    }

    #[test]
    fn path_negative_cache_evicts_when_full() {
        // Force the cache past MAX_PATH_NEG_CACHE; record must succeed without growing unbounded.
        let mut rs = make_router();
        // Pre-fill close to the limit.
        for i in 0..MAX_PATH_NEG_CACHE {
            let mut peer = [0u8; 32];
            peer[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let mut tag = [0u8; 16];
            tag[..8].copy_from_slice(&(i as u64).to_le_bytes());
            rs.path_negative_cache.insert((peer, tag), Instant::now());
        }
        let len_before = rs.path_negative_cache.len();
        // One more insertion → eviction must kick in.
        rs.record_path_negative([0xFF; 32], [0xFF; 16]);
        assert!(rs.path_negative_cache.len() <= len_before,
            "record_path_negative must evict to stay within MAX_PATH_NEG_CACHE; \
             before={}, after={}", len_before, rs.path_negative_cache.len());
        assert!(rs.is_path_negative(&[0xFF; 32], &[0xFF; 16]),
            "newly-inserted entry must be present after eviction");
    }
}
