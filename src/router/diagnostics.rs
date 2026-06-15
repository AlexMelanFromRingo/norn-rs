//! Diagnostic / test-env knobs and process-wide metric counters, split from
//! router/mod.rs. All items are pub and re-exported at the router root, so
//! external paths (crate::router::*) are unchanged.

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

/// Roadmap #9: count of periodic control broadcasts actually sent, and
/// of maintenance ticks where the broadcast was suppressed because the
/// topology was unchanged. The ratio quantifies the chatter reduction;
/// both are surfaced in `/metrics` as `norn_control_broadcasts_total`
/// and `norn_control_suppressed_total`.
pub static CONTROL_BROADCASTS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
pub static CONTROL_SUPPRESSED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Convergence instrumentation (B-step-3 §5). `TREE_PARENT_CHANGES` counts every
/// actual parent-pointer switch in `fix_tree` — a *settled* topology should stop
/// incrementing it; continued growth = parent flapping (the count-to-∞ window
/// cause). `CUCKOO_NO_ROUTE` counts transit "no route" events. Surfaced as
/// `norn_tree_parent_changes_total` / `norn_cuckoo_no_route_total`.
pub static TREE_PARENT_CHANGES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
pub static CUCKOO_NO_ROUTE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Snapshot of the convergence counters `(parent_changes, no_route)` for the
/// Prometheus exposition.
pub fn convergence_counts() -> (u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (TREE_PARENT_CHANGES.load(Relaxed), CUCKOO_NO_ROUTE.load(Relaxed))
}

/// Snapshot of the control-broadcast counters `(sent, suppressed)` for
/// the Prometheus exposition.
pub fn control_broadcast_counts() -> (u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (CONTROL_BROADCASTS.load(Relaxed), CONTROL_SUPPRESSED.load(Relaxed))
}

/// Per-message-type TX byte accounting. `send_to_peer` classifies every frame
/// by its leading type byte and adds its length here, so `/metrics` can show
/// exactly where a node's egress bandwidth goes (`norn_tx_bytes_by_type`).
/// Diagnostic only — answers "which message type dominates the gossip volume?".
pub static TX_BYTES_BY_TYPE: [std::sync::atomic::AtomicU64; 13] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 13];

/// Human-readable bucket names, indexed by `tx_type_slot`.
pub const TX_TYPE_NAMES: [&str; 13] = [
    "sig", "announce", "cuckoo", "pathfind", "traffic", "coord", "onion",
    "onionkey", "reputation", "holepunch", "pathneg", "capabilities", "other",
];

/// Map a frame's leading type byte (see packet.rs constants) to a bucket index.
fn tx_type_slot(first_byte: u8) -> usize {
    match first_byte {
        2 | 3 => 0,   // SIG_REQ / SIG_RES
        4 => 1,       // ANNOUNCE
        5 => 2,       // CUCKOO_FILTER
        6..=8 => 3,   // PATH_LOOKUP / NOTIFY / BROKEN
        9 => 4,       // TRAFFIC
        10 => 5,      // COORD_ANNOUNCE
        11 => 6,      // ONION
        12 => 7,      // ONION_KEY_ANNOUNCE
        13 => 8,      // REPUTATION_REPORT
        14 => 9,      // HOLE_PUNCH
        15 => 10,     // PATH_NEGATIVE
        0x11 => 11,   // CAPABILITIES
        _ => 12,      // other / unknown
    }
}

/// Record `len` bytes sent for a frame whose first byte is `first_byte`.
pub fn record_tx_bytes(first_byte: u8, len: u64) {
    TX_BYTES_BY_TYPE[tx_type_slot(first_byte)]
        .fetch_add(len, std::sync::atomic::Ordering::Relaxed);
}

/// Snapshot of `(type_name, bytes)` for every bucket, for the exposition.
pub fn tx_bytes_by_type() -> Vec<(&'static str, u64)> {
    use std::sync::atomic::Ordering::Relaxed;
    TX_TYPE_NAMES
        .iter()
        .enumerate()
        .map(|(i, n)| (*n, TX_BYTES_BY_TYPE[i].load(Relaxed)))
        .collect()
}
