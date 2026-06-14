//! Cost & tree-root metric functions, split from router/mod.rs.
use super::*;

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
/// angle evaluation may differ in the last bit). Used by handle_coord_announce
/// to validate that a peer's claimed coord matches the deterministic formula.
pub(crate) fn coords_approx_equal(a: &HypCoord, b: &HypCoord) -> bool {
    let dr = (a.rho - b.rho).abs();
    let dt = (a.theta - b.theta).abs();
    dr < 1e-9 && dt < 1e-9
}

/// Constant-time equality on routing tags. The leak is minor (an attacker
/// would have to time forwarding decisions under 50ms jitter) but the cost
/// is zero, so this is defence in depth.
#[inline]
pub(crate) fn routing_tag_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
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
pub(crate) fn metric_less(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a < b
}
