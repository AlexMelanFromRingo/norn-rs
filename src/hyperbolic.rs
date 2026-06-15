//! Hyperbolic coordinate routing on the hyperboloid (Lorentz) model.
//!
//! Each node has a coordinate `(rho, theta)`: `rho` is the radial **hyperbolic
//! distance** from the origin (linear in tree depth), `theta ∈ [0, 2π)` is a
//! key-derived angle. Greedy forwarding picks the neighbour with minimum
//! hyperbolic distance to the destination coordinate.
//!
//! ## Why the hyperboloid model (coordinate format v4)
//!
//! The earlier Poincaré-disk form stored `r = tanh(depth·0.5)`, which **saturates
//! to 1.0 in f64 at depth ≳ 38** (and hit a `1−1e-10` clamp at depth ~24): deep
//! nodes became indistinguishable, and the distance denominator `1 − ū·v`
//! suffered catastrophic cancellation near the boundary. Carrying `rho` (which
//! grows linearly and never saturates) and computing distance on the hyperboloid
//! removes both problems. See `docs/superpowers/specs/2026-06-14-hyperbolic-coords-v4-design.md`.
//!
//! Reference: Kleinberg 2007; Sarkar 2011; Nickel & Kiela 2018 (hyperboloid model).

use std::f64::consts::PI;
use blake2::{Blake2b512, Digest};

/// Radial step per tree-depth level, in hyperbolic units. The Poincaré radius is
/// `r = tanh(rho/2)`; with this step the legacy embedding's `r = tanh(depth·0.5)`
/// corresponds exactly to `rho = depth`.
const RADIAL_STEP: f64 = 1.0;

/// Upper clamp on the radial coordinate. `cosh(RHO_MAX)²` must stay within f64
/// range so the distance computation never overflows to NaN: `cosh(354)² ≈ 6e306
/// < f64::MAX`, so 350 is a safe bound — and ~15× deeper than the legacy ceiling
/// (~24). Beyond this depth distances saturate gracefully (monotone, finite).
const RHO_MAX: f64 = 350.0;

/// Angular-sector shrink factor per tree-depth level for the greedy embedding
/// ([`HypCoord::from_tree_position`]). A node's children occupy an arc of width
/// `2π / ANGULAR_SPREAD^(depth-1)` centred on the parent's angle; deeper subtrees
/// occupy progressively narrower arcs, so distinct subtrees separate angularly
/// and greedy gets a gradient toward a destination's subtree. ~8 models a
/// generous branching factor — large enough that sibling subtrees rarely overlap,
/// small enough that the arc doesn't underflow within realistic depths.
const ANGULAR_SPREAD: f64 = 8.0;

/// A point on the hyperbolic plane in radial form. `rho ≥ 0`, `theta ∈ [0, 2π)`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HypCoord {
    /// Radial hyperbolic distance from the origin. Linear in tree depth; never
    /// saturates (unlike the legacy Poincaré `r`).
    pub rho: f64,
    /// Angle in [0, 2π).
    pub theta: f64,
}

impl HypCoord {
    pub fn origin() -> Self {
        Self { rho: 0.0, theta: 0.0 }
    }

    /// Hyperbolic distance between two points, via the hyperbolic law of cosines
    /// **rewritten to avoid catastrophic cancellation**:
    ///
    /// ```text
    ///   cosh d = cosh ρu cosh ρv − sinh ρu sinh ρv cos Δθ
    ///          = cosh(ρu − ρv) + 2·sinh ρu·sinh ρv·sin²(Δθ/2)
    /// ```
    ///
    /// The second form has no `huge − huge` subtraction: `cosh(ρu−ρv)` is exact
    /// when `ρu ≈ ρv` (the case the old Poincaré formula mangled), and the rest is
    /// a sum of non-negatives. `RHO_MAX` keeps the `sinh·sinh` product finite;
    /// `max(1.0, …)` absorbs sub-ulp rounding so `acosh` stays real (identical
    /// points give exactly 0).
    pub fn distance(self, other: Self) -> f64 {
        let a = self.rho.clamp(0.0, RHO_MAX);
        let b = other.rho.clamp(0.0, RHO_MAX);
        let dtheta = self.theta - other.theta;
        let sin_half = (0.5 * dtheta).sin();
        let cosh_d = (a - b).cosh() + 2.0 * a.sinh() * b.sinh() * sin_half * sin_half;
        cosh_d.max(1.0).acosh()
    }

    /// Encode as 16 bytes: rho as f64 LE + theta as f64 LE.
    pub fn encode(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.rho.to_le_bytes());
        out[8..].copy_from_slice(&self.theta.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8; 16]) -> Self {
        let rho = f64::from_le_bytes(data[..8].try_into().unwrap());
        let theta = f64::from_le_bytes(data[8..].try_into().unwrap());
        // Sanitise non-finite values — NaN/Inf would otherwise propagate through
        // `distance()` and silently poison greedy routing (NaN comparisons are
        // always false, so a NaN-coord node is effectively never closer/farther).
        // Clamp rho to [0, RHO_MAX]: negatives are invalid, and the upper bound
        // keeps the distance math overflow-free.
        let rho = if rho.is_finite() { rho.clamp(0.0, RHO_MAX) } else { 0.0 };
        let theta = if theta.is_finite() {
            // Use rem_euclid for a canonical [0, 2π) result regardless of sign.
            theta.rem_euclid(2.0 * PI)
        } else {
            0.0
        };
        Self { rho, theta }
    }

    /// Deterministic value in `[0, 1]` from an ed25519 public key (first 8 bytes
    /// of BLAKE2b). The per-node angular jitter source for the embedding.
    pub fn hash01(pub_key: &[u8; 32]) -> f64 {
        let hash = Blake2b512::digest(pub_key);
        let val = u64::from_le_bytes(hash[..8].try_into().unwrap());
        val as f64 / u64::MAX as f64
    }

    /// Derive a deterministic θ from an ed25519 public key (legacy v4 embedding).
    pub fn angle_from_key(pub_key: &[u8; 32]) -> f64 {
        Self::hash01(pub_key) * 2.0 * PI
    }

    /// LEGACY (v4) coordinate: `rho` from depth, `theta` a random key-hash angle.
    /// Kept for reference/tests. The random θ has **no relation to tree
    /// position**, so two nodes in the same subtree get unrelated angles —
    /// greedy hyperbolic routing has no gradient and is effectively source-only.
    /// Superseded by [`from_tree_position`].
    pub fn from_tree_depth(depth: u32, pub_key: &[u8; 32]) -> Self {
        let rho = (depth as f64 * RADIAL_STEP).min(RHO_MAX);
        let theta = Self::angle_from_key(pub_key);
        Self { rho, theta }
    }

    /// GREEDY (v5) tree-position embedding. `rho` from depth (as before); `theta`
    /// is the **parent's** θ plus a per-node offset within a depth-shrinking
    /// sector, so a node's descendants cluster in its angular sector. This is
    /// what gives greedy a real gradient: a neighbour geometrically closer to the
    /// destination's coord is closer in tree-position to the destination's
    /// subtree (vs the legacy random angle, which had no such relation).
    ///
    /// - depth 0 (root): the origin (θ irrelevant there).
    /// - depth 1: sector = 2π (the root's children spread around the full circle).
    /// - depth d>1: sector = 2π / `ANGULAR_SPREAD`^(d-1), centred on the parent's θ.
    ///
    /// `parent_theta` is the parent's advertised θ (from its CoordAnnounce); like
    /// `depth`, θ converges as CoordAnnounces propagate down the tree.
    pub fn from_tree_position(depth: u32, parent_theta: f64, pub_key: &[u8; 32]) -> Self {
        if depth == 0 {
            return Self::origin();
        }
        let rho = (depth as f64 * RADIAL_STEP).min(RHO_MAX);
        // Sector width: full circle at depth 1, shrinking by ANGULAR_SPREAD each
        // level deeper. The per-node offset is centred in [-0.5, 0.5]·sector.
        let sector = 2.0 * PI / ANGULAR_SPREAD.powi(depth as i32 - 1);
        let offset = (Self::hash01(pub_key) - 0.5) * sector;
        let theta = (parent_theta + offset).rem_euclid(2.0 * PI);
        Self { rho, theta }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_is_zero() {
        let o = HypCoord::origin();
        assert_eq!(o.rho, 0.0);
        assert_eq!(o.theta, 0.0);
    }

    #[test]
    fn origin_distance_zero() {
        let o = HypCoord::origin();
        assert!(o.distance(o).abs() < 1e-12);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let c = HypCoord { rho: 3.5, theta: 1.23 };
        let d = HypCoord::decode(&c.encode());
        assert!((d.rho - c.rho).abs() < 1e-12);
        assert!((d.theta - c.theta).abs() < 1e-12);
    }

    // ── distance: core metric properties ──────────────────────────────────────

    #[test]
    fn distance_self_is_zero() {
        let a = HypCoord { rho: 7.0, theta: 1.0 };
        assert!(a.distance(a).abs() < 1e-9, "distance to self must be 0");
    }

    #[test]
    fn distance_symmetric() {
        let a = HypCoord { rho: 3.0, theta: 0.5 };
        let b = HypCoord { rho: 7.0, theta: 2.1 };
        assert!((a.distance(b) - b.distance(a)).abs() < 1e-9, "distance not symmetric");
    }

    #[test]
    fn distance_positive_for_distinct_points() {
        let a = HypCoord { rho: 2.0, theta: 0.5 };
        let b = HypCoord { rho: 8.0, theta: 3.0 };
        assert!(a.distance(b) > 0.0);
    }

    #[test]
    fn distance_triangle_inequality() {
        let a = HypCoord { rho: 1.0, theta: 0.0 };
        let b = HypCoord { rho: 5.0, theta: 1.5 };
        let c = HypCoord { rho: 3.0, theta: 3.0 };
        assert!(a.distance(c) <= a.distance(b) + b.distance(c) + 1e-9,
            "triangle inequality violated");
    }

    #[test]
    fn distance_increases_with_rho() {
        let o = HypCoord::origin();
        let near = HypCoord { rho: 3.0, theta: 0.0 };
        let far = HypCoord { rho: 8.0, theta: 0.0 };
        assert!(o.distance(far) > o.distance(near));
    }

    // ── distance: exact references ────────────────────────────────────────────

    /// Distance from the origin to a point equals its radial coordinate — exact
    /// at ANY rho (this is the property that fails under the legacy saturation).
    #[test]
    fn distance_from_origin_equals_rho() {
        for rho in [0.5, 2.0, 10.0, 40.0, 300.0] {
            let p = HypCoord { rho, theta: 1.234 };
            let d = HypCoord::origin().distance(p);
            assert!((d - rho).abs() < 1e-6, "origin→rho={rho}: got {d}");
        }
    }

    /// Cross-check the stable formula against the *naive* hyperbolic law of
    /// cosines (which is accurate at moderate rho, where there is no cancellation).
    #[test]
    fn distance_matches_naive_law_of_cosines() {
        let a = HypCoord { rho: 2.5, theta: 0.7 };
        let b = HypCoord { rho: 1.8, theta: 2.4 };
        let naive = (a.rho.cosh() * b.rho.cosh()
            - a.rho.sinh() * b.rho.sinh() * (a.theta - b.theta).cos())
            .max(1.0)
            .acosh();
        assert!((a.distance(b) - naive).abs() < 1e-9,
            "stable vs naive law of cosines: {} vs {}", a.distance(b), naive);
    }

    // ── the v3 regression: deep nodes must stay distinguishable ───────────────

    #[test]
    fn deep_nodes_are_distinguishable() {
        let key = [9u8; 32];
        let c40 = HypCoord::from_tree_depth(40, &key);
        let c45 = HypCoord::from_tree_depth(45, &key);
        // Radial coordinate tracks depth exactly (v3: both saturated to ~1.0).
        assert!((c40.rho - 40.0).abs() < 1e-9 && (c45.rho - 45.0).abs() < 1e-9);
        // Distance from origin is distinct (v3: both ≈ 23.7, indistinguishable).
        let o = HypCoord::origin();
        let (d40, d45) = (o.distance(c40), o.distance(c45));
        assert!((d40 - 40.0).abs() < 1e-6 && (d45 - 45.0).abs() < 1e-6, "got {d40} {d45}");
        assert!(d45 - d40 > 4.9, "deep nodes must be distinguishable: {d40} vs {d45}");
    }

    // ── numerical robustness near/over the boundary ───────────────────────────

    #[test]
    fn large_rho_distance_finite() {
        // Two far-from-centre nodes close in angle — the catastrophic-cancellation
        // case for the naive/Poincaré forms. Must be finite and positive.
        let a = HypCoord { rho: 300.0, theta: 0.0 };
        let b = HypCoord { rho: 320.0, theta: 1.0e-6 };
        let d = a.distance(b);
        assert!(d.is_finite() && d > 0.0, "large-rho distance must be finite: {d}");
    }

    #[test]
    fn rho_overflow_is_clamped_not_nan() {
        let a = HypCoord { rho: 1e9, theta: 0.0 };
        let b = HypCoord { rho: 1e12, theta: 2.0 };
        assert!(a.distance(b).is_finite(), "huge rho must clamp, not overflow");
        assert!(HypCoord::origin().distance(a).is_finite());
    }

    // ── from_tree_depth ───────────────────────────────────────────────────────

    #[test]
    fn from_tree_depth_root_at_origin() {
        assert_eq!(HypCoord::from_tree_depth(0, &[0u8; 32]).rho, 0.0);
    }

    #[test]
    fn from_tree_depth_rho_equals_depth() {
        let key = [0u8; 32];
        assert!((HypCoord::from_tree_depth(1, &key).rho - 1.0).abs() < 1e-12);
        assert!((HypCoord::from_tree_depth(7, &key).rho - 7.0).abs() < 1e-12);
    }

    #[test]
    fn from_tree_position_root_is_origin_and_rho_tracks_depth() {
        let k = [9u8; 32];
        assert_eq!(HypCoord::from_tree_position(0, 1.0, &k), HypCoord::origin());
        assert!((HypCoord::from_tree_position(4, 0.3, &k).rho - 4.0).abs() < 1e-12);
    }

    #[test]
    fn from_tree_position_clusters_descendants_under_ancestor() {
        // The whole point of the v5 embedding: a descendant clusters in its
        // ancestor's angular sector, so greedy gets a gradient toward a subtree —
        // unlike the legacy random-θ embedding. Build root → A (depth 1) → A1
        // (depth 2) and check A1 is angularly within sector/2 of A, and is closer
        // (hyperbolic distance) to A than to a node on the opposite side.
        let a = [1u8; 32];
        let a1 = [3u8; 32];
        let c_a = HypCoord::from_tree_position(1, 0.0, &a); // root θ = 0
        let c_a1 = HypCoord::from_tree_position(2, c_a.theta, &a1);

        // Clustering: depth-2 sector = 2π/8 = π/4, so the offset is within ±π/8.
        let mut dtheta = (c_a1.theta - c_a.theta).rem_euclid(2.0 * PI);
        if dtheta > PI {
            dtheta = 2.0 * PI - dtheta;
        }
        assert!(dtheta <= PI / 8.0 + 1e-9,
            "depth-2 node must cluster within sector/2 (π/8) of its parent, got {dtheta}");

        // Gradient: A1 is closer to its parent A than to a node π away at depth 1.
        let c_far = HypCoord { rho: 1.0, theta: (c_a.theta + PI).rem_euclid(2.0 * PI) };
        assert!(c_a1.distance(c_a) < c_a1.distance(c_far),
            "descendant must be closer to its ancestor than to a foreign subtree");
    }

    #[test]
    fn from_tree_depth_rho_increases_with_depth() {
        let key = [5u8; 32];
        let c0 = HypCoord::from_tree_depth(0, &key);
        let c1 = HypCoord::from_tree_depth(1, &key);
        let c5 = HypCoord::from_tree_depth(5, &key);
        assert_eq!(c0.rho, 0.0);
        assert!(c1.rho > 0.0 && c5.rho > c1.rho);
    }

    #[test]
    fn from_tree_depth_same_key_same_angle() {
        let key = [7u8; 32];
        let c1 = HypCoord::from_tree_depth(1, &key);
        let c3 = HypCoord::from_tree_depth(3, &key);
        assert!((c1.theta - c3.theta).abs() < 1e-15);
    }

    #[test]
    fn from_tree_depth_clamps_extreme_depth() {
        let c = HypCoord::from_tree_depth(u32::MAX, &[1u8; 32]);
        assert!(c.rho <= RHO_MAX && c.rho.is_finite(), "extreme depth must clamp: {}", c.rho);
    }

    // ── decode: sanitation & clamping ─────────────────────────────────────────

    #[test]
    fn decode_clamps_rho_to_max() {
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&1e9f64.to_le_bytes());
        data[8..].copy_from_slice(&1.0f64.to_le_bytes());
        let c = HypCoord::decode(&data);
        assert!(c.rho <= RHO_MAX && c.rho >= 0.0, "rho must clamp into [0, RHO_MAX], got {}", c.rho);
    }

    #[test]
    fn decode_negative_rho_clamped_nonneg() {
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&(-5.0f64).to_le_bytes());
        data[8..].copy_from_slice(&1.0f64.to_le_bytes());
        assert!(HypCoord::decode(&data).rho >= 0.0, "negative rho must clamp to 0");
    }

    #[test]
    fn decode_sanitizes_non_finite() {
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&f64::NAN.to_le_bytes());
        data[8..].copy_from_slice(&f64::INFINITY.to_le_bytes());
        let c = HypCoord::decode(&data);
        assert!(c.rho.is_finite() && c.theta.is_finite(), "non-finite must be sanitised");
    }

    #[test]
    fn decode_theta_wraps_into_range() {
        // 5.5 is < 2π so survives; verifies rem_euclid uses 2π (not e.g. 2+π).
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&2.0f64.to_le_bytes());
        bytes[8..].copy_from_slice(&5.5f64.to_le_bytes());
        assert!((HypCoord::decode(&bytes).theta - 5.5).abs() < 1e-12);
    }

    // ── angle_from_key (unchanged from v3) ────────────────────────────────────

    #[test]
    fn angle_from_key_in_range() {
        assert!((0.0..2.0 * PI).contains(&HypCoord::angle_from_key(&[0u8; 32])));
    }

    #[test]
    fn angle_from_key_deterministic() {
        assert_eq!(HypCoord::angle_from_key(&[42u8; 32]), HypCoord::angle_from_key(&[42u8; 32]));
    }

    #[test]
    fn angle_from_key_different_keys() {
        assert_ne!(HypCoord::angle_from_key(&[1u8; 32]), HypCoord::angle_from_key(&[2u8; 32]));
    }

    #[test]
    fn angle_from_key_pinned_exact_value() {
        let key = [0x42u8; 32];
        let hash = Blake2b512::digest(key);
        let val = u64::from_le_bytes(hash[..8].try_into().unwrap());
        let expected = (val as f64 / u64::MAX as f64) * 2.0 * PI;
        let got = HypCoord::angle_from_key(&key);
        assert!((got - expected).abs() < 1e-12,
            "angle_from_key must use (val/u64::MAX)*2π: got {got}, expected {expected}");
    }
}
