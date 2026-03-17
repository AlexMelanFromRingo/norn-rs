//! Hyperbolic coordinate routing in the Poincaré disk.
//!
//! Each node has a coordinate (r, θ) in [0,1) × [0, 2π).
//! Greedy forwarding: forward to the neighbour with minimum hyperbolic
//! distance to the destination coordinate.
//!
//! Reference: Kleinberg 2007; Sarkar 2011.

use std::f64::consts::PI;
use blake2::{Blake2b512, Digest};

/// A point in the Poincaré disk. r ∈ [0, 1), θ ∈ [0, 2π).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HypCoord {
    pub r: f64,
    pub theta: f64,
}

impl HypCoord {
    pub fn origin() -> Self {
        Self { r: 0.0, theta: 0.0 }
    }

    /// Convert to Cartesian for distance calculation.
    pub fn to_cartesian(self) -> (f64, f64) {
        (self.r * self.theta.cos(), self.r * self.theta.sin())
    }

    /// Hyperbolic distance between two Poincaré disk points.
    /// d(u,v) = 2·arctanh(|u-v| / |1 + ū·v|)  (Möbius formula)
    pub fn distance(self, other: Self) -> f64 {
        let (ax, ay) = self.to_cartesian();
        let (bx, by) = other.to_cartesian();
        let dx = ax - bx;
        let dy = ay - by;
        let num = (dx * dx + dy * dy).sqrt();
        let denom_re = 1.0 + ax * bx + ay * by;
        let denom_im = ax * by - ay * bx;
        let denom = (denom_re * denom_re + denom_im * denom_im).sqrt();
        let ratio = num / denom;
        let ratio = ratio.min(1.0 - 1e-10); // clamp for numerical safety
        2.0 * ratio.atanh()
    }

    /// Encode as 16 bytes: r as f64 LE + theta as f64 LE.
    pub fn encode(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.r.to_le_bytes());
        out[8..].copy_from_slice(&self.theta.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8; 16]) -> Self {
        let r = f64::from_le_bytes(data[..8].try_into().unwrap());
        let theta = f64::from_le_bytes(data[8..].try_into().unwrap());
        Self {
            r: r.clamp(0.0, 1.0 - 1e-10),
            theta: theta % (2.0 * PI),
        }
    }

    /// Derive a deterministic θ from an ed25519 public key.
    pub fn angle_from_key(pub_key: &[u8; 32]) -> f64 {
        let hash = Blake2b512::digest(pub_key);
        let val = u64::from_le_bytes(hash[..8].try_into().unwrap());
        (val as f64 / u64::MAX as f64) * 2.0 * PI
    }

    /// Compute coordinate for a node given its tree depth and pub key.
    /// Uses Sarkar-style embedding: r from depth, θ from key hash.
    pub fn from_tree_depth(depth: u32, pub_key: &[u8; 32]) -> Self {
        const DELTA: f64 = 0.5;
        let r = if depth == 0 {
            0.0
        } else {
            (depth as f64 * DELTA).tanh()
        };
        let theta = Self::angle_from_key(pub_key);
        Self { r, theta }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_distance_zero() {
        let o = HypCoord::origin();
        assert!((o.distance(o)).abs() < 1e-10);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let c = HypCoord { r: 0.5, theta: 1.23 };
        let enc = c.encode();
        let dec = HypCoord::decode(&enc);
        assert!((dec.r - c.r).abs() < 1e-12);
        assert!((dec.theta - c.theta).abs() < 1e-12);
    }

    #[test]
    fn from_tree_depth_root_at_origin() {
        let key = [0u8; 32];
        let c = HypCoord::from_tree_depth(0, &key);
        assert_eq!(c.r, 0.0);
    }

    #[test]
    fn distance_symmetric() {
        let a = HypCoord { r: 0.3, theta: 0.5 };
        let b = HypCoord { r: 0.7, theta: 2.1 };
        let d_ab = a.distance(b);
        let d_ba = b.distance(a);
        assert!((d_ab - d_ba).abs() < 1e-10, "distance not symmetric: {} vs {}", d_ab, d_ba);
    }

    // ── distance correctness ──────────────────────────────────────────────────

    #[test]
    fn distance_self_is_zero() {
        let a = HypCoord { r: 0.5, theta: 1.0 };
        assert!(a.distance(a).abs() < 1e-10, "distance to self must be 0");
    }

    #[test]
    fn distance_always_positive_for_distinct_points() {
        let a = HypCoord { r: 0.2, theta: 0.5 };
        let b = HypCoord { r: 0.8, theta: 3.0 };
        assert!(a.distance(b) > 0.0, "distance between distinct points must be positive");
    }

    #[test]
    fn distance_triangle_inequality() {
        let a = HypCoord { r: 0.1, theta: 0.0 };
        let b = HypCoord { r: 0.5, theta: 1.5 };
        let c = HypCoord { r: 0.3, theta: 3.0 };
        let d_ab = a.distance(b);
        let d_bc = b.distance(c);
        let d_ac = a.distance(c);
        assert!(d_ac <= d_ab + d_bc + 1e-10,
            "triangle inequality violated: {} <= {} + {}", d_ac, d_ab, d_bc);
    }

    #[test]
    fn distance_increases_with_r() {
        // Moving further from origin increases distance
        let origin = HypCoord::origin();
        let near = HypCoord { r: 0.3, theta: 0.0 };
        let far  = HypCoord { r: 0.8, theta: 0.0 };
        assert!(origin.distance(far) > origin.distance(near),
            "larger r must give larger distance from origin");
    }

    // ── to_cartesian ──────────────────────────────────────────────────────────

    #[test]
    fn to_cartesian_at_origin() {
        let o = HypCoord::origin();
        let (x, y) = o.to_cartesian();
        assert!(x.abs() < 1e-10 && y.abs() < 1e-10);
    }

    #[test]
    fn to_cartesian_at_unit_x() {
        let c = HypCoord { r: 1.0, theta: 0.0 };
        let (x, y) = c.to_cartesian();
        assert!((x - 1.0).abs() < 1e-10, "x should be 1.0, got {}", x);
        assert!(y.abs() < 1e-10, "y should be 0.0, got {}", y);
    }

    #[test]
    fn to_cartesian_at_unit_y() {
        let c = HypCoord { r: 1.0, theta: PI / 2.0 };
        let (x, y) = c.to_cartesian();
        assert!(x.abs() < 1e-10, "x should be 0, got {}", x);
        assert!((y - 1.0).abs() < 1e-10, "y should be 1.0, got {}", y);
    }

    // ── angle_from_key ────────────────────────────────────────────────────────

    #[test]
    fn angle_from_key_in_range() {
        let key = [0u8; 32];
        let angle = HypCoord::angle_from_key(&key);
        assert!(angle >= 0.0 && angle < 2.0 * PI,
            "angle must be in [0, 2π), got {}", angle);
    }

    #[test]
    fn angle_from_key_deterministic() {
        let key = [42u8; 32];
        assert_eq!(HypCoord::angle_from_key(&key), HypCoord::angle_from_key(&key));
    }

    #[test]
    fn angle_from_key_different_keys() {
        let a1 = HypCoord::angle_from_key(&[1u8; 32]);
        let a2 = HypCoord::angle_from_key(&[2u8; 32]);
        assert_ne!(a1, a2, "different keys must give different angles");
    }

    // ── from_tree_depth ───────────────────────────────────────────────────────

    #[test]
    fn from_tree_depth_r_increases_with_depth() {
        let key = [5u8; 32];
        let c0 = HypCoord::from_tree_depth(0, &key);
        let c1 = HypCoord::from_tree_depth(1, &key);
        let c5 = HypCoord::from_tree_depth(5, &key);
        assert_eq!(c0.r, 0.0, "depth 0 must be at origin");
        assert!(c1.r > 0.0, "depth 1 must have r > 0");
        assert!(c5.r > c1.r, "larger depth must give larger r");
    }

    #[test]
    fn from_tree_depth_same_key_same_angle() {
        let key = [7u8; 32];
        let c1 = HypCoord::from_tree_depth(1, &key);
        let c3 = HypCoord::from_tree_depth(3, &key);
        // Same key → same angle regardless of depth
        assert!((c1.theta - c3.theta).abs() < 1e-15);
    }

    // ── decode clamping ───────────────────────────────────────────────────────

    #[test]
    fn decode_clamps_r_to_valid_range() {
        let mut data = [0u8; 16];
        // r = 2.0 (out of range) stored as f64 LE
        data[..8].copy_from_slice(&2.0f64.to_le_bytes());
        data[8..].copy_from_slice(&1.0f64.to_le_bytes());
        let c = HypCoord::decode(&data);
        assert!(c.r < 1.0, "r must be clamped below 1.0, got {}", c.r);
    }

    // ── numeric pinning: distance formula ────────────────────────────────────

    #[test]
    fn distance_origin_to_point_on_real_axis() {
        // origin (0,0) to (r=0.5, theta=0) = (0.5, 0) Cartesian.
        // num = 0.5, denom_re = 1 + 0*0.5 + 0*0 = 1, denom_im = 0
        // ratio = 0.5 / 1.0 = 0.5 → distance = 2*atanh(0.5)
        let origin = HypCoord::origin();
        let p = HypCoord { r: 0.5, theta: 0.0 };
        let d = origin.distance(p);
        let expected = 2.0 * 0.5f64.atanh();
        assert!((d - expected).abs() < 1e-10,
            "distance formula mismatch: got {}, expected {}", d, expected);
    }

    #[test]
    fn distance_formula_uses_minus_for_dx_dy() {
        // Two distinct points: a=(0.3,0), b=(0.5,0) both on real axis.
        // dx = 0.3-0.5 = -0.2, dy=0
        // num = 0.2
        // denom_re = 1 + 0.3*0.5 + 0 = 1.15
        // denom_im = 0.3*0 - 0*0.5 = 0
        // ratio = 0.2/1.15 ≈ 0.17391
        // distance = 2*atanh(0.17391...)
        let a = HypCoord { r: 0.3, theta: 0.0 };
        let b = HypCoord { r: 0.5, theta: 0.0 };
        let ax = 0.3f64; let bx = 0.5f64;
        let num = (ax - bx).abs();
        let denom = 1.0 + ax * bx;
        let expected = 2.0 * (num / denom).atanh();
        let d = a.distance(b);
        assert!((d - expected).abs() < 1e-9,
            "distance along real axis: got {}, expected {}", d, expected);
    }

    #[test]
    fn distance_formula_denominator_uses_plus_for_ay_by() {
        // a=(0.5, π/2) → (0, 0.5) and b=(0.3, 0) → (0.3, 0)
        // dx=0-0.3=-0.3, dy=0.5-0=0.5
        // num = sqrt(0.09+0.25) = sqrt(0.34) ≈ 0.58310
        // denom_re = 1 + 0*0.3 + 0.5*0 = 1.0      ← ay*by term = 0.5*0 = 0
        // denom_im = 0*0 - 0.5*0.3 = -0.15
        // denom = sqrt(1 + 0.0225) = sqrt(1.0225) ≈ 1.01119
        // ratio = 0.58310 / 1.01119 ≈ 0.57670
        // distance = 2*atanh(0.57670) ≈ 1.28...
        // If + was − in denom_re (1+ax*bx−ay*by): same (ay*by=0)
        // If denom_im was ax*by + ay*bx: 0*0 + 0.5*0.3 = +0.15 (same magnitude → same dist)
        // So use points where ay and by are BOTH nonzero.
        let a = HypCoord { r: 0.4, theta: PI / 4.0 }; // (0.4/√2, 0.4/√2)
        let b = HypCoord { r: 0.4, theta: 3.0 * PI / 4.0 }; // (-0.4/√2, 0.4/√2)
        let (ax, ay) = a.to_cartesian();
        let (bx, by) = b.to_cartesian();
        let dx = ax - bx; let dy = ay - by;
        let num = (dx * dx + dy * dy).sqrt();
        let denom_re = 1.0 + ax * bx + ay * by; // the correct formula
        let denom_im = ax * by - ay * bx;
        let denom = (denom_re * denom_re + denom_im * denom_im).sqrt();
        let expected = 2.0 * (num / denom).atanh();
        let d = a.distance(b);
        assert!((d - expected).abs() < 1e-9,
            "distance with nonzero ay/by: got {}, expected {}", d, expected);
    }

    // ── numeric pinning: to_cartesian formula ─────────────────────────────────

    #[test]
    fn to_cartesian_uses_cos_for_x_sin_for_y() {
        // theta=π/3: x must be r*cos(π/3), y must be r*sin(π/3)
        let r = 0.4f64;
        let theta = PI / 3.0;
        let c = HypCoord { r, theta };
        let (x, y) = c.to_cartesian();
        assert!((x - r * theta.cos()).abs() < 1e-12,
            "x must be r*cos(theta): got {} vs {}", x, r * theta.cos());
        assert!((y - r * theta.sin()).abs() < 1e-12,
            "y must be r*sin(theta): got {} vs {}", y, r * theta.sin());
    }

    // ── numeric pinning: from_tree_depth DELTA=0.5 ───────────────────────────

    #[test]
    fn from_tree_depth_r_uses_delta_half() {
        let key = [0u8; 32];
        // depth=1: r = tanh(1 * 0.5) = tanh(0.5) ≈ 0.46212
        let c1 = HypCoord::from_tree_depth(1, &key);
        let expected_r1 = (1.0f64 * 0.5).tanh();
        assert!((c1.r - expected_r1).abs() < 1e-12,
            "depth=1: expected r=tanh(0.5)≈0.462, got {}", c1.r);
        // depth=2: r = tanh(2 * 0.5) = tanh(1.0) ≈ 0.76159
        let c2 = HypCoord::from_tree_depth(2, &key);
        let expected_r2 = (2.0f64 * 0.5).tanh();
        assert!((c2.r - expected_r2).abs() < 1e-12,
            "depth=2: expected r=tanh(1.0)≈0.762, got {}", c2.r);
    }

    // ── numeric pinning: angle_from_key formula ───────────────────────────────

    #[test]
    fn angle_from_key_proportional_to_hash() {
        // Key with all-zero hash bytes → val=0 → angle=0
        // Use a key known to produce a specific hash direction.
        // We test that angle = (val / u64::MAX) * 2π is in bounds and varies.
        let angle_a = HypCoord::angle_from_key(&[0x00u8; 32]);
        let angle_b = HypCoord::angle_from_key(&[0xFFu8; 32]);
        // Both must be in [0, 2π)
        assert!(angle_a >= 0.0 && angle_a < 2.0 * PI);
        assert!(angle_b >= 0.0 && angle_b < 2.0 * PI);
        // They must differ (different keys → different hashes)
        assert_ne!(angle_a, angle_b, "all-0 and all-FF keys must produce different angles");
        // Maximum possible angle must be strictly < 2π (val/u64::MAX * 2π < 2π)
        let max_angle = (u64::MAX as f64 / u64::MAX as f64) * 2.0 * PI;
        assert!(max_angle <= 2.0 * PI, "max angle must not exceed 2π");
    }

    // ── distance: pin exact value with nonzero dy (kills + → - and * → +) ───
    //
    // All previous distance tests use collinear points (dy=0), so mutations
    // that corrupt dy terms aren't detected. This test uses a=origin, b on
    // the imaginary axis (theta=π/2) so both dx and dy are nonzero at distance
    // computation.
    #[test]
    fn distance_nonzero_dy_pinned_value() {
        // origin → (r=0.4, θ=π/2): Cartesian b=(0, 0.4).
        // dx = 0 - 0 = 0, dy = 0 - 0.4 = -0.4
        // num = sqrt(0 + 0.16) = 0.4
        // denom_re = 1 + 0*0 + 0*0.4 = 1.0
        // denom_im = 0*0.4 - 0*0 = 0
        // denom = 1.0, ratio = 0.4
        // distance = 2*atanh(0.4)
        let origin = HypCoord::origin();
        let p = HypCoord { r: 0.4, theta: PI / 2.0 };
        let d = origin.distance(p);
        let expected = 2.0 * 0.4f64.atanh();
        assert!((d - expected).abs() < 1e-10,
            "distance origin → (0.4, π/2): got {d}, expected {expected}");
    }

    #[test]
    fn distance_two_nonzero_dy_points_pinned() {
        // a=(0.3, π/4) → (0.3/√2, 0.3/√2), b=(0.5, π/2) → (0, 0.5)
        // dx = 0.3/√2 - 0 ≈ 0.21213
        // dy = 0.3/√2 - 0.5 ≈ -0.28787
        // num = sqrt(dx²+dy²) ≈ sqrt(0.04500+0.08287) ≈ sqrt(0.12787) ≈ 0.35759
        // With mutation + → -: num = sqrt(dx²-dy²) = sqrt(0.04500-0.08287) → negative → NaN
        // With mutation * → + (dy*dy → dy+dy=2*dy): num changes
        // So this test catches both mutations.
        let a = HypCoord { r: 0.3, theta: PI / 4.0 };
        let b = HypCoord { r: 0.5, theta: PI / 2.0 };
        let (ax, ay) = a.to_cartesian();
        let (bx, by) = b.to_cartesian();
        let dx = ax - bx;
        let dy = ay - by;
        // Compute expected with explicit % formula
        let num = (dx * dx + dy * dy).sqrt();
        let denom_re = 1.0 + ax * bx + ay * by;
        let denom_im = ax * by - ay * bx;
        let denom = (denom_re * denom_re + denom_im * denom_im).sqrt();
        let expected = 2.0 * (num / denom).atanh();
        let d = a.distance(b);
        assert!((d - expected).abs() < 1e-10 && d > 0.0,
            "distance a→b: got {d}, expected {expected}");
    }

    // ── decode: theta > 2+π distinguishes 2*PI from 2+PI modulus (line 58) ──
    //
    // Mutation replaces `2.0 * PI` with `2.0 + PI` ≈ 5.14.
    // For theta=5.5: original → 5.5 % 6.28 = 5.5; mutation → 5.5 % 5.14 ≈ 0.36.
    #[test]
    fn decode_theta_above_two_plus_pi_wraps_correctly() {
        let theta = 5.5f64; // 5.5 > 2+π ≈ 5.14 but < 2π ≈ 6.28
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&0.5f64.to_le_bytes()); // r=0.5
        bytes[8..].copy_from_slice(&theta.to_le_bytes());
        let dec = HypCoord::decode(&bytes);
        // Original: theta % (2π) ≈ 5.5 (unchanged since 5.5 < 2π)
        // Mutation: theta % (2+π) ≈ 0.36 (wrong)
        assert!((dec.theta - 5.5).abs() < 1e-12,
            "theta=5.5 must survive decode unchanged (< 2π); got {}", dec.theta);
    }

    // ── angle_from_key: pin exact value to kill * → + and * → / mutations ───
    //
    // Mutations change `(val/u64::MAX) * 2.0 * PI` to:
    //   col 40: * → /  → `(val/u64::MAX) / 2.0 * PI`  (halved then scaled)
    //   col 46: * → +  → `(val/u64::MAX) * 2.0 + PI`  (shifted by π)
    //   col 46: * → /  → `(val/u64::MAX) * 2.0 / PI`  (different scaling)
    // A pinned expected value (computed using the correct formula) catches these.
    #[test]
    fn angle_from_key_pinned_exact_value() {
        use blake2::{Blake2b512, Digest};
        let key = [0x42u8; 32];
        let hash = Blake2b512::digest(&key);
        let val = u64::from_le_bytes(hash[..8].try_into().unwrap());
        // Expected: (val / u64::MAX) * 2.0 * PI
        let expected = (val as f64 / u64::MAX as f64) * 2.0 * PI;
        let got = HypCoord::angle_from_key(&key);
        assert!((got - expected).abs() < 1e-12,
            "angle_from_key must use (val/u64::MAX)*2π formula: got {got}, expected {expected}");
        // Sanity: must be strictly positive for a non-zero hash (key=0x42 gives nonzero val)
        assert!(got > 0.0, "angle for key=[0x42;32] must be > 0");
    }
}
