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
}
