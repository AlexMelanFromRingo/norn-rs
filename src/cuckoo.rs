// Cuckoo filter implementation for norn-rs
// 512 buckets × 4 slots × 2-byte fingerprint = 4096 bytes
// FPR ≈ 2×4 / 2^16 ≈ 0.012% (vs 0.78% with 1-byte fingerprints)

use blake2::{Blake2b, Digest};
use blake2::digest::consts::U8;
use rand::Rng;

const NUM_BUCKETS: usize = 512;
const SLOTS_PER_BUCKET: usize = 4;
const MAX_KICKS: usize = 500;

/// Wire size of the encoded filter (bytes).
pub const FILTER_BYTES: usize = NUM_BUCKETS * SLOTS_PER_BUCKET * 2; // 4096

/// Cuckoo filter — 512 buckets, 4 slots, 2-byte fingerprints.
/// FPR ≈ 0.012%, wire size 4096 bytes.
#[derive(Clone)]
pub struct CuckooFilter {
    buckets: [[u16; SLOTS_PER_BUCKET]; NUM_BUCKETS],
    count: usize,
}

impl CuckooFilter {
    pub fn new() -> Self {
        CuckooFilter {
            buckets: [[0u16; SLOTS_PER_BUCKET]; NUM_BUCKETS],
            count: 0,
        }
    }

    /// Compute 2-byte fingerprint. Zero means empty slot, so map 0 → 1.
    fn fingerprint(key: &[u8]) -> u16 {
        let mut h: Blake2b<U8> = Blake2b::new();
        h.update(key);
        let result = h.finalize();
        let fp = u16::from_le_bytes([result[0], result[1]]);
        if fp == 0 { 1 } else { fp }
    }

    fn bucket1(key: &[u8]) -> usize {
        let mut h: Blake2b<U8> = Blake2b::new();
        h.update(b"b1");
        h.update(key);
        let result = h.finalize();
        let v = u64::from_le_bytes(result[..8].try_into().unwrap());
        (v as usize) % NUM_BUCKETS
    }

    fn bucket2(b1: usize, fp: u16) -> usize {
        let mut h: Blake2b<U8> = Blake2b::new();
        h.update(b"b2");
        h.update(fp.to_le_bytes());
        let result = h.finalize();
        let v = u64::from_le_bytes(result[..8].try_into().unwrap());
        let offset = (v as usize) % NUM_BUCKETS;
        (b1 ^ offset) % NUM_BUCKETS
    }

    fn insert_slot(bucket: &mut [u16; SLOTS_PER_BUCKET], fp: u16) -> bool {
        for slot in bucket.iter_mut() {
            if *slot == 0 {
                *slot = fp;
                return true;
            }
        }
        false
    }

    fn remove_slot(bucket: &mut [u16; SLOTS_PER_BUCKET], fp: u16) -> bool {
        for slot in bucket.iter_mut() {
            if *slot == fp {
                *slot = 0;
                return true;
            }
        }
        false
    }

    fn contains_slot(bucket: &[u16; SLOTS_PER_BUCKET], fp: u16) -> bool {
        bucket.contains(&fp)
    }

    pub fn add(&mut self, key: &[u8]) -> bool {
        let fp = Self::fingerprint(key);
        let b1 = Self::bucket1(key);
        let b2 = Self::bucket2(b1, fp);

        if Self::insert_slot(&mut self.buckets[b1], fp) {
            self.count += 1;
            return true;
        }
        if Self::insert_slot(&mut self.buckets[b2], fp) {
            self.count += 1;
            return true;
        }

        let mut rng = rand::thread_rng();
        let mut cur_bucket = if rng.gen_bool(0.5) { b1 } else { b2 };
        let mut cur_fp = fp;

        for _ in 0..MAX_KICKS {
            let slot_idx = rng.gen_range(0..SLOTS_PER_BUCKET);
            std::mem::swap(&mut self.buckets[cur_bucket][slot_idx], &mut cur_fp);
            let alt = Self::bucket2(cur_bucket, cur_fp);
            cur_bucket = alt;
            if Self::insert_slot(&mut self.buckets[cur_bucket], cur_fp) {
                self.count += 1;
                return true;
            }
        }
        false
    }

    pub fn remove(&mut self, key: &[u8]) -> bool {
        let fp = Self::fingerprint(key);
        let b1 = Self::bucket1(key);
        let b2 = Self::bucket2(b1, fp);
        if Self::remove_slot(&mut self.buckets[b1], fp) {
            self.count -= 1;
            return true;
        }
        if Self::remove_slot(&mut self.buckets[b2], fp) {
            self.count -= 1;
            return true;
        }
        false
    }

    pub fn contains(&self, key: &[u8]) -> bool {
        let fp = Self::fingerprint(key);
        let b1 = Self::bucket1(key);
        let b2 = Self::bucket2(b1, fp);
        Self::contains_slot(&self.buckets[b1], fp)
            || Self::contains_slot(&self.buckets[b2], fp)
    }

    /// Encode to 4096-byte flat array (2 bytes per slot, little-endian).
    pub fn encode(&self) -> [u8; FILTER_BYTES] {
        let mut out = [0u8; FILTER_BYTES];
        for (i, bucket) in self.buckets.iter().enumerate() {
            for (j, &slot) in bucket.iter().enumerate() {
                let off = (i * SLOTS_PER_BUCKET + j) * 2;
                out[off..off + 2].copy_from_slice(&slot.to_le_bytes());
            }
        }
        out
    }

    pub fn decode(data: &[u8; FILTER_BYTES]) -> Self {
        let mut f = CuckooFilter::new();
        let mut count = 0;
        for i in 0..NUM_BUCKETS {
            for j in 0..SLOTS_PER_BUCKET {
                let off = (i * SLOTS_PER_BUCKET + j) * 2;
                let v = u16::from_le_bytes(data[off..off + 2].try_into().unwrap());
                f.buckets[i][j] = v;
                if v != 0 { count += 1; }
            }
        }
        f.count = count;
        f
    }

    /// OR-merge: union of two filters.
    pub fn merge(&mut self, other: &CuckooFilter) {
        for i in 0..NUM_BUCKETS {
            for j in 0..SLOTS_PER_BUCKET {
                let other_fp = other.buckets[i][j];
                if other_fp != 0 && self.buckets[i][j] == 0 {
                    self.buckets[i][j] = other_fp;
                    self.count += 1;
                }
            }
        }
    }

    pub fn count(&self) -> usize { self.count }
}

impl Default for CuckooFilter {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_remove_contains() {
        let mut cf = CuckooFilter::new();
        assert!(!cf.contains(b"hello"));
        assert!(cf.add(b"hello"));
        assert!(cf.contains(b"hello"));
        assert!(cf.remove(b"hello"));
        assert!(!cf.contains(b"hello"));
    }

    #[test]
    fn multiple_items() {
        let mut cf = CuckooFilter::new();
        let keys: Vec<Vec<u8>> = (0u32..100).map(|i| i.to_le_bytes().to_vec()).collect();
        for k in &keys { assert!(cf.add(k)); }
        for k in &keys { assert!(cf.contains(k), "should contain {:?}", k); }
        for k in &keys[..50] { assert!(cf.remove(k)); }
        for k in &keys[..50] { assert!(!cf.contains(k)); }
        for k in &keys[50..] { assert!(cf.contains(k)); }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut cf = CuckooFilter::new();
        for i in 0u32..50 { cf.add(&i.to_le_bytes()); }
        let encoded = cf.encode();
        let decoded = CuckooFilter::decode(&encoded);
        for i in 0u32..50 {
            assert!(decoded.contains(&i.to_le_bytes()), "decoded missing {}", i);
        }
    }

    #[test]
    fn fpr_test() {
        let mut cf = CuckooFilter::new();
        let keys: Vec<Vec<u8>> = (0u32..100)
            .map(|i| format!("key_{}", i).into_bytes())
            .collect();
        for k in &keys { cf.add(k); }
        let mut fp = 0;
        for i in 0u32..10_000 {
            if cf.contains(&format!("query_{}", i).into_bytes()) { fp += 1; }
        }
        let fpr = fp as f64 / 10_000.0;
        // With 2-byte fingerprints FPR should be well under 1%
        assert!(fpr < 0.01, "FPR too high: {:.4}", fpr);
    }

    #[test]
    fn merge_test() {
        let mut cf1 = CuckooFilter::new();
        let mut cf2 = CuckooFilter::new();
        cf1.add(b"key_a");
        cf2.add(b"key_b");
        cf1.merge(&cf2);
        assert!(cf1.contains(b"key_a"));
        assert!(cf1.contains(b"key_b"));
    }
}
