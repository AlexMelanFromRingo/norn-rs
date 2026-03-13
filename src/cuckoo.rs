// Cuckoo filter implementation for norn-rs
// 512 buckets × 4 slots per bucket × 1 byte fingerprint = 2048 bytes
// FPR ≈ 0.78%

use blake2::{Blake2b, Digest};
use blake2::digest::consts::U8;
use rand::Rng;

const NUM_BUCKETS: usize = 512;
const SLOTS_PER_BUCKET: usize = 4;
const MAX_KICKS: usize = 500;

/// Cuckoo filter with 512 buckets, 4 slots, 1-byte fingerprints.
#[derive(Clone)]
pub struct CuckooFilter {
    buckets: [[u8; SLOTS_PER_BUCKET]; NUM_BUCKETS],
    count: usize,
}

impl CuckooFilter {
    pub fn new() -> Self {
        CuckooFilter {
            buckets: [[0u8; SLOTS_PER_BUCKET]; NUM_BUCKETS],
            count: 0,
        }
    }

    /// Compute fingerprint for a key. Never zero (zero means empty slot).
    fn fingerprint(key: &[u8]) -> u8 {
        let mut h: Blake2b<U8> = Blake2b::new();
        h.update(key);
        let result = h.finalize();
        let fp = result[0];
        if fp == 0 { 1 } else { fp }
    }

    /// Primary bucket index for a key.
    fn bucket1(key: &[u8]) -> usize {
        let mut h: Blake2b<U8> = Blake2b::new();
        h.update(b"b1");
        h.update(key);
        let result = h.finalize();
        let v = u64::from_le_bytes(result[..8].try_into().unwrap());
        (v as usize) % NUM_BUCKETS
    }

    /// Alternate bucket index given primary bucket and fingerprint.
    fn bucket2(b1: usize, fp: u8) -> usize {
        // hash(fingerprint) XOR b1
        let mut h: Blake2b<U8> = Blake2b::new();
        h.update(b"b2");
        h.update(&[fp]);
        let result = h.finalize();
        let v = u64::from_le_bytes(result[..8].try_into().unwrap());
        let offset = (v as usize) % NUM_BUCKETS;
        (b1 ^ offset) % NUM_BUCKETS
    }

    fn has_empty_slot(bucket: &[u8; SLOTS_PER_BUCKET]) -> bool {
        bucket.iter().any(|&s| s == 0)
    }

    fn insert_slot(bucket: &mut [u8; SLOTS_PER_BUCKET], fp: u8) -> bool {
        for slot in bucket.iter_mut() {
            if *slot == 0 {
                *slot = fp;
                return true;
            }
        }
        false
    }

    fn remove_slot(bucket: &mut [u8; SLOTS_PER_BUCKET], fp: u8) -> bool {
        for slot in bucket.iter_mut() {
            if *slot == fp {
                *slot = 0;
                return true;
            }
        }
        false
    }

    fn contains_slot(bucket: &[u8; SLOTS_PER_BUCKET], fp: u8) -> bool {
        bucket.iter().any(|&s| s == fp)
    }

    /// Add a key to the filter. Returns false if the filter is full.
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

        // Need to kick out an existing entry
        let mut rng = rand::thread_rng();
        let mut cur_bucket = if rng.gen_bool(0.5) { b1 } else { b2 };
        let mut cur_fp = fp;

        for _ in 0..MAX_KICKS {
            // Pick a random slot to evict
            let slot_idx = rng.gen_range(0..SLOTS_PER_BUCKET);
            let evicted_fp = self.buckets[cur_bucket][slot_idx];
            self.buckets[cur_bucket][slot_idx] = cur_fp;

            // Find alternate bucket for evicted item
            cur_fp = evicted_fp;
            let alt = Self::bucket2(cur_bucket, cur_fp);
            cur_bucket = alt;

            if Self::insert_slot(&mut self.buckets[cur_bucket], cur_fp) {
                self.count += 1;
                return true;
            }
        }

        // Filter is full
        false
    }

    /// Remove a key from the filter. Returns false if not found.
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

    /// Check if a key is probably in the filter.
    pub fn contains(&self, key: &[u8]) -> bool {
        let fp = Self::fingerprint(key);
        let b1 = Self::bucket1(key);
        let b2 = Self::bucket2(b1, fp);
        Self::contains_slot(&self.buckets[b1], fp) || Self::contains_slot(&self.buckets[b2], fp)
    }

    /// Encode filter as a flat 2048-byte array.
    pub fn encode(&self) -> [u8; 2048] {
        let mut out = [0u8; 2048];
        for (i, bucket) in self.buckets.iter().enumerate() {
            out[i * SLOTS_PER_BUCKET..(i + 1) * SLOTS_PER_BUCKET].copy_from_slice(bucket);
        }
        out
    }

    /// Decode a flat 2048-byte array into a filter.
    pub fn decode(data: &[u8; 2048]) -> Self {
        let mut f = CuckooFilter::new();
        let mut count = 0;
        for i in 0..NUM_BUCKETS {
            for j in 0..SLOTS_PER_BUCKET {
                f.buckets[i][j] = data[i * SLOTS_PER_BUCKET + j];
                if f.buckets[i][j] != 0 {
                    count += 1;
                }
            }
        }
        f.count = count;
        f
    }

    /// Merge another filter into this one (OR-merge for gossip).
    /// Sets all slots that the other filter has (union).
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

    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for CuckooFilter {
    fn default() -> Self {
        Self::new()
    }
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
        for k in &keys {
            assert!(cf.add(k));
        }
        for k in &keys {
            assert!(cf.contains(k), "should contain {:?}", k);
        }
        // Remove half
        for k in &keys[..50] {
            assert!(cf.remove(k));
        }
        for k in &keys[..50] {
            // After removal, should not contain (no false negatives in cuckoo)
            assert!(!cf.contains(k), "should not contain {:?}", k);
        }
        for k in &keys[50..] {
            assert!(cf.contains(k), "should still contain {:?}", k);
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut cf = CuckooFilter::new();
        for i in 0u32..50 {
            cf.add(&i.to_le_bytes());
        }
        let encoded = cf.encode();
        let decoded = CuckooFilter::decode(&encoded);
        // Verify same contents
        for i in 0u32..50 {
            assert!(decoded.contains(&i.to_le_bytes()), "decoded missing {}", i);
        }
    }

    #[test]
    fn fpr_test() {
        // Add 100 random keys, check FPR on 1000 different keys
        let mut cf = CuckooFilter::new();
        let keys: Vec<Vec<u8>> = (0u32..100).map(|i| format!("key_{}", i).into_bytes()).collect();
        for k in &keys {
            cf.add(k);
        }

        let mut false_positives = 0;
        let total = 1000;
        for i in 0u32..total {
            let query = format!("query_{}", i).into_bytes();
            if cf.contains(&query) {
                false_positives += 1;
            }
        }
        let fpr = false_positives as f64 / total as f64;
        // Should be well under 5%
        assert!(fpr < 0.05, "FPR too high: {:.3}", fpr);
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
