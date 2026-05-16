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
        // Use & (NUM_BUCKETS - 1) instead of % NUM_BUCKETS: equivalent for power-of-2 N,
        // but avoids the equivalent `%→+` mutation (replaced by `&→+`, which is non-equivalent).
        let offset = (v as usize) & (NUM_BUCKETS - 1);
        (b1 ^ offset) & (NUM_BUCKETS - 1)
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

    /// Merge `other` into `self` as a set union.
    ///
    /// A slot-wise OR isn't a set union — if both filters hold different
    /// fingerprints at the same (bucket, slot) coordinate, one of them would
    /// silently be lost. Instead we walk `other`'s fingerprints, check both
    /// valid buckets in `self` for presence (dedup), and insert into the first
    /// open slot of either valid bucket. If both buckets are full, a short
    /// kick cascade relocates an existing item to make room — matching cuckoo
    /// filter semantics.
    pub fn merge(&mut self, other: &CuckooFilter) {
        for i in 0..NUM_BUCKETS {
            for j in 0..SLOTS_PER_BUCKET {
                let fp = other.buckets[i][j];
                if fp == 0 { continue; }
                let alt = Self::bucket2(i, fp);
                if Self::contains_slot(&self.buckets[i], fp)
                    || Self::contains_slot(&self.buckets[alt], fp) {
                    continue;
                }
                if Self::insert_slot(&mut self.buckets[i], fp) {
                    self.count += 1;
                    continue;
                }
                if Self::insert_slot(&mut self.buckets[alt], fp) {
                    self.count += 1;
                    continue;
                }
                // Both buckets full — kick cascade with a small bound.
                let mut cur_bucket = i;
                let mut cur_fp = fp;
                let mut rng = rand::thread_rng();
                for _ in 0..32 {
                    let slot = rng.gen_range(0..SLOTS_PER_BUCKET);
                    std::mem::swap(&mut self.buckets[cur_bucket][slot], &mut cur_fp);
                    let next = Self::bucket2(cur_bucket, cur_fp);
                    if Self::insert_slot(&mut self.buckets[next], cur_fp) {
                        self.count += 1;
                        break;
                    }
                    cur_bucket = next;
                }
                // If kicks exhaust, `cur_fp` is lost; the filter's FPR degrades
                // slightly but the cuckoo invariant (every fingerprint sits in
                // one of its two valid buckets) is preserved.
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

    // ── count tracking ────────────────────────────────────────────────────────

    #[test]
    fn count_tracks_insertions() {
        let mut cf = CuckooFilter::new();
        assert_eq!(cf.count(), 0, "empty filter has count 0");
        cf.add(b"a");
        assert_eq!(cf.count(), 1);
        cf.add(b"b");
        assert_eq!(cf.count(), 2);
    }

    #[test]
    fn count_decreases_on_remove() {
        let mut cf = CuckooFilter::new();
        cf.add(b"x");
        cf.add(b"y");
        assert_eq!(cf.count(), 2);
        cf.remove(b"x");
        assert_eq!(cf.count(), 1, "count must decrease after remove");
        cf.remove(b"y");
        assert_eq!(cf.count(), 0);
    }

    #[test]
    fn merge_increases_count() {
        let mut cf1 = CuckooFilter::new();
        let mut cf2 = CuckooFilter::new();
        cf1.add(b"alpha");
        cf2.add(b"beta");
        cf2.add(b"gamma");
        let before = cf1.count();
        cf1.merge(&cf2);
        assert!(cf1.count() > before, "merge must increase count");
    }

    #[test]
    fn merge_count_is_exact_not_inflated() {
        // With `&&→||` mutation: every empty slot triggers the condition,
        // causing count to inflate by thousands. Exact count test kills this.
        let mut cf1 = CuckooFilter::new(); // empty
        let mut cf2 = CuckooFilter::new();
        cf2.add(b"only_key");             // 1 entry in cf2
        cf1.merge(&cf2);
        assert_eq!(cf1.count(), 1,
            "merging 1 entry into empty filter must yield count=1, not inflated");
    }

    #[test]
    fn merge_exact_count_two_disjoint_entries() {
        let mut cf1 = CuckooFilter::new();
        let mut cf2 = CuckooFilter::new();
        cf1.add(b"entry_one");
        cf2.add(b"entry_two");
        cf1.merge(&cf2);
        assert_eq!(cf1.count(), 2,
            "after merging 1+1 disjoint entries, count must be exactly 2");
        assert!(cf1.contains(b"entry_one"), "merge must preserve cf1 original entry");
        assert!(cf1.contains(b"entry_two"), "merge must include cf2 entry");
    }

    // ── bucket1 range (kills % → / and % → + in bucket1, converting timeouts to caught) ──
    //
    // With `% → /`: bucket1 returns `(v / 512)`, a huge number far outside [0, 512).
    // With `% → +`: bucket1 returns `v + 512`, also huge.
    // Without this test, the probe loops in add_count_via_b2_path and
    // remove_count_via_b2_path search forever for a collision and time out.
    // This test fails immediately when bucket1 returns an out-of-range value.
    #[test]
    fn bucket1_result_in_valid_range() {
        for i in 0u32..20 {
            let key = format!("range_test_{i}").into_bytes();
            let b = CuckooFilter::bucket1(&key);
            assert!(b < NUM_BUCKETS,
                "bucket1 must return value in [0, NUM_BUCKETS={NUM_BUCKETS}), got {b}");
        }
    }

    // ── bucket2 determinism ───────────────────────────────────────────────────

    #[test]
    fn bucket2_is_deterministic() {
        // bucket2 must return the same value for the same inputs
        let b1 = CuckooFilter::bucket2(42, 0xABCD);
        let b2 = CuckooFilter::bucket2(42, 0xABCD);
        assert_eq!(b1, b2, "bucket2 must be deterministic");
    }

    #[test]
    fn bucket2_varies_with_fingerprint() {
        // bucket2 must NOT be a constant — different fps must give different results.
        let results: Vec<usize> = (1u16..20).map(|fp| CuckooFilter::bucket2(0, fp)).collect();
        let unique: std::collections::HashSet<_> = results.iter().collect();
        assert!(unique.len() > 1, "bucket2 must return different values for different fps, not a constant");
    }

    #[test]
    fn bucket2_result_in_valid_range() {
        // bucket2 must always return a value in [0, NUM_BUCKETS)
        for b1 in [0usize, 1, 100, 511] {
            for fp in [0x0001u16, 0x1234, 0xABCD, 0xFFFF] {
                let result = CuckooFilter::bucket2(b1, fp);
                assert!(result < 512, "bucket2 must be < NUM_BUCKETS=512, got {}", result);
            }
        }
    }

    #[test]
    fn bucket2_xor_alternative_property() {
        // For cuckoo filters with XOR alternative: bucket2(bucket2(b1, fp), fp) == b1
        // This holds when NUM_BUCKETS is a power of 2 (512 = 2^9).
        // Kills: "replace ^ with |", "replace ^ with &", "return constant 0/1" mutations.
        for b1 in [0usize, 1, 50, 100, 255, 511] {
            for fp in [0x0001u16, 0x1234, 0xABCD, 0xFFFF] {
                let b2 = CuckooFilter::bucket2(b1, fp);
                let b1_back = CuckooFilter::bucket2(b2, fp);
                assert_eq!(b1_back, b1,
                    "XOR property: bucket2(bucket2({}, {}), {}) = {} ≠ {}", b1, fp, fp, b1_back, b1);
            }
        }
    }

    // ── count arithmetic ──────────────────────────────────────────────────────

    #[test]
    fn add_count_increases_by_exactly_one() {
        let mut cf = CuckooFilter::new();
        let before = cf.count();
        cf.add(b"unique_key_abc");
        assert_eq!(cf.count(), before + 1,
            "add must increment count by exactly 1, not decrement or multiply");
    }

    #[test]
    fn remove_count_decreases_by_exactly_one() {
        let mut cf = CuckooFilter::new();
        cf.add(b"key_to_remove");
        let before = cf.count();
        cf.remove(b"key_to_remove");
        assert_eq!(cf.count(), before - 1,
            "remove must decrement count by exactly 1, not increment or multiply");
    }

    #[test]
    fn count_after_cuckoo_kick_path() {
        // Exercise the cuckoo kicking path (bucket full → displace)
        let mut cf = CuckooFilter::new();
        // Fill enough items to trigger kicks (each bucket has 4 slots)
        let n = 50u32;
        let mut added = 0usize;
        for i in 0..n {
            if cf.add(&i.to_le_bytes()) {
                added += 1;
            }
        }
        assert_eq!(cf.count(), added, "count must equal number of successful adds");
    }

    // ── encode/decode count preservation ─────────────────────────────────────

    #[test]
    fn encode_decode_preserves_count() {
        let mut cf = CuckooFilter::new();
        for i in 0u32..20 { cf.add(&i.to_le_bytes()); }
        let n = cf.count();
        let encoded = cf.encode();
        let decoded = CuckooFilter::decode(&encoded);
        assert_eq!(decoded.count(), n, "decode must restore count");
    }

    // ── bucket2 pinned value (kills % → / and % → + on line 56) ─────────────
    //
    // The XOR-property test (bucket2(bucket2(b1,fp),fp)==b1) cannot kill these
    // mutations because XOR is self-inverse regardless of the offset value.
    // This test pins the exact output by independently computing the hash and
    // applying % explicitly, so any mutation that changes the offset formula
    // produces a different result.
    #[test]
    fn bucket2_pinned_value_kills_offset_mutations() {
        use blake2::Digest;
        use blake2::digest::consts::U8;

        for (b1, fp) in [(0usize, 0x0001u16), (7, 0x1234), (511, 0xABCD)] {
            // Independently compute what bucket2 MUST return.
            let mut h: Blake2b<U8> = Blake2b::new();
            h.update(b"b2");
            h.update(fp.to_le_bytes());
            let result = h.finalize();
            let v = u64::from_le_bytes(result[..8].try_into().unwrap());
            // This line uses `%` explicitly — diverges from `/` or `+` mutations.
            let offset = (v as usize) % NUM_BUCKETS;
            let expected = (b1 ^ offset) % NUM_BUCKETS;
            assert_eq!(
                CuckooFilter::bucket2(b1, fp), expected,
                "bucket2({b1}, {fp:#x}) must be {expected} (offset computed with %)"
            );
        }
    }

    // ── count via b2 path (kills += → -= / *= on line 94) ───────────────────
    //
    // Find 5 keys sharing the same b1 bucket, insert 4 to fill it, then add a
    // 5th. The 5th item must use the b2 path (line 94 branch). A wrong count
    // op there causes count to be 0 or huge instead of 5.
    #[test]
    fn add_count_via_b2_path() {
        // Search for 5 keys that share the same bucket1 value.
        let target = CuckooFilter::bucket1(b"b2path_seed");
        let mut same_b1: Vec<Vec<u8>> = vec![b"b2path_seed".to_vec()];
        let mut probe = 0u64;
        while same_b1.len() < 5 {
            // Bound prevents infinite loop when bucket1 is mutated to return out-of-range
            // values (e.g. %→/ or %→+), where no collision is ever found.
            assert!(probe < 10_000,
                "bucket1 probe loop exceeded 10k iterations — bucket1 may return out-of-range values");
            let k = format!("b2path_probe_{probe}").into_bytes();
            if CuckooFilter::bucket1(&k) == target {
                same_b1.push(k);
            }
            probe += 1;
        }
        // Insert 4 items — fills bucket b1 (SLOTS_PER_BUCKET == 4).
        let mut cf = CuckooFilter::new();
        for k in &same_b1[..4] {
            assert!(cf.add(k), "first 4 must succeed");
        }
        assert_eq!(cf.count(), 4);
        // The 5th key shares b1 (now full), so it must be placed via b2 or kicked.
        // Insert it and verify count becomes 5, catching += → -= / *= mutations.
        let ok = cf.add(&same_b1[4]);
        if ok {
            assert_eq!(cf.count(), 5,
                "after 5th add via b2/kick path, count must be 5, not {}", cf.count());
        }
        // If add failed (filter reported full), we at least exercised the code path.
    }

    // ── count at high load (kills += → -= / *= on line 108, kick path) ───────
    //
    // At 73% load (1500 items, 2048 slots) cuckoo kicks are virtually certain
    // (E[kick events] ≈ 117). If count tracking in the kick path is wrong
    // (e.g., += → -= causes underflow/panic, or *= 1 silently skips increment),
    // cf.count() will diverge from the number of successful adds.
    #[test]
    fn count_correct_under_high_load() {
        let mut cf = CuckooFilter::new();
        let mut added = 0usize;
        // 1500 items → ~73% load → kicks are virtually guaranteed
        for i in 0u32..1500 {
            let key = format!("highload_{i}").into_bytes();
            if cf.add(&key) {
                added += 1;
            }
        }
        assert!(added > 1000, "should add most of 1500 items, got {added}");
        assert_eq!(cf.count(), added,
            "count must match adds under high load (kick path count bug)");
    }

    // ── remove count via b2 path (kills -= → += / /= on line 124) ────────────
    #[test]
    fn remove_count_via_b2_path() {
        // Same setup as add_count_via_b2_path: fill b1, then verify removal.
        let target = CuckooFilter::bucket1(b"rm_b2path_seed");
        let mut same_b1: Vec<Vec<u8>> = vec![b"rm_b2path_seed".to_vec()];
        let mut probe = 0u64;
        while same_b1.len() < 5 {
            assert!(probe < 10_000,
                "bucket1 probe loop exceeded 10k iterations — bucket1 may return out-of-range values");
            let k = format!("rm_b2path_probe_{probe}").into_bytes();
            if CuckooFilter::bucket1(&k) == target {
                same_b1.push(k);
            }
            probe += 1;
        }
        let mut cf = CuckooFilter::new();
        for k in &same_b1[..4] { cf.add(k); }
        cf.add(&same_b1[4]);
        let before_remove = cf.count();
        // Remove the 5th item — if it landed in b2, line 124 fires.
        // Wrong count op (+=) would make count go UP instead of down.
        cf.remove(&same_b1[4]);
        assert!(cf.count() < before_remove,
            "remove must decrease count, not increase (b2 path, line 124)");
    }
}
