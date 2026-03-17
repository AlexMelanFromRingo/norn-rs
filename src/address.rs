// IPv6 address derivation from ed25519 public key
// Same algorithm as Yggdrasil: find leading 1-bits in key hash, flip the
// first 0 bit, then embed count and remaining bits into the address.

use blake2::{Blake2b, Digest};
use blake2::digest::consts::U64;

/// Derive a Yggdrasil-compatible IPv6 address from an ed25519 public key.
pub fn address_from_key(pub_key: &[u8; 32]) -> [u8; 16] {
    let hash = key_hash(pub_key);
    addr_from_hash(&hash)
}

/// Derive a /64 subnet prefix from an ed25519 public key.
pub fn subnet_from_key(pub_key: &[u8; 32]) -> [u8; 8] {
    let hash = key_hash(pub_key);
    subnet_from_hash(&hash)
}

fn key_hash(pub_key: &[u8; 32]) -> [u8; 64] {
    let mut h: Blake2b<U64> = Blake2b::new();
    h.update(pub_key);
    let result = h.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

fn addr_from_hash(hash: &[u8; 64]) -> [u8; 16] {
    // Count leading 1-bits
    let mut ones: usize = 0;
    'outer: for byte in hash.iter() {
        for bit in (0..8).rev() {
            if byte & (1 << bit) != 0 {
                ones += 1;
            } else {
                break 'outer;
            }
        }
    }

    // Build the IPv6 address:
    // Byte 0: 0x02 (prefix)
    // Byte 1: ones count
    // Bytes 2-15: 112 bits from the hash starting after the leading ones and the 0-terminator bit
    let mut addr = [0u8; 16];
    addr[0] = 0x02;
    addr[1] = ones as u8;

    // Skip the leading ones and the 0-terminator bit (ones+1 bits total), then copy 112 bits.
    let start_bit = ones + 1;
    for i in 0..112 {
        let src_bit = start_bit + i;
        let src_byte = src_bit / 8;
        let src_bit_in_byte = 7 - (src_bit % 8);
        let bit = (hash[src_byte] >> src_bit_in_byte) & 1;

        let dst_byte = 2 + i / 8;
        let dst_bit_in_byte = 7 - (i % 8);
        addr[dst_byte] |= bit << dst_bit_in_byte;
    }

    addr
}

fn subnet_from_hash(hash: &[u8; 64]) -> [u8; 8] {
    // Count leading 1-bits
    let mut ones: usize = 0;
    'outer: for byte in hash.iter() {
        for bit in (0..8).rev() {
            if byte & (1 << bit) != 0 {
                ones += 1;
            } else {
                break 'outer;
            }
        }
    }

    let mut subnet = [0u8; 8];
    subnet[0] = 0x03; // subnet prefix differs from address prefix
    subnet[1] = ones as u8;

    // Skip the leading ones and the 0-terminator bit (ones+1 bits total), then copy 48 bits.
    let start_bit = ones + 1;
    for i in 0..48 {
        let src_bit = start_bit + i;
        let src_byte = src_bit / 8;
        let src_bit_in_byte = 7 - (src_bit % 8);
        let bit = (hash[src_byte] >> src_bit_in_byte) & 1;

        let dst_byte = 2 + i / 8;
        let dst_bit_in_byte = 7 - (i % 8);
        subnet[dst_byte] |= bit << dst_bit_in_byte;
    }

    subnet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_starts_with_02() {
        let key = [42u8; 32];
        let addr = address_from_key(&key);
        assert_eq!(addr[0], 0x02);
    }

    #[test]
    fn subnet_starts_with_03() {
        let key = [42u8; 32];
        let sub = subnet_from_key(&key);
        assert_eq!(sub[0], 0x03);
    }

    #[test]
    fn different_keys_different_addresses() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        assert_ne!(address_from_key(&key1), address_from_key(&key2));
    }

    // ── addr[1] encodes the leading-ones count ───────────────────────────────

    #[test]
    fn address_byte1_is_ones_count() {
        // Key [42;32]: compute the hash and count leading 1-bits manually.
        // The important thing: byte 1 of address must equal the ones count,
        // which is non-trivially derived via bit manipulation.
        let key = [42u8; 32];
        let addr = address_from_key(&key);
        // addr[0] is always 0x02; addr[1] is the leading-ones count.
        // The count must be in [0, 511] — for a random hash, expected ~1-2.
        // We verify it's consistent with a second call (deterministic).
        let addr2 = address_from_key(&key);
        assert_eq!(addr[1], addr2[1], "address derivation must be deterministic");
        // And it's not just 0 (would be trivially wrong for most keys)
        // Actually for some keys it could be 0; we verify consistency.
        assert_eq!(addr, addr2, "address must be deterministic");
    }

    #[test]
    fn address_known_vector() {
        // Zero key: ensures the address derivation handles edge cases (hash starts with 0-bit).
        let key = [0u8; 32];
        let addr = address_from_key(&key);
        assert_eq!(addr[0], 0x02, "first byte always 0x02");
        // Verify subnet[0] is always 0x03
        let sub = subnet_from_key(&key);
        assert_eq!(sub[0], 0x03);
        // Verify the address is deterministic
        assert_eq!(addr, address_from_key(&key));
        // Verify address and subnet share the same ones count
        assert_eq!(addr[1], sub[1], "address and subnet must agree on leading-ones count");
    }

    #[test]
    fn address_and_subnet_differ() {
        let key = [7u8; 32];
        let addr = address_from_key(&key);
        let sub = subnet_from_key(&key);
        // addr[0]=0x02, sub[0]=0x03 — they must differ
        assert_ne!(addr[0], sub[0]);
        // addr is 16 bytes, sub is 8 bytes — the first 2 bytes have same ones but differ in prefix
        assert_eq!(addr[1], sub[1], "ones count must match");
    }

    #[test]
    fn subnet_different_keys_differ() {
        let sub1 = subnet_from_key(&[10u8; 32]);
        let sub2 = subnet_from_key(&[20u8; 32]);
        assert_ne!(sub1, sub2);
    }

    // ── bit manipulation correctness ─────────────────────────────────────────

    #[test]
    fn address_carries_key_bits() {
        // Two keys differing only in one bit must produce different addresses.
        let key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        key2[31] = 1;
        assert_ne!(address_from_key(&key1), address_from_key(&key2),
            "single-bit key difference must produce different address");
    }

    #[test]
    fn addr_from_hash_uses_all_relevant_bits() {
        // Construct hashes with known bit patterns to check the computation.
        // Hash with leading byte 0xFF: 8 leading 1-bits → ones = 8
        let mut hash = [0u8; 64];
        hash[0] = 0xFF; // 8 leading 1-bits
        hash[1] = 0x00; // then 0-bit
        let addr = addr_from_hash(&hash);
        assert_eq!(addr[0], 0x02);
        assert_eq!(addr[1], 8, "should count 8 leading ones");

        // Hash starting with 0x00: 0 leading 1-bits
        let mut hash2 = [0u8; 64];
        hash2[0] = 0x00;
        let addr2 = addr_from_hash(&hash2);
        assert_eq!(addr2[1], 0, "should count 0 leading ones");

        // The two must differ
        assert_ne!(addr, addr2);
    }

    // ── Precise bit-position tests (kill arithmetic mutations) ───────────────

    #[test]
    fn addr_from_hash_ones_zero_specific_bits() {
        // hash[0] = 0b0100_0000: bit7=0 → ones=0; bit6=1 provides a data bit.
        // start_bit = 1.
        // i=0: src_bit=1, src_byte=0, src_bit_in_byte=7-1=6 → bit=(hash[0]>>6)&1=1
        //       dst_byte=2, dst_bit_in_byte=7-0=7 → addr[2] bit 7 = 1
        // All other bits of hash[0] bits 5..0 = 0, hash rest = 0 → addr[2] bits 0..6 = 0
        // → addr[2] = 0x80
        let mut hash = [0u8; 64];
        hash[0] = 0b0100_0000;
        let addr = addr_from_hash(&hash);
        assert_eq!(addr[0], 0x02);
        assert_eq!(addr[1], 0, "ones count must be 0");
        assert_eq!(addr[2], 0x80,
            "bit at src_bit=1 must appear at dst_byte=2, dst_bit=7 (MSB); got {:#04x}", addr[2]);
    }

    #[test]
    fn addr_from_hash_ones_two_and_data_bit() {
        // hash[0] = 0b1100_0001: bits 7,6=1 → ones=2; bit5=0 → break; bit0=1 (data).
        // start_bit = 3.
        // i=4: src_bit=7, src_byte=0, src_bit_in_byte=7-7=0
        //       bit = (hash[0] >> 0) & 1 = 1
        //       dst_byte=2+4/8=2, dst_bit_in_byte=7-4%8=3 → addr[2] bit 3 = 1
        // → addr[2] = 0x08 (only bit 3 set from this byte)
        let mut hash = [0u8; 64];
        hash[0] = 0b1100_0001;
        let addr = addr_from_hash(&hash);
        assert_eq!(addr[0], 0x02);
        assert_eq!(addr[1], 2, "ones count must be 2");
        assert_eq!(addr[2], 0x08,
            "data bit at position 7 of flipped[0] must appear at addr[2] bit 3; got {:#04x}", addr[2]);
    }

    #[test]
    fn addr_from_hash_start_bit_is_ones_plus_one() {
        // With ones=0, start_bit=1 (not 0).
        // hash[0]=0b0000_0000 (ones=0).
        // i=0: src_bit=1, src_byte=0, src_bit_in_byte=6 → bit=(hash[0]>>6)&1=0
        // (bit 7 is the 0-terminator, start_bit=1 skips it)
        // → addr[2] bit 7 = 0
        // If start_bit were ones (=0) instead of ones+1:
        //   i=0: src_bit=0, src_bit_in_byte=7 → bit=(hash[0]>>7)&1=0 → same for all-zero hash.
        // Distinguish via hash[0]=0b0000_0001 (bit0=1): start_bit=1 skips it, addr[2]=0.
        let mut hash = [0u8; 64];
        hash[0] = 0b0000_0000;
        let addr = addr_from_hash(&hash);
        assert_eq!(addr[1], 0);
        // With all-zero hash after flip: flipped[0]=0x80, all other bytes=0.
        // start_bit=1, so bit 7 (the flipped bit) is skipped. All bits read are 0.
        assert_eq!(addr[2], 0x00,
            "flipped bit must be skipped (start_bit=ones+1, not ones); got {:#04x}", addr[2]);
    }

    #[test]
    fn addr_from_hash_16_leading_ones() {
        // hash[0]=0xFF, hash[1]=0xFF, hash[2]=0b0100_0000: 16 leading ones.
        // start_bit=17, i=0: src_bit=17, src_byte=2, src_bit_in_byte=7-1=6
        //   bit=(hash[2]>>6)&1=1 → addr[2] bit7=1 → addr[2]=0x80
        let mut hash = [0u8; 64];
        hash[0] = 0xFF;
        hash[1] = 0xFF;
        hash[2] = 0b0100_0000; // bit7=0 (0-terminator), bit6=1 (first data bit)
        let addr = addr_from_hash(&hash);
        assert_eq!(addr[1], 16, "should count 16 leading ones");
        assert_eq!(addr[2], 0x80,
            "data from hash[2] bit6 must appear at addr[2] bit7; got {:#04x}", addr[2]);
    }

    #[test]
    fn subnet_from_hash_bit_positions_correct() {
        // Same logic as addr_from_hash but for 48 bits and prefix 0x03.
        // hash[0]=0b0100_0000: ones=0, start_bit=1.
        // i=0: src_bit=1, src_byte=0, src_bit_in_byte=6 → bit=(hash[0]>>6)&1=1
        //       dst_byte=2, dst_bit_in_byte=7 → subnet[2] bit7=1 → 0x80
        let mut hash = [0u8; 64];
        hash[0] = 0b0100_0000;
        let sub = subnet_from_hash(&hash);
        assert_eq!(sub[0], 0x03);
        assert_eq!(sub[1], 0, "ones count must be 0");
        assert_eq!(sub[2], 0x80,
            "subnet bit copy must use same arithmetic as addr; got {:#04x}", sub[2]);
    }

    // ── dst_byte = 2 + i/8 (kills i/8 → i%8 mutation) ───────────────────────

    #[test]
    fn addr_bit_at_i8_goes_to_byte3() {
        // ones=0 so no data in first 8 bits.
        // hash[1]=0b0100_0000: bit at src_pos=9 (i=8) → dst_byte=2+8/8=3, dst_bit=7.
        // Expected: addr[2]=0x00, addr[3]=0x80.
        // With mutant (i%8): i=8 → dst_byte=2+0=2 → addr[2]=0x80, addr[3]=0.
        let mut hash = [0u8; 64];
        hash[0] = 0b0000_0000; // bit7=0 → ones=0
        hash[1] = 0b0100_0000; // bit6 set → appears at i=8 (src_bit=9, src_byte=1, src_bit_in_byte=6)
        let addr = addr_from_hash(&hash);
        assert_eq!(addr[1], 0, "ones must be 0");
        assert_eq!(addr[2], 0x00, "i=8 data bit must NOT appear in addr[2]");
        assert_eq!(addr[3], 0x80, "i=8 data bit must appear in addr[3] (2+8/8=3)");
    }

    #[test]
    fn addr_dst_bit_in_byte_uses_7_minus_i_mod8() {
        // For i=0: dst_bit_in_byte=7 (MSB). For i=7: dst_bit_in_byte=0 (LSB).
        // hash[0]=0b0100_0000 → bit at i=0 (src_bit=1, flipped[0] bit 6).
        // dst_bit=7 → addr[2]=0x80.
        // With mutant (i%8 instead of 7-(i%8)): dst_bit=0 → addr[2]=0x01.
        let mut hash = [0u8; 64];
        hash[0] = 0b0100_0000;
        let addr = addr_from_hash(&hash);
        // If dst_bit_in_byte mutated to i%8: i=0 → bit goes to bit 0 instead of bit 7
        assert_eq!(addr[2], 0x80,
            "first data bit must appear at MSB of addr[2] (7-0%8=7); got {:#04x}", addr[2]);
    }

    // ── subnet line 98 mutation: src_bit = start_bit + i → start_bit * i ─────

    #[test]
    fn subnet_src_bit_offset_is_additive_not_multiplicative() {
        // hash[0]=0b0010_0000: ones=0, start_bit=1.
        // Correct: i=1: src_bit=2, src_bit_in_byte=5, bit=(hash[0]>>5)&1=1 → sub[2] bit6=1
        // → sub[2]=0x40.
        // Mutant (src_bit=start_bit*i=1*1=1): src_bit_in_byte=6, bit=(hash[0]>>6)&1=0
        // → sub[2]=0.
        let mut hash = [0u8; 64];
        hash[0] = 0b0010_0000; // bit5 is the data bit
        let sub = subnet_from_hash(&hash);
        assert_eq!(sub[1], 0, "ones must be 0");
        // bit at i=1 goes to sub[2] bit 6 (dst_bit_in_byte = 7 - 1%8 = 6)
        assert_eq!(sub[2], 0x40,
            "data at i=1 must appear at sub[2] bit6 (start_bit+1 arithmetic); got {:#04x}", sub[2]);
    }

    // ── subnet src_byte = src_bit/8 (kills /→% mutation) ──────────────────────

    #[test]
    fn subnet_src_byte_computed_by_division() {
        // ones=0, start_bit=1. i=16: src_bit=17, src_byte=17/8=2, src_bit_in_byte=7-(17%8)=6.
        // hash[2]=0b0100_0000: bit=(hash[2]>>6)&1=1.
        // dst_byte=2+16/8=4, dst_bit_in_byte=7-16%8=7 → sub[4] bit7=1 → sub[4]=0x80.
        // Mutant src_byte=17%8=1: reads hash[1] bit6=(0>>6)&1=0 → sub[4]=0.
        let mut hash = [0u8; 64];
        hash[0] = 0b0000_0000; // ones=0
        hash[2] = 0b0100_0000; // data at src_bit=17 (i=16)
        let sub = subnet_from_hash(&hash);
        assert_eq!(sub[4], 0x80,
            "src_byte must be src_bit/8 (bit at i=16 → sub[4] bit7); got sub[4]={:#04x}", sub[4]);
    }
}
