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

    // Flip the first 0 bit (bit at position `ones`)
    let mut flipped = *hash;
    let byte_idx = ones / 8;
    let bit_idx = 7 - (ones % 8);
    flipped[byte_idx] |= 1 << bit_idx;

    // Build the IPv6 address:
    // Byte 0: 0x02 (prefix)
    // Byte 1: ones count
    // Bytes 2-15: first 14 bytes of flipped hash (skipping the flipped bit's byte position...)
    // Actually: take bits from flipped hash starting after the ones+1 bits
    let mut addr = [0u8; 16];
    addr[0] = 0x02;
    addr[1] = ones as u8;

    // Copy 14 bytes worth of bits from the hash starting at bit position (ones+1)
    let start_bit = ones + 1;
    for i in 0..112 {
        // destination bit i goes into addr[2 + i/8], bit (7 - i%8)
        let src_bit = start_bit + i;
        let src_byte = src_bit / 8;
        let src_bit_in_byte = 7 - (src_bit % 8);
        let bit = (flipped[src_byte] >> src_bit_in_byte) & 1;

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

    let mut flipped = *hash;
    let byte_idx = ones / 8;
    let bit_idx = 7 - (ones % 8);
    flipped[byte_idx] |= 1 << bit_idx;

    let mut subnet = [0u8; 8];
    subnet[0] = 0x03; // subnet prefix differs from address prefix
    subnet[1] = ones as u8;

    let start_bit = ones + 1;
    for i in 0..48 {
        let src_bit = start_bit + i;
        let src_byte = src_bit / 8;
        let src_bit_in_byte = 7 - (src_bit % 8);
        let bit = (flipped[src_byte] >> src_bit_in_byte) & 1;

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
}
