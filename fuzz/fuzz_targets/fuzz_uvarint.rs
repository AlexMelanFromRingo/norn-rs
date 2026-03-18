#![no_main]

use libfuzzer_sys::fuzz_target;
use norn_rs::packet::{decode_uvarint, encode_uvarint};

fuzz_target!(|data: &[u8]| {
    // Round-trip property: decode(encode(x)) == x for any valid u64.
    if let Ok((val, consumed)) = decode_uvarint(data) {
        // consumed must be within bounds
        assert!(consumed <= data.len(), "consumed > input length");
        assert!(consumed > 0, "consumed must be at least 1");

        // Re-encode and re-decode must give the same value
        let mut buf = Vec::new();
        encode_uvarint(val, &mut buf);
        let (val2, _) = decode_uvarint(&buf).expect("re-decode of encoded uvarint failed");
        assert_eq!(val, val2, "round-trip mismatch");
    }
    // If decode fails on arbitrary bytes, that's fine — just no panic.
});
