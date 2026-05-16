// Property-based tests for the parsing surfaces.
//
// proptest runs each #[test] hundreds of times with shrunk failing inputs,
// catching parser bugs that example-based unit tests miss. Complements the
// libfuzzer targets under fuzz/ with deterministic CI coverage.

use proptest::prelude::*;

use norn_rs::onion::OnionPacket;
use norn_rs::packet::{
    decode_path, decode_uvarint, encode_path, encode_uvarint,
    Announce, CoordAnnounce, CuckooMsg, OnionKeyAnnounce, PathBroken,
    PathLookup, PathNotify, SigReq, SigRes, Traffic,
};
use norn_rs::session::{SessionAck, SessionInit};

// ── uvarint: full-range roundtrip ────────────────────────────────────────

proptest! {
    /// For any u64, encode then decode must yield the original value and
    /// consume all written bytes.
    #[test]
    fn uvarint_roundtrip(v in any::<u64>()) {
        let mut buf = Vec::new();
        encode_uvarint(v, &mut buf);
        let (decoded, n) = decode_uvarint(&buf).expect("decode of own encoding must succeed");
        prop_assert_eq!(decoded, v);
        prop_assert_eq!(n, buf.len());
    }

    /// decode_uvarint MUST NOT panic on arbitrary byte slices.
    #[test]
    fn uvarint_decode_no_panic(bytes in proptest::collection::vec(any::<u8>(), 0..32)) {
        let _ = decode_uvarint(&bytes);
    }
}

// ── path: roundtrip + decode robustness ──────────────────────────────────

proptest! {
    /// Any vector of hop indices encodes then decodes back to itself.
    /// (Capped at 1024 hops to match the decode bound.)
    #[test]
    fn path_roundtrip(hops in proptest::collection::vec(0u64..1_000_000_000, 0..32)) {
        let enc = encode_path(&hops);
        let (dec, _) = decode_path(&enc).expect("decode of own encoding must succeed");
        prop_assert_eq!(dec, hops);
    }

    #[test]
    fn path_decode_no_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = decode_path(&bytes);
    }
}

// ── decode_no_panic for every frame type ─────────────────────────────────

// Every Decode function on the wire surface MUST NOT panic on arbitrary
// bytes. proptest hammers each one with many random inputs.

macro_rules! decode_never_panics {
    ($name:ident, $ty:ty, $min_len:expr, $max_len:expr) => {
        proptest! {
            #[test]
            fn $name(bytes in proptest::collection::vec(any::<u8>(), $min_len..$max_len)) {
                let _ = <$ty>::decode(&bytes);
            }
        }
    };
}

decode_never_panics!(sigreq_decode_no_panic,        SigReq,         0, 256);
decode_never_panics!(sigres_decode_no_panic,        SigRes,         0, 256);
decode_never_panics!(announce_decode_no_panic,      Announce,       0, 256);
decode_never_panics!(cuckoomsg_decode_no_panic,     CuckooMsg,      0, 8192);
decode_never_panics!(pathlookup_decode_no_panic,    PathLookup,     0, 256);
decode_never_panics!(pathnotify_decode_no_panic,    PathNotify,     0, 256);
decode_never_panics!(pathbroken_decode_no_panic,    PathBroken,     0, 256);
decode_never_panics!(traffic_decode_no_panic,       Traffic,        0, 4096);
decode_never_panics!(coord_announce_no_panic,       CoordAnnounce,  0, 256);
decode_never_panics!(onion_key_ann_no_panic,        OnionKeyAnnounce, 0, 256);
decode_never_panics!(session_init_no_panic,         SessionInit,    0, 2048);
decode_never_panics!(session_ack_no_panic,          SessionAck,     0, 2048);
decode_never_panics!(onion_packet_decode_no_panic,  OnionPacket,    0, 4096);

// ── encode/decode roundtrip for the simpler structs ──────────────────────

proptest! {
    #[test]
    fn announce_roundtrip(
        tree_id in any::<u8>(),
        root in any::<[u8; 32]>(),
        root_seq in any::<u64>(),
        path_cost in any::<u64>(),
        sender in any::<[u8; 32]>(),
        depth in any::<u32>(),
    ) {
        let ann = Announce {
            tree_id, root, root_seq, path_cost, sender,
            signature: [0u8; 64], depth,
        };
        let enc = ann.encode();
        // encode() prefixes the type byte; decode() consumes the rest.
        let dec = Announce::decode(&enc[1..]).expect("roundtrip must decode");
        prop_assert_eq!(dec.tree_id, tree_id);
        prop_assert_eq!(dec.root, root);
        prop_assert_eq!(dec.root_seq, root_seq);
        prop_assert_eq!(dec.path_cost, path_cost);
        prop_assert_eq!(dec.sender, sender);
        prop_assert_eq!(dec.depth, depth);
    }

    #[test]
    fn sigreq_roundtrip(
        tree_id in any::<u8>(),
        seq in any::<u64>(),
        timestamp_ms in any::<u64>(),
        pub_key in any::<[u8; 32]>(),
    ) {
        let r = SigReq { tree_id, seq, timestamp_ms, pub_key };
        let enc = r.encode();
        let dec = SigReq::decode(&enc[1..]).expect("roundtrip must decode");
        prop_assert_eq!(dec.tree_id, tree_id);
        prop_assert_eq!(dec.seq, seq);
        prop_assert_eq!(dec.timestamp_ms, timestamp_ms);
        prop_assert_eq!(dec.pub_key, pub_key);
    }

    #[test]
    fn sigres_roundtrip(
        tree_id in any::<u8>(),
        seq in any::<u64>(),
        timestamp_ms in any::<u64>(),
        pub_key in any::<[u8; 32]>(),
    ) {
        let r = SigRes {
            tree_id, seq, timestamp_ms,
            signature: [0u8; 64], pub_key,
        };
        let enc = r.encode();
        let dec = SigRes::decode(&enc[1..]).expect("roundtrip must decode");
        prop_assert_eq!(dec.tree_id, tree_id);
        prop_assert_eq!(dec.seq, seq);
        prop_assert_eq!(dec.timestamp_ms, timestamp_ms);
        prop_assert_eq!(dec.pub_key, pub_key);
    }
}
