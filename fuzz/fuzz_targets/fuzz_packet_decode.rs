#![no_main]

use libfuzzer_sys::fuzz_target;
use norn_rs::packet::{
    decode_uvarint, decode_path, SigReq, SigRes, Announce, CuckooMsg,
    PathLookup, PathNotify, PathBroken, Traffic, CoordAnnounce, OnionKeyAnnounce,
    ReputationReport, HolePunch, CapabilityAnnounce,
};

fuzz_target!(|data: &[u8]| {
    // All decode functions must never panic — they may return Err but not crash.

    let _ = decode_uvarint(data);
    let _ = decode_path(data);

    let _ = SigReq::decode(data);
    let _ = SigRes::decode(data);
    let _ = Announce::decode(data);
    let _ = CuckooMsg::decode(data);
    let _ = PathLookup::decode(data);
    let _ = PathNotify::decode(data);
    let _ = PathBroken::decode(data);
    let _ = Traffic::decode(data);
    let _ = CoordAnnounce::decode(data);
    let _ = OnionKeyAnnounce::decode(data);
    let _ = ReputationReport::decode(data);
    let _ = HolePunch::decode(data);
    let _ = CapabilityAnnounce::decode(data);
});
