#![no_main]

use libfuzzer_sys::fuzz_target;
use norn_rs::session::{SessionInit, SessionAck};

fuzz_target!(|data: &[u8]| {
    // Session decode functions must never panic on arbitrary input.
    let _ = SessionInit::decode(data);
    let _ = SessionAck::decode(data);
});
