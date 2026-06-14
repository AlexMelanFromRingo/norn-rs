#![no_main]

use libfuzzer_sys::fuzz_target;
use norn_rs::sphinx::{process_sphinx, replay_digest};
use x25519_dalek::StaticSecret;

// `process_sphinx` parses an attacker-controlled cell (size/type/offsets) and,
// on a MAC match, unwraps a header + payload layer. It must NEVER panic on
// arbitrary bytes — only return Err. A fixed onion key exercises the parsing
// and the MAC path; `replay_digest` is the cheap pre-check a relay runs first.
fuzz_target!(|data: &[u8]| {
    let sk = StaticSecret::from([7u8; 32]);
    // Raw input: exercises the size/type guards.
    let _ = process_sphinx(data, &[&sk]);
    let _ = replay_digest(data);
    // Normalised to a full cell so the field parsing + MAC path is reached
    // regardless of input length (random data rarely lands on exactly
    // CELL_SIZE, so without this the size-bail dominates).
    let mut cell = vec![0u8; norn_rs::sphinx::CELL_SIZE];
    let n = data.len().min(cell.len());
    cell[..n].copy_from_slice(&data[..n]);
    let _ = process_sphinx(&cell, &[&sk]);
    let _ = replay_digest(&cell);
});
