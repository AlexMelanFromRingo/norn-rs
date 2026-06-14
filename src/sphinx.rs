//! Fixed-size (Sphinx-style) onion format — see `docs/onion-sphinx-design.md`.
//!
//! Closes REVIEW-FINDINGS #3: the legacy onion (`crate::onion`) writes a cleartext
//! per-layer `aead_len` that shrinks ~one layer per hop, letting an observer of two
//! consecutive hops correlate predecessor↔successor. This format makes every cell
//! byte-for-byte structurally identical at every hop:
//!
//! ```text
//! [TYPE_ONION_SPHINX:1][routing_tag:16][epk:32][gamma:16][beta:325][payload:890] = 1280
//! ```
//! `routing_tag` is cleartext per-segment routing metadata (mesh routes the cell to
//! the current onion hop on it, like the legacy onion's outer tag); each peeling hop
//! rewrites it to the next hop's tag. Everything else is fresh-pseudorandom per hop.
//!
//! The routing header (`beta`) is kept constant-size across hops by the Sphinx
//! filler trick (BOLT-04 mechanics). Per-hop X25519 ephemerals are independent
//! (no blinding / no ristretto migration); the payload is a constant-size
//! stream-cipher onion whose integrity is provided end-to-end by the session AEAD.

use anyhow::{bail, Result};
use blake2::digest::consts::{U16, U32};
use blake2::digest::Mac;
use blake2::{Blake2b, Blake2bMac, Digest};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key as CcKey, Nonce as CcNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

/// Wire type byte for a Sphinx-style onion cell. Distinct from `TYPE_ONION` (11)
/// so the two formats coexist during rollout. 0x10 = first free type byte.
pub const TYPE_ONION_SPHINX: u8 = 0x10;

/// Max relays (including the exit) a single cell can carry.
pub const MAX_HOPS: usize = 5;

const EPK_LEN: usize = 32;
const TAG_LEN: usize = 16;
const MAC_LEN: usize = 16;
const FLAGS_LEN: usize = 1;
/// Per-hop routing payload: flags + next routing_tag + next epk.
const HOP_PAYLOAD: usize = FLAGS_LEN + TAG_LEN + EPK_LEN; // 49
/// Bytes of `beta` consumed per hop: hop payload + the next hop's MAC.
const PER_HOP: usize = HOP_PAYLOAD + MAC_LEN; // 65
/// Routing header length — constant at every hop.
const BETA_LEN: usize = PER_HOP * MAX_HOPS; // 325
const HEADER_LEN: usize = EPK_LEN + MAC_LEN + BETA_LEN; // 373

/// Total cell size on the wire — identical to the legacy onion cell.
pub const CELL_SIZE: usize = crate::onion::ONION_CELL_SIZE; // 1280
/// Constant onion payload budget (the innermost `[len:2][traffic][pad]`).
pub const PAYLOAD_LEN: usize = CELL_SIZE - 1 - TAG_LEN - HEADER_LEN; // 890

const FLAG_FORWARD: u8 = 0x00;
const FLAG_EXIT: u8 = 0x01;

// Wire offsets within a cell (after the 1-byte type). The cleartext `routing_tag`
// (per-segment, mutable) lets the mesh greedily route the cell to the current
// onion hop, exactly like the legacy onion's outer tag. It is NOT covered by the
// MAC — it is routing metadata, rewritten by each peeling hop to the next tag.
const OFF_TAG: usize = 1;
const OFF_EPK: usize = OFF_TAG + TAG_LEN; // 17
const OFF_GAMMA: usize = OFF_EPK + EPK_LEN; // 49
const OFF_BETA: usize = OFF_GAMMA + MAC_LEN; // 65
const OFF_PAYLOAD: usize = OFF_BETA + BETA_LEN; // 390

const _: () = assert!(1 + TAG_LEN + HEADER_LEN + PAYLOAD_LEN == CELL_SIZE);
const _: () = assert!(OFF_PAYLOAD + PAYLOAD_LEN == CELL_SIZE);
// Max bytes of caller traffic that fit (2-byte length prefix lives inside payload).
/// Largest `traffic` payload `build` accepts.
pub const MAX_TRAFFIC_LEN: usize = PAYLOAD_LEN - 2;

/// One hop on the path: its routing tag (for the cuckoo lookup at the *previous*
/// hop) and its advertised X25519 onion public key (for the ECDH).
#[derive(Clone, Debug)]
pub struct SphinxHop {
    pub routing_tag: [u8; 16],
    pub onion_pub: [u8; 32],
}

/// Result of processing one cell.
#[derive(Debug)]
pub enum SphinxPeeled {
    /// Relay hop: forward `cell` toward `next_tag`.
    Forward { next_tag: [u8; 16], cell: Vec<u8> },
    /// Exit hop: deliver the recovered Traffic packet bytes.
    Deliver(Vec<u8>),
}

// ── key schedule ────────────────────────────────────────────────────────────

fn kdf(label: &[u8], s: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    h.update(label);
    h.update(s);
    h.finalize().into()
}

fn rho_key(s: &[u8; 32]) -> [u8; 32] { kdf(b"norn-sphinx:rho:v1", s) }
fn mu_key(s: &[u8; 32]) -> [u8; 32] { kdf(b"norn-sphinx:mu:v1", s) }
fn pi_key(s: &[u8; 32]) -> [u8; 32] { kdf(b"norn-sphinx:pi:v1", s) }

/// ChaCha20 keystream (key derived per hop, nonce = 0; safe because the key is
/// unique per hop) XORed in place.
fn chacha_apply(key: &[u8; 32], buf: &mut [u8]) {
    let mut c = ChaCha20::new(CcKey::from_slice(key), CcNonce::from_slice(&[0u8; 12]));
    c.apply_keystream(buf);
}

fn chacha_keystream(key: &[u8; 32], n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    chacha_apply(key, &mut buf);
    buf
}

/// Keyed BLAKE2b MAC truncated to 16 bytes, over `beta`.
fn mac16(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut m = <Blake2bMac<U16> as Mac>::new_from_slice(key)
        .expect("32-byte key is a valid BLAKE2b MAC key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

fn x25519_shared(local: &StaticSecret, remote_pub: &[u8; 32]) -> [u8; 32] {
    *local.diffie_hellman(&PublicKey::from(*remote_pub)).as_bytes()
}

// ── build ───────────────────────────────────────────────────────────────────

/// Build a Sphinx-style onion cell carrying `traffic` (an encoded Traffic packet,
/// WITH its leading type byte) to the last hop in `hops`, relayed through the
/// earlier hops. Returns the full wire cell (leading `TYPE_ONION_SPHINX`).
pub fn build_sphinx(hops: &[SphinxHop], traffic: &[u8]) -> Result<Vec<u8>> {
    let nu = hops.len();
    if nu == 0 || nu > MAX_HOPS {
        bail!("sphinx build: hop count {nu} out of 1..={MAX_HOPS}");
    }
    if traffic.len() > MAX_TRAFFIC_LEN {
        bail!("sphinx build: traffic {} > max {}", traffic.len(), MAX_TRAFFIC_LEN);
    }

    // Per-hop ephemerals and shared secrets.
    let mut epks: Vec<[u8; 32]> = Vec::with_capacity(nu);
    let mut secrets: Vec<[u8; 32]> = Vec::with_capacity(nu);
    for hop in hops {
        let eph = StaticSecret::random_from_rng(OsRng);
        epks.push(*PublicKey::from(&eph).as_bytes());
        secrets.push(x25519_shared(&eph, &hop.onion_pub));
    }

    // Filler (length (nu-1)*PER_HOP). See design §7.1.
    let mut filler: Vec<u8> = Vec::new();
    for s in secrets.iter().take(nu - 1) {
        filler.extend(std::iter::repeat_n(0u8, PER_HOP));
        let stream = chacha_keystream(&rho_key(s), BETA_LEN + PER_HOP);
        let l = filler.len();
        for (b, k) in filler.iter_mut().zip(&stream[BETA_LEN + PER_HOP - l..]) {
            *b ^= k;
        }
    }

    // Beta, built back-to-front. `mac_acc` carries gamma_{i+1}.
    let mut beta = vec![0u8; BETA_LEN];
    OsRng.fill_bytes(&mut beta); // random tail → unused slots indistinguishable
    let mut mac_acc = [0u8; MAC_LEN];
    for i in (0..nu).rev() {
        let mut hop_payload = [0u8; HOP_PAYLOAD];
        if i == nu - 1 {
            hop_payload[0] = FLAG_EXIT;
            OsRng.fill_bytes(&mut hop_payload[1..]);
        } else {
            hop_payload[0] = FLAG_FORWARD;
            hop_payload[1..1 + TAG_LEN].copy_from_slice(&hops[i + 1].routing_tag);
            hop_payload[1 + TAG_LEN..].copy_from_slice(&epks[i + 1]);
        }
        // newbeta = (hop_payload || mac_acc || beta)[..BETA_LEN]  (shift right PER_HOP)
        let mut newbeta = vec![0u8; BETA_LEN];
        newbeta[..HOP_PAYLOAD].copy_from_slice(&hop_payload);
        newbeta[HOP_PAYLOAD..PER_HOP].copy_from_slice(&mac_acc);
        newbeta[PER_HOP..].copy_from_slice(&beta[..BETA_LEN - PER_HOP]);
        let stream = chacha_keystream(&rho_key(&secrets[i]), BETA_LEN);
        for (b, k) in newbeta.iter_mut().zip(&stream) {
            *b ^= k;
        }
        if i == nu - 1 && !filler.is_empty() {
            newbeta[BETA_LEN - filler.len()..].copy_from_slice(&filler);
        }
        beta = newbeta;
        mac_acc = mac16(&mu_key(&secrets[i]), &beta);
    }

    // Payload onion: [len:2 LE][traffic][random pad], peeled by each hop.
    let mut payload = vec![0u8; PAYLOAD_LEN];
    payload[..2].copy_from_slice(&(traffic.len() as u16).to_le_bytes());
    payload[2..2 + traffic.len()].copy_from_slice(traffic);
    OsRng.fill_bytes(&mut payload[2 + traffic.len()..]);
    for s in secrets.iter().take(nu).rev() {
        chacha_apply(&pi_key(s), &mut payload);
    }

    let mut cell = Vec::with_capacity(CELL_SIZE);
    cell.push(TYPE_ONION_SPHINX);
    cell.extend_from_slice(&hops[0].routing_tag); // cleartext per-segment routing tag
    cell.extend_from_slice(&epks[0]);
    cell.extend_from_slice(&mac_acc); // gamma_0
    cell.extend_from_slice(&beta);
    cell.extend_from_slice(&payload);
    debug_assert_eq!(cell.len(), CELL_SIZE);
    Ok(cell)
}

// ── process ─────────────────────────────────────────────────────────────────

/// Process one cell at a relay/exit. Tries each candidate onion private key
/// (current / previous / identity-derived) and uses the one whose derived key
/// authenticates `beta`. Returns `Forward` or `Deliver`; never panics on
/// malformed input (only the fixed `CELL_SIZE` is asserted up front).
pub fn process_sphinx(cell: &[u8], onion_privs: &[&StaticSecret]) -> Result<SphinxPeeled> {
    if cell.len() != CELL_SIZE {
        bail!("sphinx process: cell is {} bytes, expected {CELL_SIZE}", cell.len());
    }
    if cell[0] != TYPE_ONION_SPHINX {
        bail!("sphinx process: wrong type byte 0x{:02x}", cell[0]);
    }
    let epk: [u8; 32] = cell[OFF_EPK..OFF_EPK + EPK_LEN].try_into().unwrap();
    let gamma = &cell[OFF_GAMMA..OFF_GAMMA + MAC_LEN];
    let beta = &cell[OFF_BETA..OFF_BETA + BETA_LEN];
    let payload = &cell[OFF_PAYLOAD..];

    // Identify our key via the MAC (also the "is this for me?" check).
    let mut shared: Option<[u8; 32]> = None;
    for &priv_ in onion_privs {
        let s = x25519_shared(priv_, &epk);
        if bool::from(mac16(&mu_key(&s), beta)[..].ct_eq(gamma)) {
            shared = Some(s);
            break;
        }
    }
    let s = shared.ok_or_else(|| anyhow::anyhow!("sphinx process: MAC mismatch (not for us)"))?;

    // Unwrap one header layer: B = (beta || zeros(PER_HOP)) XOR PRG.
    let mut b = vec![0u8; BETA_LEN + PER_HOP];
    b[..BETA_LEN].copy_from_slice(beta);
    let stream = chacha_keystream(&rho_key(&s), BETA_LEN + PER_HOP);
    for (x, k) in b.iter_mut().zip(&stream) {
        *x ^= k;
    }
    let flags = b[0];
    let next_tag: [u8; 16] = b[FLAGS_LEN..FLAGS_LEN + TAG_LEN].try_into().unwrap();
    let next_epk = &b[FLAGS_LEN + TAG_LEN..HOP_PAYLOAD];
    let next_mac = &b[HOP_PAYLOAD..PER_HOP];
    let beta2 = &b[PER_HOP..PER_HOP + BETA_LEN];

    // Peel one payload layer.
    let mut pl = payload.to_vec();
    chacha_apply(&pi_key(&s), &mut pl);

    match flags {
        FLAG_EXIT => {
            let orig_len = u16::from_le_bytes([pl[0], pl[1]]) as usize;
            if 2 + orig_len > pl.len() {
                bail!("sphinx process: bad inner payload length {orig_len}");
            }
            Ok(SphinxPeeled::Deliver(pl[2..2 + orig_len].to_vec()))
        }
        FLAG_FORWARD => {
            let mut next_cell = Vec::with_capacity(CELL_SIZE);
            next_cell.push(TYPE_ONION_SPHINX);
            next_cell.extend_from_slice(&next_tag); // rewrite the per-segment routing tag
            next_cell.extend_from_slice(next_epk);
            next_cell.extend_from_slice(next_mac);
            next_cell.extend_from_slice(beta2);
            next_cell.extend_from_slice(&pl);
            debug_assert_eq!(next_cell.len(), CELL_SIZE);
            Ok(SphinxPeeled::Forward { next_tag, cell: next_cell })
        }
        other => bail!("sphinx process: unknown flags byte 0x{other:02x}"),
    }
}

/// Replay-cache digest for a cell: BLAKE2b over (epk || first 16 `beta` bytes) —
/// the per-hop-fresh fields. The mutable cleartext routing tag is deliberately
/// excluded so a relay can't dodge the cache by rewriting it. `None` on bad size.
pub fn replay_digest(cell: &[u8]) -> Option<[u8; 32]> {
    if cell.len() != CELL_SIZE {
        return None;
    }
    let mut h = Blake2b::<U32>::new();
    h.update(b"norn:sphinx-replay");
    h.update(&cell[OFF_EPK..OFF_EPK + EPK_LEN]);
    h.update(&cell[OFF_BETA..OFF_BETA + 16]);
    Some(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Make `n` relays: returns (hops for `build`, their private keys for `process`).
    fn make_hops(n: usize) -> (Vec<SphinxHop>, Vec<StaticSecret>) {
        let mut hops = Vec::new();
        let mut privs = Vec::new();
        for i in 0..n {
            let sk = StaticSecret::random_from_rng(OsRng);
            let pk = *PublicKey::from(&sk).as_bytes();
            let mut tag = [0u8; 16];
            tag[0] = i as u8;
            tag[1] = 0xAB;
            hops.push(SphinxHop { routing_tag: tag, onion_pub: pk });
            privs.push(sk);
        }
        (hops, privs)
    }

    fn drive(hops: &[SphinxHop], privs: &[StaticSecret], traffic: &[u8]) -> Vec<u8> {
        let nu = hops.len();
        let mut cell = build_sphinx(hops, traffic).expect("build");
        for (i, priv_) in privs.iter().enumerate() {
            assert_eq!(cell.len(), CELL_SIZE, "hop {i}: cell must stay constant size");
            assert_eq!(cell[0], TYPE_ONION_SPHINX, "hop {i}: type byte preserved");
            assert_eq!(&cell[OFF_TAG..OFF_TAG + TAG_LEN], &hops[i].routing_tag,
                "hop {i}: cleartext routing tag must address this hop");
            match process_sphinx(&cell, &[priv_]).expect("process") {
                SphinxPeeled::Forward { next_tag, cell: next } => {
                    assert!(i < nu - 1, "hop {i} forwarded but should have delivered");
                    assert_eq!(next_tag, hops[i + 1].routing_tag, "hop {i}: wrong next tag");
                    cell = next;
                }
                SphinxPeeled::Deliver(t) => {
                    assert_eq!(i, nu - 1, "hop {i} delivered but is not the exit");
                    return t;
                }
            }
        }
        unreachable!("exit hop must Deliver");
    }

    #[test]
    fn round_trip_all_hop_counts() {
        for nu in 1..=MAX_HOPS {
            let (hops, privs) = make_hops(nu);
            let traffic: Vec<u8> = (0..200u32).map(|x| (x as u8) ^ (nu as u8)).collect();
            let got = drive(&hops, &privs, &traffic);
            assert_eq!(got, traffic, "nu={nu}: exit must recover exact traffic");
        }
    }

    #[test]
    fn cells_are_indistinguishable_in_size_for_1_vs_max_hops() {
        let (h1, _) = make_hops(1);
        let (h5, _) = make_hops(MAX_HOPS);
        let c1 = build_sphinx(&h1, b"hi").unwrap();
        let c5 = build_sphinx(&h5, b"hi").unwrap();
        assert_eq!(c1.len(), CELL_SIZE);
        assert_eq!(c5.len(), CELL_SIZE);
        // No field reveals the hop count: same lengths, same type byte.
        assert_eq!(c1[0], c5[0]);
    }

    #[test]
    fn empty_and_max_traffic() {
        let (hops, privs) = make_hops(3);
        assert_eq!(drive(&hops, &privs, b""), b"");
        let big = vec![0x5Au8; MAX_TRAFFIC_LEN];
        assert_eq!(drive(&hops, &privs, &big), big);
        assert!(build_sphinx(&hops, &vec![0u8; MAX_TRAFFIC_LEN + 1]).is_err());
    }

    #[test]
    fn tampered_beta_fails_mac_at_first_hop() {
        let (hops, privs) = make_hops(3);
        let mut cell = build_sphinx(&hops, b"payload").unwrap();
        cell[OFF_BETA + 10] ^= 0xFF; // flip a beta byte
        assert!(process_sphinx(&cell, &[&privs[0]]).is_err(),
            "tampered beta must fail the MAC, not forward");
    }

    #[test]
    fn tampered_gamma_fails() {
        let (hops, privs) = make_hops(2);
        let mut cell = build_sphinx(&hops, b"x").unwrap();
        cell[OFF_GAMMA] ^= 0x01;
        assert!(process_sphinx(&cell, &[&privs[0]]).is_err());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (hops, _privs) = make_hops(3);
        let cell = build_sphinx(&hops, b"x").unwrap();
        let stranger = StaticSecret::random_from_rng(OsRng);
        assert!(process_sphinx(&cell, &[&stranger]).is_err(),
            "a relay not on the path must not authenticate the cell");
    }

    #[test]
    fn process_never_panics_on_garbage() {
        let sk = StaticSecret::random_from_rng(OsRng);
        // wrong size
        assert!(process_sphinx(&[0u8; 10], &[&sk]).is_err());
        // right size, random content (wrong type byte / MAC)
        let mut junk = vec![0u8; CELL_SIZE];
        OsRng.fill_bytes(&mut junk);
        let _ = process_sphinx(&junk, &[&sk]); // must not panic
        // right type byte, random rest
        junk[0] = TYPE_ONION_SPHINX;
        assert!(process_sphinx(&junk, &[&sk]).is_err());
    }

    #[test]
    fn key_schedule_is_domain_separated() {
        let s = [7u8; 32];
        assert_ne!(rho_key(&s), mu_key(&s));
        assert_ne!(mu_key(&s), pi_key(&s));
        assert_ne!(rho_key(&s), pi_key(&s));
    }
}
