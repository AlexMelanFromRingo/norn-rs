// Onion routing for norn-rs
//
// Sphinx-inspired layered encryption. The sender wraps a Traffic packet in N
// concentric AEAD layers, one per relay. Each relay peels one layer:
//
//   Relay: decrypt → read next routing_tag → re-encode → forward
//   Exit:  decrypt → read inner Traffic bytes → deliver as local Traffic
//
// Privacy properties:
//   - Each relay knows only its predecessor and successor — not the full path.
//   - The exit relay knows the destination routing_tag but not the source.
//   - Relays between sender and exit see only opaque ciphertext.
//   - Combined with Traffic.enc_header, neither source nor destination identities
//     are visible to any relay.
//
// Forward secrecy (v0.3):
//   - Each relay maintains a rotating x25519 ephemeral keypair separate from
//     its long-term Ed25519 identity. The pub is announced (signed by identity)
//     via CoordAnnounce. The priv rotates every ONION_KEY_ROTATION_INTERVAL.
//     Old privs are zeroized on rotation. Past onion traffic that transited
//     a relay becomes undecryptable once the priv has rotated out.
//   - `OnionKeyChain` keeps current + one previous priv so that in-flight
//     onions sent just before a rotation can still be peeled.
//
// Wire format for an OnionPacket:
//   [TYPE_ONION: 1][routing_tag: 16][epk: 32][aead_len: varint][aead_payload]
//
// After peeling (AEAD decrypt), the plaintext starts with a type byte:
//   0x01 (ONION_FORWARD): [inner_len: varint][inner_onion_bytes]
//   0x00 (ONION_DELIVER): [traffic_len: varint][traffic_bytes]
//
// The inner_onion_bytes for FORWARD has the same layout as the outer packet
// (without the leading TYPE_ONION byte — that is added when re-encoding).
//
// Fixed-cell padding: see ONION_CELL_SIZE — every onion packet is padded to a
// constant total wire size, regardless of remaining hop count, to prevent
// a global passive observer from correlating packets across hops by size.

use anyhow::{bail, Result};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::Instant;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::packet::{decode_uvarint, encode_uvarint, routing_tag};
use crate::session::ed25519_priv_to_x25519;

pub const TYPE_ONION: u8 = 11;
const ONION_FORWARD: u8 = 0x01;
const ONION_DELIVER: u8 = 0x00;

/// Fixed total wire size of an onion cell (including the TYPE_ONION byte).
///
/// Every onion packet is padded to this size regardless of depth. This removes
/// the per-hop size signal that lets a passive observer correlate packets
/// across consecutive links. 1280 bytes matches the IPv6 minimum MTU so cells
/// fit inside the underlay path's MTU without fragmentation.
pub const ONION_CELL_SIZE: usize = 1280;

/// How long an onion ephemeral key remains valid before rotation.
pub const ONION_KEY_ROTATION_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(3600); // 1 hour

// ─────────────────────────────────────────────────────────────
// OnionKeyChain — rotating per-node ephemeral key
// ─────────────────────────────────────────────────────────────

/// Per-node rotating onion ephemeral keypair. Distinct from the node's
/// long-term Ed25519 identity. The current `priv` is used to peel incoming
/// onions; the `previous` priv is kept for one extra rotation period so that
/// onions built against the about-to-be-rotated pub can still be peeled.
pub struct OnionKeyChain {
    current_priv: StaticSecret,
    current_pub: X25519PublicKey,
    previous_priv: Option<StaticSecret>,
    rotated_at: Instant,
    /// Identity-derived X25519 priv. Used only as a *fallback* peel key when
    /// the sender didn't know our current ephemeral pub. Provides
    /// confidentiality but not forward secrecy. Stored here so peel() doesn't
    /// need the SigningKey passed in alongside.
    identity_x_priv: Option<StaticSecret>,
}

impl Default for OnionKeyChain {
    fn default() -> Self {
        Self::new()
    }
}

impl OnionKeyChain {
    pub fn new() -> Self {
        let current_priv = StaticSecret::random_from_rng(OsRng);
        let current_pub = X25519PublicKey::from(&current_priv);
        OnionKeyChain {
            current_priv,
            current_pub,
            previous_priv: None,
            rotated_at: Instant::now(),
            identity_x_priv: None,
        }
    }

    /// Construct a keychain that also accepts onion layers built against the
    /// identity-derived x25519 pub. Use this when peers may not yet have
    /// learned our advertised ephemeral pub (fallback path; provides
    /// confidentiality but not forward secrecy for those layers).
    pub fn with_identity_fallback(signing_key: &SigningKey) -> Self {
        let mut k = Self::new();
        k.identity_x_priv = Some(ed25519_priv_to_x25519(&signing_key.to_bytes()));
        k
    }

    /// Our current advertised ephemeral pub key.
    pub fn pub_key(&self) -> X25519PublicKey {
        self.current_pub
    }

    /// Rotate: move current → previous (zeroize-on-drop happens automatically
    /// when `previous` is overwritten on the *next* rotation), generate fresh.
    pub fn rotate(&mut self) {
        let mut new_priv = StaticSecret::random_from_rng(OsRng);
        let new_pub = X25519PublicKey::from(&new_priv);
        std::mem::swap(&mut self.current_priv, &mut new_priv);
        self.previous_priv = Some(new_priv); // the *old* current becomes previous
        self.current_pub = new_pub;
        self.rotated_at = Instant::now();
    }

    /// True if this chain is due for rotation.
    pub fn due_for_rotation(&self) -> bool {
        self.rotated_at.elapsed() >= ONION_KEY_ROTATION_INTERVAL
    }

    /// Try to peel a layer using current key, then previous if that fails.
    /// Returns the *plaintext* (without padding stripping; caller parses).
    fn try_decrypt(&self, epk: &[u8; 32], aead_payload: &[u8]) -> Result<Vec<u8>> {
        let epk_pub = X25519PublicKey::from(*epk);
        let nonce = Nonce::from([0u8; 12]);
        let aad = epk;

        // Current key first (the common case).
        {
            let shared = self.current_priv.diffie_hellman(&epk_pub);
            let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes()));
            let mut buf = aead_payload.to_vec();
            if cipher.decrypt_in_place(&nonce, aad, &mut buf).is_ok() {
                return Ok(buf);
            }
        }

        // Fall back to the previous (just-rotated-out) key.
        if let Some(prev) = &self.previous_priv {
            let shared = prev.diffie_hellman(&epk_pub);
            let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes()));
            let mut buf = aead_payload.to_vec();
            if cipher.decrypt_in_place(&nonce, aad, &mut buf).is_ok() {
                return Ok(buf);
            }
        }

        // Last resort: identity-derived key (no FS for this layer).
        if let Some(id_priv) = &self.identity_x_priv {
            let shared = id_priv.diffie_hellman(&epk_pub);
            let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes()));
            let mut buf = aead_payload.to_vec();
            if cipher.decrypt_in_place(&nonce, aad, &mut buf).is_ok() {
                return Ok(buf);
            }
        }

        bail!("onion peel: AEAD authentication failed against all available keys")
    }
}

// ─────────────────────────────────────────────────────────────
// OnionPacket
// ─────────────────────────────────────────────────────────────

/// One layer of an onion packet (what a relay receives and peels).
#[derive(Clone, Debug)]
pub struct OnionPacket {
    /// Routing tag for the current layer's intended recipient.
    pub routing_tag: [u8; 16],
    /// Ephemeral X25519 pub key used for this layer's ECDH.
    pub epk: [u8; 32],
    /// AEAD-encrypted payload (type byte + inner content + 16-byte tag).
    pub aead_payload: Vec<u8>,
}

impl OnionPacket {
    /// Encode as bytes starting with TYPE_ONION, padded to ONION_CELL_SIZE.
    /// Padding bytes after the AEAD-authenticated data are not encrypted but
    /// also carry no information — they're zeros — so the only goal is the
    /// constant-size property; integrity of payload is already covered by the
    /// AEAD tag inside `aead_payload`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = self.encode_unpadded(true);
        // Pad to fixed cell size for traffic-analysis resistance.
        if buf.len() < ONION_CELL_SIZE {
            buf.resize(ONION_CELL_SIZE, 0u8);
        }
        // If the unpadded encoding already exceeds ONION_CELL_SIZE, leave it
        // — the receiver enforces the cap separately. (This should not happen
        // for any single layer because we cap the inner content size.)
        buf
    }

    fn encode_unpadded(&self, include_type_byte: bool) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ONION_CELL_SIZE);
        if include_type_byte {
            buf.push(TYPE_ONION);
        }
        buf.extend_from_slice(&self.routing_tag);
        buf.extend_from_slice(&self.epk);
        encode_uvarint(self.aead_payload.len() as u64, &mut buf);
        buf.extend_from_slice(&self.aead_payload);
        buf
    }

    /// Decode from bytes that do NOT include the leading TYPE_ONION byte
    /// (i.e., pass `data[1..]` from a raw frame). Trailing padding bytes are
    /// ignored; the `aead_len` field tells us where the AEAD payload ends.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 48 {
            bail!("OnionPacket too short: {}", data.len());
        }
        let routing_tag: [u8; 16] = data[0..16].try_into().unwrap();
        let epk: [u8; 32] = data[16..48].try_into().unwrap();
        let mut pos = 48;
        let (aead_len, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        let aead_len_usize = usize::try_from(aead_len)
            .map_err(|_| anyhow::anyhow!("OnionPacket aead_len too large"))?;
        // Cap aead_len at ONION_CELL_SIZE to bound parsing cost regardless of
        // claimed length. (Genuine cells will always satisfy this.)
        if aead_len_usize > ONION_CELL_SIZE {
            bail!("OnionPacket aead_len {} exceeds cell size {}", aead_len_usize, ONION_CELL_SIZE);
        }
        let aead_end = pos.checked_add(aead_len_usize)
            .ok_or_else(|| anyhow::anyhow!("OnionPacket aead_len overflow"))?;
        if aead_end > data.len() {
            bail!("OnionPacket aead_payload truncated");
        }
        let aead_payload = data[pos..aead_end].to_vec();
        Ok(OnionPacket { routing_tag, epk, aead_payload })
    }

    /// Peel one encryption layer using a rotating ephemeral key chain.
    pub fn peel(&self, keys: &OnionKeyChain) -> Result<PeeledOnion> {
        let buf = keys.try_decrypt(&self.epk, &self.aead_payload)?;
        if buf.is_empty() {
            bail!("empty onion payload after decrypt");
        }
        match buf[0] {
            ONION_FORWARD => {
                let (inner_len, n) = decode_uvarint(&buf[1..])?;
                let end = 1 + n + inner_len as usize;
                if buf.len() < end {
                    bail!("onion forward payload truncated");
                }
                Ok(PeeledOnion::Forward(buf[1 + n..end].to_vec()))
            }
            ONION_DELIVER => {
                let (traf_len, n) = decode_uvarint(&buf[1..])?;
                let end = 1 + n + traf_len as usize;
                if buf.len() < end {
                    bail!("onion deliver payload truncated");
                }
                Ok(PeeledOnion::Deliver(buf[1 + n..end].to_vec()))
            }
            t => bail!("unknown onion type byte: {}", t),
        }
    }
}

/// Result of peeling one onion layer.
#[derive(Debug)]
pub enum PeeledOnion {
    /// This is a relay hop. Inner bytes encode the next OnionPacket (no TYPE_ONION prefix).
    Forward(Vec<u8>),
    /// This is the exit hop. Inner bytes are a full Traffic packet (WITH TYPE_TRAFFIC prefix).
    Deliver(Vec<u8>),
}

// ─────────────────────────────────────────────────────────────
// Onion construction
// ─────────────────────────────────────────────────────────────

/// One node in the onion path: (routing identity, current ephemeral x25519 pub).
///
/// The ephemeral pub is what the sender uses for DH; the identity is only used
/// to compute the routing_tag.
#[derive(Clone, Debug)]
pub struct OnionHop {
    pub identity_ed_pub: [u8; 32],
    pub ephemeral_x_pub: [u8; 32],
}

/// Build an onion-wrapped Traffic packet using ephemeral keys.
///
/// `relays`   — ordered list of relay (identity, ephemeral) pairs.
/// `dest`     — final destination's (identity, ephemeral) pair.
/// `traffic`  — already-encoded Traffic packet (WITH leading TYPE_TRAFFIC byte).
///
/// Returns the outermost OnionPacket, addressed to `relays[0]` (or `dest` if empty).
pub fn build_onion(
    relays: &[OnionHop],
    dest: &OnionHop,
    traffic_bytes: Vec<u8>,
) -> Result<OnionPacket> {
    let mut current = build_layer(dest, ONION_DELIVER, traffic_bytes)?;
    for relay in relays.iter().rev() {
        let inner_bytes = current.encode_inner();
        current = build_layer(relay, ONION_FORWARD, inner_bytes)?;
    }
    Ok(current)
}

fn build_layer(target: &OnionHop, layer_type: u8, content: Vec<u8>) -> Result<OnionPacket> {
    let tag = routing_tag(&target.identity_ed_pub);

    // Per-layer ephemeral sender keypair (separate from the relay's ephemeral
    // keypair). Discarded after use → forward secrecy of the layer key.
    let epk_priv = StaticSecret::random_from_rng(OsRng);
    let epk_pub = X25519PublicKey::from(&epk_priv);

    // DH against the relay's *current advertised ephemeral* pub.
    let relay_eph_pub = X25519PublicKey::from(target.ephemeral_x_pub);
    let shared = epk_priv.diffie_hellman(&relay_eph_pub);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes()));
    let nonce = Nonce::from([0u8; 12]);
    let aad = epk_pub.as_bytes();

    // Plaintext: [type][varint(content_len)][content]
    let mut plaintext = vec![layer_type];
    encode_uvarint(content.len() as u64, &mut plaintext);
    plaintext.extend_from_slice(&content);

    // NOTE: the per-layer plaintext is deliberately NOT padded here. Only the
    // OUTERMOST wire packet is zero-padded to ONION_CELL_SIZE (see `encode`), so
    // every cell is 1280 B on the wire and relays re-pad on forward.
    //
    // KNOWN LIMITATION (REVIEW-FINDINGS #3): the per-layer `aead_len` varint is
    // cleartext and shrinks ~67 B per hop, which leaks onion depth to anyone who
    // can read consecutive hops' cells — mitigated by QUIC link encryption but
    // exposed on the raw-TCP transport. Making `aead_len` constant is impossible
    // with this nested-AEAD + variable-hop format (an equal-sized inner can't fit
    // inside an equal-sized outer); removing the leak needs a Sphinx-style mix
    // format with a fixed header + wide-block payload. Tracked as a follow-up.

    cipher
        .encrypt_in_place(&nonce, aad, &mut plaintext)
        .map_err(|e| anyhow::anyhow!("onion encrypt layer: {:?}", e))?;

    Ok(OnionPacket {
        routing_tag: tag,
        epk: *epk_pub.as_bytes(),
        aead_payload: plaintext,
    })
}

impl OnionPacket {
    /// Encode without the leading TYPE_ONION byte (used as inner content in outer layers).
    /// NOT padded — padding is only applied to the outermost wire encoding.
    fn encode_inner(&self) -> Vec<u8> {
        self.encode_unpadded(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn hop_from_signing_key(sk: &SigningKey) -> (OnionHop, OnionKeyChain) {
        let chain = OnionKeyChain::new();
        let hop = OnionHop {
            identity_ed_pub: sk.verifying_key().to_bytes(),
            ephemeral_x_pub: *chain.pub_key().as_bytes(),
        };
        (hop, chain)
    }

    #[test]
    fn onion_roundtrip_no_relays() {
        let dest_sk = SigningKey::generate(&mut OsRng);
        let (dest_hop, dest_keys) = hop_from_signing_key(&dest_sk);

        let traffic = b"hello world traffic".to_vec();
        let packet = build_onion(&[], &dest_hop, traffic.clone()).unwrap();

        match packet.peel(&dest_keys).unwrap() {
            PeeledOnion::Deliver(bytes) => assert_eq!(bytes, traffic),
            PeeledOnion::Forward(_) => panic!("expected Deliver"),
        }
    }

    #[test]
    fn onion_roundtrip_two_relays() {
        let r1_sk = SigningKey::generate(&mut OsRng);
        let r2_sk = SigningKey::generate(&mut OsRng);
        let dest_sk = SigningKey::generate(&mut OsRng);
        let (r1_hop, r1_keys) = hop_from_signing_key(&r1_sk);
        let (r2_hop, r2_keys) = hop_from_signing_key(&r2_sk);
        let (dest_hop, dest_keys) = hop_from_signing_key(&dest_sk);

        let traffic = b"secret payload".to_vec();
        let packet = build_onion(
            &[r1_hop.clone(), r2_hop.clone()],
            &dest_hop,
            traffic.clone(),
        )
        .unwrap();

        // Outer addresses relay1.
        assert_eq!(packet.routing_tag, routing_tag(&r1_hop.identity_ed_pub));

        // Relay 1 peels.
        let inner1_bytes = match packet.peel(&r1_keys).unwrap() {
            PeeledOnion::Forward(b) => b,
            PeeledOnion::Deliver(_) => panic!("relay1 should forward"),
        };
        let inner1 = OnionPacket::decode(&inner1_bytes).unwrap();
        assert_eq!(inner1.routing_tag, routing_tag(&r2_hop.identity_ed_pub));

        // Relay 2 peels.
        let inner2_bytes = match inner1.peel(&r2_keys).unwrap() {
            PeeledOnion::Forward(b) => b,
            PeeledOnion::Deliver(_) => panic!("relay2 should forward"),
        };
        let inner2 = OnionPacket::decode(&inner2_bytes).unwrap();

        match inner2.peel(&dest_keys).unwrap() {
            PeeledOnion::Deliver(bytes) => assert_eq!(bytes, traffic),
            PeeledOnion::Forward(_) => panic!("dest should deliver"),
        }
    }

    #[test]
    fn onion_wrong_key_fails() {
        let dest_sk = SigningKey::generate(&mut OsRng);
        let (dest_hop, _) = hop_from_signing_key(&dest_sk);
        let other_keys = OnionKeyChain::new(); // unrelated keypair

        let packet = build_onion(&[], &dest_hop, b"payload".to_vec()).unwrap();
        assert!(packet.peel(&other_keys).is_err());
    }

    #[test]
    fn rotation_keeps_in_flight_decryptable_once() {
        let dest_sk = SigningKey::generate(&mut OsRng);
        let (dest_hop, mut dest_keys) = hop_from_signing_key(&dest_sk);

        let traffic = b"in-flight".to_vec();
        let packet = build_onion(&[], &dest_hop, traffic.clone()).unwrap();

        // Rotate ONCE: previous key is now the one the packet was built against.
        dest_keys.rotate();
        match packet.peel(&dest_keys).expect("must decrypt with previous key") {
            PeeledOnion::Deliver(bytes) => assert_eq!(bytes, traffic),
            _ => panic!("expected Deliver"),
        }
    }

    #[test]
    fn rotation_twice_loses_old_key() {
        let dest_sk = SigningKey::generate(&mut OsRng);
        let (dest_hop, mut dest_keys) = hop_from_signing_key(&dest_sk);

        let traffic = b"forward secret".to_vec();
        let packet = build_onion(&[], &dest_hop, traffic).unwrap();

        // Two rotations: original key is gone (previous slot now holds the
        // first rotated key, not the original). Forward secrecy property.
        dest_keys.rotate();
        dest_keys.rotate();
        assert!(packet.peel(&dest_keys).is_err(),
            "after 2 rotations the original key must be gone (FS)");
    }

    #[test]
    fn rotation_changes_pub_key() {
        let mut chain = OnionKeyChain::new();
        let before = *chain.pub_key().as_bytes();
        chain.rotate();
        let after = *chain.pub_key().as_bytes();
        assert_ne!(before, after, "rotate must change the public key");
    }

    // ── decode boundary tests ─────────────────────────────────────────────────

    #[test]
    fn decode_47_bytes_fails() {
        assert!(OnionPacket::decode(&[0u8; 47]).is_err());
    }

    #[test]
    fn decode_minimal_valid_packet() {
        let mut data = vec![0u8; 48];
        data.push(0u8); // uvarint(0)
        let result = OnionPacket::decode(&data);
        assert!(result.is_ok(), "49-byte minimal packet must succeed: {:?}", result.err());
        assert_eq!(result.unwrap().aead_payload.len(), 0);
    }

    #[test]
    fn decode_exactly_48_bytes_fails_at_uvarint_not_too_short() {
        let data = [0u8; 48];
        let err = OnionPacket::decode(&data).unwrap_err().to_string();
        assert!(!err.contains("too short"),
            "48-byte input must fail at uvarint parse, not 'too short'; got: {err}");
    }

    #[test]
    fn decode_aead_truncated_fails() {
        let mut data = vec![0u8; 48];
        encode_uvarint(100, &mut data);
        data.extend_from_slice(&[0u8; 5]);
        assert!(OnionPacket::decode(&data).is_err());
    }

    #[test]
    fn decode_aead_len_above_cell_size_rejected() {
        let mut data = vec![0u8; 48];
        // Claim 2 MiB.
        encode_uvarint(2 * 1024 * 1024, &mut data);
        let err = OnionPacket::decode(&data).unwrap_err().to_string();
        assert!(err.contains("cell size") || err.contains("exceeds"),
            "oversized aead_len must mention cell size; got: {err}");
    }

    // ── fixed-cell padding ────────────────────────────────────────────────────

    #[test]
    fn encoded_packet_pads_to_cell_size() {
        let sk = SigningKey::generate(&mut OsRng);
        let (hop, _keys) = hop_from_signing_key(&sk);
        let packet = build_onion(&[], &hop, b"small".to_vec()).unwrap();
        let encoded = packet.encode();
        assert_eq!(encoded.len(), ONION_CELL_SIZE,
            "every onion packet must be padded to ONION_CELL_SIZE");
    }

    #[test]
    fn cell_size_independent_of_depth() {
        // A 0-relay and a 2-relay onion to small payloads should both wire to
        // exactly ONION_CELL_SIZE.
        let dest_sk = SigningKey::generate(&mut OsRng);
        let r1_sk = SigningKey::generate(&mut OsRng);
        let r2_sk = SigningKey::generate(&mut OsRng);
        let (dest_hop, _) = hop_from_signing_key(&dest_sk);
        let (r1_hop, _) = hop_from_signing_key(&r1_sk);
        let (r2_hop, _) = hop_from_signing_key(&r2_sk);

        let p0 = build_onion(&[], &dest_hop, b"a".to_vec()).unwrap().encode();
        let p2 = build_onion(&[r1_hop, r2_hop], &dest_hop, b"a".to_vec()).unwrap().encode();
        assert_eq!(p0.len(), ONION_CELL_SIZE);
        assert_eq!(p2.len(), ONION_CELL_SIZE);
        assert_eq!(p0.len(), p2.len(),
            "cell size must not depend on onion depth (traffic-analysis resistance)");
    }

    // ── encode/decode roundtrip ──────────────────────────────────────────────

    #[test]
    fn encode_decode_onionpacket_roundtrip() {
        let pkt = OnionPacket {
            routing_tag: [0xABu8; 16],
            epk: [0xCDu8; 32],
            aead_payload: vec![1, 2, 3, 4, 5],
        };
        let enc = pkt.encode();
        assert_eq!(enc[0], crate::packet::TYPE_ONION, "first byte must be TYPE_ONION");
        let dec = OnionPacket::decode(&enc[1..]).unwrap();
        assert_eq!(dec.routing_tag, pkt.routing_tag);
        assert_eq!(dec.epk, pkt.epk);
        assert_eq!(dec.aead_payload, pkt.aead_payload);
    }

    // ── outer routing_tag addresses correct hop ──────────────────────────────

    #[test]
    fn build_onion_outer_tag_addresses_first_relay() {
        let relay_sk = SigningKey::generate(&mut OsRng);
        let dest_sk  = SigningKey::generate(&mut OsRng);
        let (relay_hop, _) = hop_from_signing_key(&relay_sk);
        let (dest_hop, _) = hop_from_signing_key(&dest_sk);
        let pkt = build_onion(std::slice::from_ref(&relay_hop), &dest_hop, b"payload".to_vec()).unwrap();
        assert_eq!(pkt.routing_tag, routing_tag(&relay_hop.identity_ed_pub),
            "outer routing_tag must address first relay, not destination");
    }

    #[test]
    fn build_onion_no_relays_tag_addresses_dest() {
        let dest_sk = SigningKey::generate(&mut OsRng);
        let (dest_hop, _) = hop_from_signing_key(&dest_sk);
        let pkt = build_onion(&[], &dest_hop, b"data".to_vec()).unwrap();
        assert_eq!(pkt.routing_tag, routing_tag(&dest_hop.identity_ed_pub),
            "with no relays, outer tag must address dest");
    }

    // Trailing-byte boundary test: peel should reject onion packets that claim
    // an inner length but the AEAD plaintext has fewer bytes (truncation).
    #[test]
    fn peel_inner_truncated_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let chain = OnionKeyChain::new();

        // Build a layer with a declared content length larger than what's there.
        let epk_priv = StaticSecret::random_from_rng(OsRng);
        let epk_pub = X25519PublicKey::from(&epk_priv);
        let shared = epk_priv.diffie_hellman(&chain.pub_key());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes()));
        let nonce = Nonce::from([0u8; 12]);
        let aad = epk_pub.as_bytes();

        let mut plaintext = vec![ONION_FORWARD];
        encode_uvarint(100, &mut plaintext); // claim 100 bytes
        plaintext.extend_from_slice(&[0u8; 4]); // provide 4
        cipher.encrypt_in_place(&nonce, aad, &mut plaintext).unwrap();

        let pkt = OnionPacket {
            routing_tag: [0u8; 16],
            epk: *epk_pub.as_bytes(),
            aead_payload: plaintext,
        };
        let _ = &sk;
        let err = pkt.peel(&chain).unwrap_err().to_string();
        assert!(err.contains("truncated"),
            "inner-truncated onion must be rejected; got: {err}");
    }
}
