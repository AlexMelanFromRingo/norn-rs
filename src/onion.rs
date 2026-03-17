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
// Limitation: packet size decreases with each peel, leaking hop count to a
// global observer. Fixed-size cells (Tor-style) are left as a future TODO.

use anyhow::{bail, Result};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::packet::{decode_uvarint, encode_uvarint, routing_tag};
use crate::session::{ed25519_priv_to_x25519, ed25519_pub_to_x25519};

pub const TYPE_ONION: u8 = 11;
const ONION_FORWARD: u8 = 0x01;
const ONION_DELIVER: u8 = 0x00;

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
    /// Encode as bytes starting with TYPE_ONION.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![TYPE_ONION];
        buf.extend_from_slice(&self.routing_tag);
        buf.extend_from_slice(&self.epk);
        encode_uvarint(self.aead_payload.len() as u64, &mut buf);
        buf.extend_from_slice(&self.aead_payload);
        buf
    }

    /// Decode from bytes that do NOT include the leading TYPE_ONION byte
    /// (i.e., pass `data[1..]` from a raw frame).
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 48 {
            bail!("OnionPacket too short: {}", data.len());
        }
        let routing_tag: [u8; 16] = data[0..16].try_into().unwrap();
        let epk: [u8; 32] = data[16..48].try_into().unwrap();
        let mut pos = 48;
        let (aead_len, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        if data.len() < pos + aead_len as usize {
            bail!("OnionPacket aead_payload truncated");
        }
        let aead_payload = data[pos..pos + aead_len as usize].to_vec();
        Ok(OnionPacket { routing_tag, epk, aead_payload })
    }

    /// Peel one encryption layer using our ed25519 signing key.
    ///
    /// Returns `PeeledOnion::Forward(inner)` if this is a relay hop — `inner`
    /// contains the bytes of the next OnionPacket (without TYPE_ONION prefix).
    /// Returns `PeeledOnion::Deliver(traffic_bytes)` if this is the exit hop.
    pub fn peel(&self, my_sk: &SigningKey) -> Result<PeeledOnion> {
        let epk_pub = X25519PublicKey::from(self.epk);
        let my_x = ed25519_priv_to_x25519(&my_sk.to_bytes());
        let shared = my_x.diffie_hellman(&epk_pub);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes()));
        let nonce = Nonce::from([0u8; 12]);
        let aad = &self.epk; // authenticate the ephemeral key

        let mut buf = self.aead_payload.clone();
        cipher
            .decrypt_in_place(&nonce, aad, &mut buf)
            .map_err(|_| anyhow::anyhow!("onion peel: AEAD authentication failed"))?;

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
pub enum PeeledOnion {
    /// This is a relay hop. Inner bytes encode the next OnionPacket (no TYPE_ONION prefix).
    Forward(Vec<u8>),
    /// This is the exit hop. Inner bytes are a full Traffic packet (WITH TYPE_TRAFFIC prefix).
    Deliver(Vec<u8>),
}

// ─────────────────────────────────────────────────────────────
// Onion construction
// ─────────────────────────────────────────────────────────────

/// Build an onion-wrapped Traffic packet.
///
/// `relays`         — ordered list of relay ed25519 pub keys (0 = no relays = direct).
/// `dest_ed_pub`    — final destination ed25519 pub key.
/// `traffic_bytes`  — already-encoded Traffic packet (WITH leading TYPE_TRAFFIC byte).
///
/// Returns the outermost OnionPacket, addressed to `relays[0]` (or `dest` if empty).
pub fn build_onion(
    relays: &[[u8; 32]],
    dest_ed_pub: &[u8; 32],
    traffic_bytes: Vec<u8>,
) -> Result<OnionPacket> {
    // Innermost layer: DELIVER to dest
    let mut current = build_layer(dest_ed_pub, ONION_DELIVER, traffic_bytes)?;

    // Wrap with relay layers from innermost to outermost
    for relay in relays.iter().rev() {
        let inner_bytes = current.encode_inner(); // without TYPE_ONION prefix
        current = build_layer(relay, ONION_FORWARD, inner_bytes)?;
    }

    Ok(current)
}

fn build_layer(target_ed_pub: &[u8; 32], layer_type: u8, content: Vec<u8>) -> Result<OnionPacket> {
    let tag = routing_tag(target_ed_pub);

    // Ephemeral X25519 keypair
    let epk_priv = StaticSecret::random_from_rng(OsRng);
    let epk_pub = X25519PublicKey::from(&epk_priv);
    let dest_x = ed25519_pub_to_x25519(target_ed_pub)?;
    let shared = epk_priv.diffie_hellman(&dest_x);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes()));
    let nonce = Nonce::from([0u8; 12]);
    let aad = epk_pub.as_bytes();

    // Plaintext: [type][varint(content_len)][content]
    let mut plaintext = vec![layer_type];
    encode_uvarint(content.len() as u64, &mut plaintext);
    plaintext.extend_from_slice(&content);

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
    fn encode_inner(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.routing_tag);
        buf.extend_from_slice(&self.epk);
        encode_uvarint(self.aead_payload.len() as u64, &mut buf);
        buf.extend_from_slice(&self.aead_payload);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn onion_roundtrip_no_relays() {
        let dest_sk = SigningKey::generate(&mut OsRng);
        let dest_pub = dest_sk.verifying_key().to_bytes();

        let traffic = b"hello world traffic".to_vec();
        let packet = build_onion(&[], &dest_pub, traffic.clone()).unwrap();

        // Dest peels the single delivery layer
        match packet.peel(&dest_sk).unwrap() {
            PeeledOnion::Deliver(bytes) => assert_eq!(bytes, traffic),
            PeeledOnion::Forward(_) => panic!("expected Deliver"),
        }
    }

    #[test]
    fn onion_roundtrip_two_relays() {
        let relay1_sk = SigningKey::generate(&mut OsRng);
        let relay2_sk = SigningKey::generate(&mut OsRng);
        let dest_sk = SigningKey::generate(&mut OsRng);

        let relay1_pub = relay1_sk.verifying_key().to_bytes();
        let relay2_pub = relay2_sk.verifying_key().to_bytes();
        let dest_pub = dest_sk.verifying_key().to_bytes();

        let traffic = b"secret payload".to_vec();
        let packet = build_onion(
            &[relay1_pub, relay2_pub],
            &dest_pub,
            traffic.clone(),
        )
        .unwrap();

        // Confirm outer packet is addressed to relay1
        let my_tag = routing_tag(&relay1_pub);
        assert_eq!(packet.routing_tag, my_tag);

        // Relay 1 peels
        let inner1_bytes = match packet.peel(&relay1_sk).unwrap() {
            PeeledOnion::Forward(b) => b,
            PeeledOnion::Deliver(_) => panic!("relay1 should forward"),
        };
        let inner1 = OnionPacket::decode(&inner1_bytes).unwrap();

        // Confirm next layer is addressed to relay2
        let relay2_tag = routing_tag(&relay2_pub);
        assert_eq!(inner1.routing_tag, relay2_tag);

        // Relay 2 peels
        let inner2_bytes = match inner1.peel(&relay2_sk).unwrap() {
            PeeledOnion::Forward(b) => b,
            PeeledOnion::Deliver(_) => panic!("relay2 should forward"),
        };
        let inner2 = OnionPacket::decode(&inner2_bytes).unwrap();

        // Dest receives the delivery layer
        match inner2.peel(&dest_sk).unwrap() {
            PeeledOnion::Deliver(bytes) => assert_eq!(bytes, traffic),
            PeeledOnion::Forward(_) => panic!("dest should deliver"),
        }
    }

    #[test]
    fn onion_wrong_key_fails() {
        let dest_sk = SigningKey::generate(&mut OsRng);
        let wrong_sk = SigningKey::generate(&mut OsRng);
        let dest_pub = dest_sk.verifying_key().to_bytes();

        let packet = build_onion(&[], &dest_pub, b"payload".to_vec()).unwrap();
        // Peel with wrong key should fail AEAD authentication
        assert!(packet.peel(&wrong_sk).is_err());
    }

    // ── decode boundary tests (kills < vs == and < vs <= mutations) ───────────

    #[test]
    fn decode_47_bytes_fails() {
        // Header = 16 (tag) + 32 (epk) = 48 bytes minimum.
        // 47 bytes must fail. Mutation `< 48` → `== 48` would not trigger on 47.
        assert!(OnionPacket::decode(&[0u8; 47]).is_err(),
            "47 bytes must fail");
    }

    #[test]
    fn decode_minimal_valid_packet() {
        // 48 bytes header + uvarint(0) = 49 bytes for empty aead_payload.
        let mut data = vec![0u8; 48]; // routing_tag + epk
        data.push(0u8);               // uvarint(0): empty aead_payload
        let result = OnionPacket::decode(&data);
        assert!(result.is_ok(), "49-byte minimal packet must succeed: {:?}", result.err());
        assert_eq!(result.unwrap().aead_payload.len(), 0);
    }

    // Kills `< 48 → <= 48` mutation on line 71.
    // With `< 48`: 48 bytes passes the initial check, then decode_uvarint on empty
    // slice fails (not "too short"). With `<= 48`: 48 bytes fails as "too short".
    #[test]
    fn decode_exactly_48_bytes_fails_at_uvarint_not_too_short() {
        let data = [0u8; 48]; // exactly the header size, no uvarint byte
        let err = OnionPacket::decode(&data).unwrap_err().to_string();
        assert!(!err.contains("too short"),
            "48-byte input must fail at uvarint parse, not 'too short'; got: {err}");
    }

    #[test]
    fn decode_aead_truncated_fails() {
        // Claims aead_len=100 but provides only 5. Tests inner truncation guard.
        // Mutation `< pos+aead_len` → `> pos+aead_len` would accept truncated data.
        let mut data = vec![0u8; 48]; // header
        encode_uvarint(100, &mut data);
        data.extend_from_slice(&[0u8; 5]); // only 5 of 100 claimed bytes
        assert!(OnionPacket::decode(&data).is_err(), "truncated aead must fail");
    }

    // ── routing_tag must address correct recipient ─────────────────────────────

    #[test]
    fn build_onion_outer_tag_addresses_first_relay() {
        let relay_sk = SigningKey::generate(&mut OsRng);
        let dest_sk  = SigningKey::generate(&mut OsRng);
        let relay_pub = relay_sk.verifying_key().to_bytes();
        let dest_pub  = dest_sk.verifying_key().to_bytes();
        let pkt = build_onion(&[relay_pub], &dest_pub, b"payload".to_vec()).unwrap();
        assert_eq!(pkt.routing_tag, routing_tag(&relay_pub),
            "outer routing_tag must address first relay, not destination");
    }

    #[test]
    fn build_onion_no_relays_tag_addresses_dest() {
        let dest_sk = SigningKey::generate(&mut OsRng);
        let dest_pub = dest_sk.verifying_key().to_bytes();
        let pkt = build_onion(&[], &dest_pub, b"data".to_vec()).unwrap();
        assert_eq!(pkt.routing_tag, routing_tag(&dest_pub),
            "with no relays, outer tag must address dest");
    }

    // ── peel correctness ──────────────────────────────────────────────────────

    #[test]
    fn peel_relay_returns_forward_not_deliver() {
        let relay_sk = SigningKey::generate(&mut OsRng);
        let dest_sk  = SigningKey::generate(&mut OsRng);
        let relay_pub = relay_sk.verifying_key().to_bytes();
        let dest_pub  = dest_sk.verifying_key().to_bytes();
        let pkt = build_onion(&[relay_pub], &dest_pub, b"data".to_vec()).unwrap();
        match pkt.peel(&relay_sk).unwrap() {
            PeeledOnion::Forward(_) => {} // correct
            PeeledOnion::Deliver(_) => panic!("relay must Forward, not Deliver"),
        }
    }

    #[test]
    fn peel_dest_returns_deliver_not_forward() {
        let dest_sk  = SigningKey::generate(&mut OsRng);
        let dest_pub = dest_sk.verifying_key().to_bytes();
        let payload  = b"exact_payload_bytes".to_vec();
        let pkt = build_onion(&[], &dest_pub, payload.clone()).unwrap();
        match pkt.peel(&dest_sk).unwrap() {
            PeeledOnion::Deliver(bytes) => {
                assert_eq!(bytes, payload, "Deliver payload must match original");
            }
            PeeledOnion::Forward(_) => panic!("dest must Deliver, not Forward"),
        }
    }

    // Helper: build an OnionPacket whose decrypted plaintext has `extra` bytes
    // appended after the declared inner_len bytes. This gives buf.len() > end
    // after peel(), which triggers the `< → >` mutation on lines 111/119 but
    // not the original `< end` guard.
    fn make_onion_with_extra_bytes(
        receiver_sk: &SigningKey,
        layer_type: u8,
        declared_len: usize,
        actual_content: &[u8],
    ) -> OnionPacket {
        let epk_priv = StaticSecret::random_from_rng(OsRng);
        let epk_pub = X25519PublicKey::from(&epk_priv);
        let dest_x = ed25519_pub_to_x25519(&receiver_sk.verifying_key().to_bytes()).unwrap();
        let shared = epk_priv.diffie_hellman(&dest_x);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes()));
        let nonce = Nonce::from([0u8; 12]);
        let aad = epk_pub.as_bytes();

        // Plaintext: [type | varint(declared_len) | actual_content]
        // actual_content.len() > declared_len → buf.len() > end after decrypt
        let mut plaintext = vec![layer_type];
        encode_uvarint(declared_len as u64, &mut plaintext);
        plaintext.extend_from_slice(actual_content);

        cipher.encrypt_in_place(&nonce, aad, &mut plaintext).unwrap();
        OnionPacket { routing_tag: [0u8; 16], epk: *epk_pub.as_bytes(), aead_payload: plaintext }
    }

    // Kills `< end → > end` mutation on line 111 (ONION_FORWARD branch).
    // declared_len=5, actual_content=8 bytes → buf.len()=10, end=7 → buf.len() > end.
    // Original `< end`: 10 < 7? No → OK → Forward(first 5 bytes).
    // Mutation `> end`: 10 > 7? Yes → bail "truncated" → Err → test fails.
    #[test]
    fn peel_forward_with_trailing_bytes_succeeds() {
        let sk = SigningKey::generate(&mut OsRng);
        let pkt = make_onion_with_extra_bytes(
            &sk, ONION_FORWARD, 5, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        );
        let result = pkt.peel(&sk);
        assert!(result.is_ok(),
            "peel FORWARD with extra trailing bytes must succeed: {:?}", result.err());
        match result.unwrap() {
            PeeledOnion::Forward(inner) => assert_eq!(inner.len(), 5,
                "Forward inner must be exactly declared_len bytes, got {}", inner.len()),
            PeeledOnion::Deliver(_) => panic!("expected Forward"),
        }
    }

    // Kills `< end → > end` mutation on line 119 (ONION_DELIVER branch).
    #[test]
    fn peel_deliver_with_trailing_bytes_succeeds() {
        let sk = SigningKey::generate(&mut OsRng);
        let pkt = make_onion_with_extra_bytes(
            &sk, ONION_DELIVER, 4, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        );
        let result = pkt.peel(&sk);
        assert!(result.is_ok(),
            "peel DELIVER with extra trailing bytes must succeed: {:?}", result.err());
        match result.unwrap() {
            PeeledOnion::Deliver(inner) => assert_eq!(inner.len(), 4,
                "Deliver inner must be exactly declared_len bytes, got {}", inner.len()),
            PeeledOnion::Forward(_) => panic!("expected Deliver"),
        }
    }

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
}
