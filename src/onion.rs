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
}
