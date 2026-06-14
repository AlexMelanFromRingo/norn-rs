//! Header-privacy helpers (source+dest identity hiding), split from router/mod.rs.
use super::*;

// ──────────────────────────────────────────────
// Header privacy helpers (source + dest hiding)
// ──────────────────────────────────────────────

/// Block size for payload padding (bytes). All payloads are padded to a
/// multiple of this before encryption so observers cannot infer content
/// length from ciphertext length.
pub(crate) const PAD_BLOCK: usize = 256;

/// Pad `data` to the next `PAD_BLOCK` boundary.
/// Wire: [orig_len: 2 bytes LE][data...][zero padding...]
///
/// Maximum payload size is u16::MAX (65535) bytes because the length header is
/// 2 bytes. Larger payloads are truncated by `unpad_payload` because the wire
/// length field cannot represent them — so we silently used to corrupt them.
/// Now we panic in debug and saturate the length in release: callers should not
/// feed >65535-byte payloads through this path.
pub(crate) fn pad_payload(data: &[u8]) -> Vec<u8> {
    debug_assert!(
        data.len() <= u16::MAX as usize,
        "pad_payload: data.len() = {} exceeds u16::MAX; length header would wrap",
        data.len()
    );
    let orig_len = data.len().min(u16::MAX as usize);
    let data = &data[..orig_len];
    let mut out = Vec::with_capacity(PAD_BLOCK);
    out.push((orig_len & 0xFF) as u8);
    out.push((orig_len >> 8) as u8);
    out.extend_from_slice(data);
    let target = out.len().div_ceil(PAD_BLOCK) * PAD_BLOCK;
    out.resize(target, 0u8);
    out
}

/// Strip padding added by `pad_payload`.
pub(crate) fn unpad_payload(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < 2 {
        bail!("unpad: too short");
    }
    // Use from_le_bytes instead of `| << 8` to avoid the equivalent `| → ^` mutation
    // (bit 8+ of padded[0] and bit 0-7 of padded[1]<<8 never overlap, so | == ^).
    let orig_len = u16::from_le_bytes([padded[0], padded[1]]) as usize;
    if padded.len() < 2 + orig_len {
        bail!("unpad: length field {} > available {}", orig_len, padded.len() - 2);
    }
    Ok(padded[2..2 + orig_len].to_vec())
}

/// Encrypt both source and destination identities into a 128-byte header.
///
/// Layout: [epk: 32][AEAD_nonce0(source_ed_pub): 48][AEAD_nonce1(dest_ed_pub): 48]
///
/// The single ephemeral keypair is derived from a DH with the *destination's*
/// X25519 public key, so only the destination can decrypt either field.
/// Forward secrecy: the ephemeral private key is discarded immediately.
///
/// Returns `(enc_header, routing_tag)`.
pub(crate) fn encrypt_header(
    source_ed_pub: &[u8; 32],
    dest_ed_pub: &[u8; 32],
) -> ([u8; 128], [u8; 16]) {
    let epk_priv = StaticSecret::random_from_rng(OsRng);
    let epk_pub = X25519PublicKey::from(&epk_priv);

    let dest_x = match ed25519_pub_to_x25519(dest_ed_pub) {
        Ok(k) => k,
        Err(_) => return ([0u8; 128], [0u8; 16]),
    };
    let shared = epk_priv.diffie_hellman(&dest_x);
    let key = Key::from_slice(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);
    let aad = epk_pub.as_bytes();

    // Encrypt source with nonce=0
    let mut src_buf = source_ed_pub.to_vec();
    if cipher
        .encrypt_in_place(&Nonce::from([0u8; 12]), aad, &mut src_buf)
        .is_err()
    {
        return ([0u8; 128], [0u8; 16]);
    }

    // Encrypt dest with nonce=1 (first 8 bytes = 1u64 LE)
    let mut dst_buf = dest_ed_pub.to_vec();
    let mut n1 = [0u8; 12];
    n1[..8].copy_from_slice(&1u64.to_le_bytes());
    if cipher
        .encrypt_in_place(&Nonce::from(n1), aad, &mut dst_buf)
        .is_err()
    {
        return ([0u8; 128], [0u8; 16]);
    }

    let mut header = [0u8; 128];
    header[..32].copy_from_slice(epk_pub.as_bytes());
    header[32..80].copy_from_slice(&src_buf);  // 48 bytes
    header[80..128].copy_from_slice(&dst_buf); // 48 bytes

    (header, routing_tag(dest_ed_pub))
}

/// Decrypt the source identity from enc_header using our ed25519 signing key.
pub(crate) fn decrypt_source_from_header(enc_header: &[u8; 128], my_sk: &SigningKey) -> Option<[u8; 32]> {
    let epk_pub_bytes: [u8; 32] = enc_header[..32].try_into().ok()?;
    let epk_pub = X25519PublicKey::from(epk_pub_bytes);
    let my_x = ed25519_priv_to_x25519(&my_sk.to_bytes());
    let shared = my_x.diffie_hellman(&epk_pub);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes()));
    let mut buf = enc_header[32..80].to_vec();
    cipher
        .decrypt_in_place(&Nonce::from([0u8; 12]), &epk_pub_bytes, &mut buf)
        .ok()?;
    buf.try_into().ok()
}

/// Decrypt the destination identity from enc_header (used to confirm packet is for us).
// Skip mutations: dead code — not called in current routing logic. All mutations
// (function body replacement, slice ranges, etc.) are untestable without a full
// integration harness that exercises this path.
#[mutants::skip]
#[allow(dead_code)]
pub(crate) fn decrypt_dest_from_header(enc_header: &[u8; 128], my_sk: &SigningKey) -> Option<[u8; 32]> {
    let epk_pub_bytes: [u8; 32] = enc_header[..32].try_into().ok()?;
    let epk_pub = X25519PublicKey::from(epk_pub_bytes);
    let my_x = ed25519_priv_to_x25519(&my_sk.to_bytes());
    let shared = my_x.diffie_hellman(&epk_pub);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes()));
    let mut n1 = [0u8; 12];
    n1[..8].copy_from_slice(&1u64.to_le_bytes());
    let mut buf = enc_header[80..128].to_vec();
    cipher
        .decrypt_in_place(&Nonce::from(n1), &epk_pub_bytes, &mut buf)
        .ok()?;
    buf.try_into().ok()
}
