//! Roadmap #8 — human-friendly key sharing.
//!
//! A norn identity is a 32-byte ed25519 public key. Off the LAN —
//! where mDNS would otherwise discover a peer with no config — the
//! only way to hand that key to someone has been to copy-paste 64 hex
//! characters: error-prone and unfriendly. This module gives two
//! better channels for the *same public* key. The key carries no
//! secret, so there is nothing to protect here — only transcription
//! errors to catch:
//!
//! * **Word mnemonic** — the key as 24 BIP39 English words. BIP39's
//!   8-bit checksum catches almost every single-word typo and most
//!   word transpositions, so a phrase read aloud over the phone
//!   either decodes to the exact key or fails loudly.
//! * **QR code** — the key (or any short string) rendered as a
//!   terminal QR a phone camera can scan.
//!
//! Both are lossless and reversible, and neither needs a network or a
//! central directory — those (rendezvous tokens, a name→key
//! directory) are the larger follow-ups still open under roadmap #8.

use anyhow::{bail, Context, Result};

/// Encode a 32-byte key as a 24-word BIP39 English mnemonic.
pub fn to_mnemonic(key: &[u8; 32]) -> String {
    // `from_entropy` only rejects entropy lengths BIP39 doesn't
    // support; 32 bytes is valid (→ 24 words), so this never fails.
    bip39::Mnemonic::from_entropy(key)
        .expect("32 bytes is a valid BIP39 entropy length")
        .to_string()
}

/// Decode a BIP39 word mnemonic back into the 32-byte key.
///
/// Rejects the phrase if the word count is wrong, a word is not in
/// the list, or the BIP39 checksum fails — a mistyped phrase is an
/// error, never a silently-wrong key.
pub fn from_mnemonic(phrase: &str) -> Result<[u8; 32]> {
    let m = bip39::Mnemonic::parse(phrase.trim())
        .context("not a valid BIP39 mnemonic (check word count, spelling, order)")?;
    let entropy = m.to_entropy();
    if entropy.len() != 32 {
        bail!(
            "mnemonic decodes to {} bytes, expected 32 — a norn key \
             needs the full 24-word phrase",
            entropy.len()
        );
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&entropy);
    Ok(key)
}

/// Render `data` as a QR code drawn with Unicode half-blocks, ready
/// to print to a terminal. Errors only if `data` is too large for
/// the largest QR version.
pub fn qr_terminal(data: &str) -> Result<String> {
    use qrcode::render::unicode;
    use qrcode::QrCode;
    let code = QrCode::new(data.as_bytes())
        .context("data too large to fit in a QR code")?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_round_trips() {
        let key: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let phrase = to_mnemonic(&key);
        assert_eq!(phrase.split_whitespace().count(), 24, "256-bit key → 24 words");
        assert_eq!(from_mnemonic(&phrase).unwrap(), key, "round-trip must be lossless");
    }

    #[test]
    fn zero_key_is_the_canonical_bip39_vector() {
        // The 32-byte all-zero entropy is the well-known BIP39 vector:
        // 23×"abandon" + "art". A regression here means the encoding
        // diverged from the standard wordlist/checksum.
        let phrase = to_mnemonic(&[0u8; 32]);
        let expected = format!("{}art", "abandon ".repeat(23));
        assert_eq!(phrase, expected);
        assert_eq!(from_mnemonic(&phrase).unwrap(), [0u8; 32]);
    }

    #[test]
    fn checksum_rejects_a_single_word_typo() {
        let key = [0xABu8; 32];
        let phrase = to_mnemonic(&key);
        // Swap the first word for a different valid wordlist entry —
        // still all real words, but the BIP39 checksum no longer matches.
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        words[0] = if words[0] == "zoo" { "abandon" } else { "zoo" };
        let corrupted = words.join(" ");
        assert!(
            from_mnemonic(&corrupted).is_err(),
            "a single-word change must fail the checksum, not decode silently"
        );
    }

    #[test]
    fn rejects_too_short_a_phrase() {
        // A valid 12-word mnemonic decodes to 16 bytes, not 32.
        let short = bip39::Mnemonic::from_entropy(&[0u8; 16]).unwrap().to_string();
        assert!(from_mnemonic(&short).is_err(), "16-byte phrase is not a norn key");
    }

    #[test]
    fn rejects_garbage() {
        assert!(from_mnemonic("not actually a mnemonic at all").is_err());
        assert!(from_mnemonic("").is_err());
    }

    #[test]
    fn qr_encodes_a_hex_key() {
        let hex_key = hex::encode([0x5Au8; 32]);
        let qr = qr_terminal(&hex_key).unwrap();
        assert!(!qr.is_empty(), "QR render must produce output");
        // Dense1x2 renders with half-block glyphs; sanity-check one is present.
        assert!(qr.contains('█') || qr.contains('▀') || qr.contains('▄'));
    }
}
