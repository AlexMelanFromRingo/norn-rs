//! PQ-hybrid signature identity — ML-DSA-65 (FIPS 204), Option B.
//!
//! Each node holds a long-term ML-DSA-65 keypair **independent of its Ed25519
//! identity** (derived from a separate persisted 32-byte seed — NOT from the
//! Ed25519 secret, so a CRQC that breaks Ed25519 cannot also forge ML-DSA). The
//! session handshake (SessionInit/Ack) carries an ML-DSA signature alongside the
//! Ed25519 one; verifiers TOFU-pin each identity's ML-DSA public key, so an
//! established/repeat session is authenticated post-quantum.
//!
//! ML-DSA-65 matches ML-KEM-768's NIST security level (3). Sizes: verifying key
//! 1952 B, signature 3309 B — large, but the handshake is per-session (never
//! flooded), so this fits the lightweight budget; flooded announces stay Ed25519.

use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, SigningKey, VerifyingKey, B32,
};

/// ML-DSA-65 verifying-key size in bytes (FIPS 204).
pub const ML_DSA_PUB_BYTES: usize = 1952;
/// ML-DSA-65 signature size in bytes (FIPS 204).
pub const ML_DSA_SIG_BYTES: usize = 3309;
/// Seed (ξ) size for deterministic key generation.
pub const ML_DSA_SEED_BYTES: usize = 32;

/// A node's long-term ML-DSA-65 signing identity, reconstructed from a persisted
/// 32-byte seed so the public key (and thus the TOFU pin) is stable across
/// restarts.
pub struct PqSigner {
    sk: SigningKey<MlDsa65>,
    pub_bytes: [u8; ML_DSA_PUB_BYTES],
}

impl PqSigner {
    /// Generate an ephemeral keypair from OS randomness. Used as the default
    /// before a config-seeded key is installed (the TOFU pin then resets on
    /// restart — fine for tests; nornd installs a persisted seed in production).
    pub fn generate_ephemeral() -> Self {
        use rand::{rngs::OsRng, RngCore};
        let mut seed = [0u8; ML_DSA_SEED_BYTES];
        OsRng.fill_bytes(&mut seed);
        let signer = Self::from_seed(&seed);
        // best-effort scrub
        seed.iter_mut().for_each(|b| *b = 0);
        signer
    }

    /// Deterministically derive the keypair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; ML_DSA_SEED_BYTES]) -> Self {
        let sk = SigningKey::<MlDsa65>::from_seed(&B32::from(*seed));
        let enc: EncodedVerifyingKey<MlDsa65> = sk.verifying_key().encode();
        let pub_bytes: [u8; ML_DSA_PUB_BYTES] = enc
            .as_slice()
            .try_into()
            .expect("ML-DSA-65 verifying key is 1952 bytes");
        PqSigner { sk, pub_bytes }
    }

    /// Our ML-DSA public key bytes (advertised in the handshake; TOFU-pinned by peers).
    pub fn pub_bytes(&self) -> &[u8; ML_DSA_PUB_BYTES] {
        &self.pub_bytes
    }

    /// Sign `msg` with our ML-DSA secret key (deterministic variant).
    pub fn sign(&self, msg: &[u8]) -> [u8; ML_DSA_SIG_BYTES] {
        let sig: Signature<MlDsa65> = self.sk.sign(msg);
        sig.encode()
            .as_slice()
            .try_into()
            .expect("ML-DSA-65 signature is 3309 bytes")
    }
}

/// Verify an ML-DSA-65 signature over `msg` against `pub_bytes`. Returns false on
/// any decode failure or signature mismatch (never panics on hostile input).
pub fn verify(
    pub_bytes: &[u8; ML_DSA_PUB_BYTES],
    msg: &[u8],
    sig_bytes: &[u8; ML_DSA_SIG_BYTES],
) -> bool {
    let enc_vk = EncodedVerifyingKey::<MlDsa65>::try_from(pub_bytes.as_slice());
    let enc_sig = EncodedSignature::<MlDsa65>::try_from(sig_bytes.as_slice());
    let (Ok(enc_vk), Ok(enc_sig)) = (enc_vk, enc_sig) else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);
    let Some(sig) = Signature::<MlDsa65>::decode(&enc_sig) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_from_seed_is_deterministic() {
        let seed = [7u8; 32];
        let a = PqSigner::from_seed(&seed);
        let b = PqSigner::from_seed(&seed);
        assert_eq!(a.pub_bytes(), b.pub_bytes(), "same seed → same public key");
        let other = PqSigner::from_seed(&[8u8; 32]);
        assert_ne!(a.pub_bytes(), other.pub_bytes(), "different seed → different key");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let signer = PqSigner::from_seed(&[1u8; 32]);
        let msg = b"norn handshake bytes";
        let sig = signer.sign(msg);
        assert!(verify(signer.pub_bytes(), msg, &sig), "valid signature must verify");
    }

    #[test]
    fn verify_rejects_tampered_msg_and_sig() {
        let signer = PqSigner::from_seed(&[2u8; 32]);
        let sig = signer.sign(b"original");
        assert!(!verify(signer.pub_bytes(), b"tampered", &sig), "wrong message rejected");
        let mut bad = sig;
        bad[100] ^= 0xFF;
        assert!(!verify(signer.pub_bytes(), b"original", &bad), "tampered signature rejected");
        let other = PqSigner::from_seed(&[3u8; 32]);
        assert!(!verify(other.pub_bytes(), b"original", &sig), "wrong key rejected");
    }
}
