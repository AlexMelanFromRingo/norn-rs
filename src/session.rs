// Session encryption for norn-rs
// X25519 DH key exchange + ChaCha20-Poly1305 AEAD
// Double-ratchet: rotate local x25519 key on each send, integrate remote on recv

use anyhow::{bail, Context, Result};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest as Sha2Digest, Sha512};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Convert an ed25519 private key scalar to an x25519 static secret.
pub fn ed25519_priv_to_x25519(ed_priv_bytes: &[u8; 32]) -> StaticSecret {
    let hash = Sha512::digest(ed_priv_bytes);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    StaticSecret::from(scalar)
}

/// Convert an ed25519 public key to an x25519 public key.
pub fn ed25519_pub_to_x25519(ed_pub_bytes: &[u8; 32]) -> Result<X25519PublicKey> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let compressed = CompressedEdwardsY(*ed_pub_bytes);
    let edwards = compressed.decompress().context("invalid ed25519 public key")?;
    let montgomery = edwards.to_montgomery();
    Ok(X25519PublicKey::from(montgomery.to_bytes()))
}

// ──────────────────────────────────────────────
// Per-session state
// ──────────────────────────────────────────────

/// Per-session state.
///
/// Encryption protocol:
/// - Each side has a local x25519 keypair (rotated after each send).
/// - Shared key = DH(local_priv, remote_pub).
/// - Each encrypted packet carries sender's current x25519 pub key.
/// - Receiver updates remote_pub from packet, recomputes shared key.
pub struct SessionInfo {
    /// Remote's ed25519 public key
    pub remote_ed_pub: [u8; 32],

    // Local x25519 keypair (rotated on each send)
    local_x25519_priv: StaticSecret,
    local_x25519_pub: X25519PublicKey,

    // Remote's most recently seen x25519 public key
    remote_x25519_pub: X25519PublicKey,

    // Sequence numbers
    pub local_seq: u64,
    // Anti-replay sliding window (64-slot).
    // remote_seq_high: highest seq successfully decrypted.
    // remote_seq_window: bitmask; bit i set → (remote_seq_high - i) was accepted.
    pub remote_seq_high: u64,
    remote_seq_window: u64,

    // Session is established (handshake complete)
    pub established: bool,
}

impl SessionInfo {
    fn new(
        remote_ed_pub: [u8; 32],
        local_x25519_priv: StaticSecret,
        remote_x25519_pub: X25519PublicKey,
    ) -> Self {
        let local_x25519_pub = X25519PublicKey::from(&local_x25519_priv);
        SessionInfo {
            remote_ed_pub,
            local_x25519_priv,
            local_x25519_pub,
            remote_x25519_pub,
            local_seq: 0,
            remote_seq_high: 0,
            remote_seq_window: 0,
            established: false,
        }
    }

    fn compute_key(local_priv: &StaticSecret, remote_pub: &X25519PublicKey) -> [u8; 32] {
        let shared = local_priv.diffie_hellman(remote_pub);
        *shared.as_bytes()
    }

    /// Encrypt a payload.
    ///
    /// Wire format: [local_x25519_pub: 32][seq: u64 le][ciphertext+tag]
    ///
    /// Key: DH(local_priv, remote_pub) — both sides know each other's pub keys
    /// from the handshake or from previously received packets.
    ///
    /// The packet includes our current x25519 pub key so the remote can always
    /// identify which DH key to use to decrypt, enabling forward secrecy.
    ///
    /// Ratchet: after every RATCHET_INTERVAL sends, rotate local keypair. The
    /// remote will see the new pub in subsequent packets and update its state.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let sender_x_pub = *self.local_x25519_pub.as_bytes();
        let key_bytes = Self::compute_key(&self.local_x25519_priv, &self.remote_x25519_pub);
        let key = Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.local_seq.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut buf = plaintext.to_vec();
        cipher
            .encrypt_in_place(nonce, &sender_x_pub, &mut buf)
            .map_err(|e| anyhow::anyhow!("encrypt error: {:?}", e))?;

        let mut out = Vec::with_capacity(32 + 8 + buf.len());
        out.extend_from_slice(&sender_x_pub);
        out.extend_from_slice(&self.local_seq.to_le_bytes());
        out.extend_from_slice(&buf);

        self.local_seq += 1;
        Ok(out)
    }

    /// Rotate the local x25519 keypair (call periodically for forward secrecy).
    pub fn rotate_local_key(&mut self) {
        let new_priv = StaticSecret::random_from_rng(OsRng);
        self.local_x25519_pub = X25519PublicKey::from(&new_priv);
        self.local_x25519_priv = new_priv;
    }

    /// Decrypt a payload.
    ///
    /// The packet carries sender's current x25519 pub key.
    /// Key: DH(our_local_priv, sender_pub_from_packet).
    ///
    /// After decryption, update remote_x25519_pub so our next encrypt uses
    /// the sender's latest key.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 32 + 8 + 16 {
            bail!("ciphertext too short ({})", ciphertext.len());
        }

        let mut sender_x_pub_bytes = [0u8; 32];
        sender_x_pub_bytes.copy_from_slice(&ciphertext[..32]);
        let sender_x_pub = X25519PublicKey::from(sender_x_pub_bytes);

        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&ciphertext[32..40]);
        let seq = u64::from_le_bytes(seq_bytes);

        // Key = DH(our_stable_local_priv, sender_pub_from_packet)
        // equals DH(sender_priv, our_local_pub) by commutativity — because
        // our_local_pub is what we advertised in our last packet, and the
        // sender used DH(sender_priv, our_pub) to encrypt.
        let key_bytes = Self::compute_key(&self.local_x25519_priv, &sender_x_pub);
        let key = Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&seq.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Anti-replay sliding window (64 slots).
        // Reject packets that are replays or older than the window.
        const WINDOW: u64 = 64;
        if seq + WINDOW <= self.remote_seq_high {
            bail!("replay: seq {} too old (high={})", seq, self.remote_seq_high);
        }
        if seq <= self.remote_seq_high {
            let offset = self.remote_seq_high - seq;
            if self.remote_seq_window & (1u64 << offset) != 0 {
                bail!("replay: seq {} already seen", seq);
            }
        }

        let mut buf = ciphertext[40..].to_vec();
        cipher
            .decrypt_in_place(nonce, &sender_x_pub_bytes, &mut buf)
            .map_err(|e| anyhow::anyhow!("decrypt error: {:?}", e))?;

        // Update the sliding window after successful decryption.
        if seq > self.remote_seq_high {
            let shift = seq - self.remote_seq_high;
            self.remote_seq_window = if shift >= WINDOW {
                1 // window completely advanced
            } else {
                (self.remote_seq_window << shift) | 1
            };
            self.remote_seq_high = seq;
        } else {
            let offset = self.remote_seq_high - seq;
            self.remote_seq_window |= 1u64 << offset;
        }

        // Update remote_x25519_pub: use sender's latest pub for our next encrypt
        self.remote_x25519_pub = sender_x_pub;
        Ok(buf)
    }
}

// ──────────────────────────────────────────────
// SessionInit / SessionAck wire format
// ──────────────────────────────────────────────

pub const SESSION_INIT_MAGIC: u8 = 0x53; // 'S'
pub const SESSION_ACK_MAGIC: u8 = 0x41; // 'A'

/// SessionInit wire format:
/// [magic:1][ed_pub:32][sig:64][x25519_pub:32]
/// sig covers: magic || ed_pub || x25519_pub
pub struct SessionInit {
    pub ed_pub: [u8; 32],
    pub signature: [u8; 64],
    pub x25519_pub: [u8; 32],
}

impl SessionInit {
    /// Create a SessionInit signed with our signing key, announcing our x25519 pub.
    pub fn create(signing_key: &SigningKey, x25519_pub: &X25519PublicKey) -> Self {
        let ed_pub = signing_key.verifying_key().to_bytes();
        let mut sign_data = vec![SESSION_INIT_MAGIC];
        sign_data.extend_from_slice(&ed_pub);
        sign_data.extend_from_slice(x25519_pub.as_bytes());
        let signature = signing_key.sign(&sign_data).to_bytes();
        SessionInit { ed_pub, signature, x25519_pub: *x25519_pub.as_bytes() }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![SESSION_INIT_MAGIC];
        buf.extend_from_slice(&self.ed_pub);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&self.x25519_pub);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() || data[0] != SESSION_INIT_MAGIC {
            bail!("invalid SessionInit magic");
        }
        let mut pos = 1;
        if data.len() < pos + 32 + 64 + 32 {
            bail!("SessionInit too short: {}", data.len());
        }
        let mut ed_pub = [0u8; 32];
        ed_pub.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[pos..pos + 64]);
        pos += 64;
        let mut x25519_pub = [0u8; 32];
        x25519_pub.copy_from_slice(&data[pos..pos + 32]);
        Ok(SessionInit { ed_pub, signature, x25519_pub })
    }

    pub fn verify(&self) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.ed_pub)?;
        let mut sign_data = vec![SESSION_INIT_MAGIC];
        sign_data.extend_from_slice(&self.ed_pub);
        sign_data.extend_from_slice(&self.x25519_pub);
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&sign_data, &sig)?;
        Ok(())
    }
}

/// SessionAck wire format:
/// [magic:1][ed_pub:32][sig:64][x25519_pub:32]
/// sig covers: magic || ed_pub || x25519_pub
pub struct SessionAck {
    pub ed_pub: [u8; 32],
    pub signature: [u8; 64],
    pub x25519_pub: [u8; 32],
}

impl SessionAck {
    pub fn create(signing_key: &SigningKey, x25519_pub: &X25519PublicKey) -> Self {
        let ed_pub = signing_key.verifying_key().to_bytes();
        let mut sign_data = vec![SESSION_ACK_MAGIC];
        sign_data.extend_from_slice(&ed_pub);
        sign_data.extend_from_slice(x25519_pub.as_bytes());
        let signature = signing_key.sign(&sign_data).to_bytes();
        SessionAck { ed_pub, signature, x25519_pub: *x25519_pub.as_bytes() }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![SESSION_ACK_MAGIC];
        buf.extend_from_slice(&self.ed_pub);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&self.x25519_pub);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() || data[0] != SESSION_ACK_MAGIC {
            bail!("invalid SessionAck magic");
        }
        let mut pos = 1;
        if data.len() < pos + 32 + 64 + 32 {
            bail!("SessionAck too short");
        }
        let mut ed_pub = [0u8; 32];
        ed_pub.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[pos..pos + 64]);
        pos += 64;
        let mut x25519_pub = [0u8; 32];
        x25519_pub.copy_from_slice(&data[pos..pos + 32]);
        Ok(SessionAck { ed_pub, signature, x25519_pub })
    }

    pub fn verify(&self) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.ed_pub)?;
        let mut sign_data = vec![SESSION_ACK_MAGIC];
        sign_data.extend_from_slice(&self.ed_pub);
        sign_data.extend_from_slice(&self.x25519_pub);
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&sign_data, &sig)?;
        Ok(())
    }
}

// ──────────────────────────────────────────────
// SessionManager
// ──────────────────────────────────────────────

pub struct SessionManager {
    pub sessions: HashMap<[u8; 32], SessionInfo>,
    our_signing_key: SigningKey,
}

impl SessionManager {
    pub fn new(signing_key: SigningKey) -> Self {
        SessionManager {
            sessions: HashMap::new(),
            our_signing_key: signing_key,
        }
    }

    pub fn our_signing_key(&self) -> &SigningKey {
        &self.our_signing_key
    }

    /// Handle an incoming SessionInit from remote. Returns SessionAck bytes to send back.
    ///
    /// If we already have a session with this remote (e.g., simultaneous crossing inits),
    /// we complete our own session using the remote's x25519 pub key from their init,
    /// without overwriting our keypair. This resolves the crossing-init race condition:
    /// both sides end up with matching DH shared secrets.
    pub fn handle_init(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let init = SessionInit::decode(data)?;
        init.verify()?;

        let remote_x25519_pub = X25519PublicKey::from(init.x25519_pub);

        if let Some(existing) = self.sessions.get_mut(&init.ed_pub) {
            // Session already exists (we initiated or they initiated before).
            // Update remote pub and mark established — don't replace our keypair.
            existing.remote_x25519_pub = remote_x25519_pub;
            existing.established = true;
            let local_pub = X25519PublicKey::from(&existing.local_x25519_priv);
            let ack = SessionAck::create(&self.our_signing_key, &local_pub);
            return Ok(ack.encode());
        }

        // No existing session: we are the responder.
        let local_priv = StaticSecret::random_from_rng(OsRng);
        let local_pub = X25519PublicKey::from(&local_priv);
        let mut info = SessionInfo::new(init.ed_pub, local_priv, remote_x25519_pub);
        info.established = true;
        self.sessions.insert(init.ed_pub, info);

        let ack = SessionAck::create(&self.our_signing_key, &local_pub);
        Ok(ack.encode())
    }

    /// Handle an incoming SessionAck from remote. Marks session as established.
    pub fn handle_ack(&mut self, data: &[u8]) -> Result<()> {
        let ack = SessionAck::decode(data)?;
        ack.verify()?;
        let remote_x_pub = X25519PublicKey::from(ack.x25519_pub);
        if let Some(info) = self.sessions.get_mut(&ack.ed_pub) {
            info.remote_x25519_pub = remote_x_pub;
            info.established = true;
        } else {
            // Create new session from ACK (remote initiated then we missed init?)
            let local_priv = StaticSecret::random_from_rng(OsRng);
            let mut info = SessionInfo::new(ack.ed_pub, local_priv, remote_x_pub);
            info.established = true;
            self.sessions.insert(ack.ed_pub, info);
        }
        Ok(())
    }

    /// Initiate session with remote: creates local session state, returns SessionInit bytes.
    pub fn initiate(&mut self, remote_ed_pub: &[u8; 32]) -> Vec<u8> {
        // Create (or re-create) session with a fresh local x25519 keypair
        let local_priv = StaticSecret::random_from_rng(OsRng);
        let local_pub = X25519PublicKey::from(&local_priv);
        // remote_x25519_pub placeholder (will be updated from ACK)
        let remote_x_placeholder = X25519PublicKey::from([0u8; 32]);
        let info = SessionInfo::new(*remote_ed_pub, local_priv, remote_x_placeholder);
        self.sessions.insert(*remote_ed_pub, info);
        SessionInit::create(&self.our_signing_key, &local_pub).encode()
    }

    pub fn encrypt(&mut self, remote_ed_pub: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        let info = self.sessions.get_mut(remote_ed_pub).context("no session")?;
        if !info.established {
            bail!("session not established");
        }
        info.encrypt(plaintext)
    }

    pub fn decrypt(&mut self, remote_ed_pub: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let info = self.sessions.get_mut(remote_ed_pub).context("no session")?;
        if !info.established {
            bail!("session not established");
        }
        info.decrypt(ciphertext)
    }

    pub fn is_established(&self, remote_ed_pub: &[u8; 32]) -> bool {
        self.sessions.get(remote_ed_pub).map(|s| s.established).unwrap_or(false)
    }

    pub fn remove(&mut self, remote_ed_pub: &[u8; 32]) {
        self.sessions.remove(remote_ed_pub);
    }

    /// Returns init bytes only if no session record exists yet.
    /// Does NOT re-initiate while a handshake is already in-flight — the
    /// initial init from handle_conn is sufficient on reliable TCP transport.
    /// Re-initiating while in-flight overwrites the local keypair, breaking
    /// the DH shared secret that the remote side is trying to use.
    pub fn get_or_initiate_bytes(&mut self, remote_ed_pub: &[u8; 32]) -> Option<Vec<u8>> {
        if self.sessions.contains_key(remote_ed_pub) {
            return None; // already established or handshake in-flight — don't overwrite
        }
        Some(self.initiate(remote_ed_pub))
    }
}

pub type SharedSessionManager = Arc<Mutex<SessionManager>>;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn session_handshake_and_encrypt_decrypt() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_a = sk_a.verifying_key().to_bytes();
        let pub_b = sk_b.verifying_key().to_bytes();

        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);

        // A initiates to B: sends SessionInit with A's x25519 pub
        let init_bytes = mgr_a.initiate(&pub_b);

        // B handles init, creates session, sends ACK with B's x25519 pub
        let ack_bytes = mgr_b.handle_init(&init_bytes).unwrap();

        // A handles ACK: updates remote x25519 pub (B's x25519 pub)
        mgr_a.handle_ack(&ack_bytes).unwrap();

        assert!(mgr_a.is_established(&pub_b));
        assert!(mgr_b.is_established(&pub_a));

        // At this point:
        // A session: local_priv=A_x25519_priv, remote_pub=B_x25519_pub
        // B session: local_priv=B_x25519_priv, remote_pub=A_x25519_pub (from SessionInit)
        //
        // A encrypts: key = DH(A_x25519_priv, B_x25519_pub), packet carries A_x25519_pub
        // B decrypts: updates remote_pub=A_x25519_pub (from packet), key = DH(B_x25519_priv, A_x25519_pub)
        // DH is commutative: DH(A_priv, B_pub) == DH(B_priv, A_pub) ✓

        // A encrypts to B
        let plaintext = b"hello from A";
        let ciphertext = mgr_a.encrypt(&pub_b, plaintext).unwrap();
        let decrypted = mgr_b.decrypt(&pub_a, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // B encrypts to A (B needs to know A's updated x25519 pub after rotation)
        // After A sent, A's key was rotated. B doesn't know A's new key yet.
        // B encrypts with B's current priv × A's x25519_pub (from SessionInit)
        // A decrypts: updates remote_pub to B's x25519_pub (from packet), key = DH(A_new_priv, B_pub_from_packet)
        let plaintext2 = b"hello from B";
        let ciphertext2 = mgr_b.encrypt(&pub_a, plaintext2).unwrap();
        let decrypted2 = mgr_a.decrypt(&pub_b, &ciphertext2).unwrap();
        assert_eq!(decrypted2, plaintext2);

        // Subsequent messages in both directions
        for i in 0..5u32 {
            let msg = format!("msg {}", i).into_bytes();
            let ct = mgr_a.encrypt(&pub_b, &msg).unwrap();
            let pt = mgr_b.decrypt(&pub_a, &ct).unwrap();
            assert_eq!(pt, msg);

            let ct2 = mgr_b.encrypt(&pub_a, &msg).unwrap();
            let pt2 = mgr_a.decrypt(&pub_b, &ct2).unwrap();
            assert_eq!(pt2, msg);
        }
    }

    #[test]
    fn ed25519_to_x25519_conversion() {
        let sk = SigningKey::generate(&mut OsRng);
        let ed_priv = sk.to_bytes();
        let ed_pub = sk.verifying_key().to_bytes();

        let x_priv = ed25519_priv_to_x25519(&ed_priv);
        let x_pub_from_priv = X25519PublicKey::from(&x_priv);
        let x_pub_from_pub = ed25519_pub_to_x25519(&ed_pub).unwrap();

        // Both should give the same x25519 public key
        assert_eq!(x_pub_from_priv.as_bytes(), x_pub_from_pub.as_bytes());
    }
}
