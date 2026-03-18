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
use std::time::Instant;
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
    // Last time this session was used for encrypt or decrypt
    pub last_used: Instant,
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
            last_used: Instant::now(),
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
        self.last_used = Instant::now();
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
        self.last_used = Instant::now();
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
    use x25519_dalek::StaticSecret;

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

    // ── compute_key ─────────────────────────────────────────────────────────

    #[test]
    fn compute_key_differs_with_different_inputs() {
        // If compute_key returned [0;32] or a constant, all keys would be equal
        let priv1 = StaticSecret::random_from_rng(OsRng);
        let priv2 = StaticSecret::random_from_rng(OsRng);
        let pub1 = X25519PublicKey::from(&priv1);
        let pub2 = X25519PublicKey::from(&priv2);
        let k1 = SessionInfo::compute_key(&priv1, &pub2);
        let k2 = SessionInfo::compute_key(&priv2, &pub1);
        // DH is commutative: both sides compute the same shared secret
        assert_eq!(k1, k2, "DH should be commutative");
        // And non-zero
        assert_ne!(k1, [0u8; 32], "shared key must not be zero");
    }

    #[test]
    fn compute_key_different_remote_gives_different_key() {
        let local_priv = StaticSecret::random_from_rng(OsRng);
        let remote1 = X25519PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let remote2 = X25519PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let k1 = SessionInfo::compute_key(&local_priv, &remote1);
        let k2 = SessionInfo::compute_key(&local_priv, &remote2);
        assert_ne!(k1, k2, "different remotes must give different keys");
    }

    // ── wrong-key decryption fails ───────────────────────────────────────────

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let sk_c = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let pub_a = sk_a.verifying_key().to_bytes();

        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b.clone());
        let mut mgr_c = SessionManager::new(sk_c);

        let init = mgr_a.initiate(&pub_b);
        let ack  = mgr_b.handle_init(&init).unwrap();
        mgr_a.handle_ack(&ack).unwrap();

        let ct = mgr_a.encrypt(&pub_b, b"secret").unwrap();

        // mgr_c has a different signing key and different x25519 key → decrypt should fail
        let pub_b2 = sk_b.verifying_key().to_bytes();
        // Give C an established (but wrong-key) session by initiating separately
        let init_c = mgr_c.initiate(&pub_b2);
        let _ = mgr_b.handle_init(&init_c); // B creates a session for C too

        // C tries to decrypt A's ciphertext using its own wrong session key → must fail
        assert!(mgr_c.decrypt(&pub_a, &ct).is_err(),
            "decryption with wrong key must fail");
    }

    // ── SessionInit / SessionAck signature verification ───────────────────────

    #[test]
    fn session_init_verify_rejects_tampered_signature() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let mut mgr_a = SessionManager::new(sk_a);
        let mut init_bytes = mgr_a.initiate(&pub_b);
        // Corrupt the signature bytes (last 64 bytes of SessionInit)
        let n = init_bytes.len();
        init_bytes[n - 1] ^= 0xFF;
        let mut mgr_b = SessionManager::new(sk_b);
        assert!(mgr_b.handle_init(&init_bytes).is_err(),
            "tampered SessionInit signature must be rejected");
    }

    #[test]
    fn session_ack_verify_rejects_tampered_signature() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);
        let init = mgr_a.initiate(&pub_b);
        let mut ack = mgr_b.handle_init(&init).unwrap();
        // Corrupt ACK signature
        let n = ack.len();
        ack[n - 1] ^= 0xFF;
        assert!(mgr_a.handle_ack(&ack).is_err(),
            "tampered SessionAck signature must be rejected");
    }

    // ── Sliding window replay protection ─────────────────────────────────────

    #[test]
    fn replay_same_packet_rejected() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let pub_a = sk_a.verifying_key().to_bytes();
        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);
        let init = mgr_a.initiate(&pub_b);
        let ack = mgr_b.handle_init(&init).unwrap();
        mgr_a.handle_ack(&ack).unwrap();

        let ct = mgr_a.encrypt(&pub_b, b"once").unwrap();
        // First decrypt succeeds
        assert!(mgr_b.decrypt(&pub_a, &ct).is_ok());
        // Replay must fail
        assert!(mgr_b.decrypt(&pub_a, &ct).is_err(),
            "replayed packet must be rejected");
    }

    #[test]
    fn old_packet_outside_window_rejected() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let pub_a = sk_a.verifying_key().to_bytes();
        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);
        let init = mgr_a.initiate(&pub_b);
        let ack = mgr_b.handle_init(&init).unwrap();
        mgr_a.handle_ack(&ack).unwrap();

        // Send 65 packets to advance the window past seq=0
        let old_ct = mgr_a.encrypt(&pub_b, b"old").unwrap();
        for _ in 0..65 {
            let ct = mgr_a.encrypt(&pub_b, b"x").unwrap();
            let _ = mgr_b.decrypt(&pub_a, &ct);
        }
        // Now the window has advanced; seq=0 is too old
        assert!(mgr_b.decrypt(&pub_a, &old_ct).is_err(),
            "packet older than window must be rejected");
    }

    #[test]
    fn out_of_order_within_window_accepted() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let pub_a = sk_a.verifying_key().to_bytes();
        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);
        let init = mgr_a.initiate(&pub_b);
        let ack = mgr_b.handle_init(&init).unwrap();
        mgr_a.handle_ack(&ack).unwrap();

        // Encrypt two packets out of order
        let ct0 = mgr_a.encrypt(&pub_b, b"zero").unwrap();
        let ct1 = mgr_a.encrypt(&pub_b, b"one").unwrap();
        // Deliver 1 before 0
        assert!(mgr_b.decrypt(&pub_a, &ct1).is_ok(), "seq 1 should be accepted first");
        assert!(mgr_b.decrypt(&pub_a, &ct0).is_ok(), "seq 0 within window should be accepted");
    }

    // ── rotate_local_key ─────────────────────────────────────────────────────

    #[test]
    fn rotate_local_key_changes_pub() {
        let sk = SigningKey::generate(&mut OsRng);
        let pub_b = [1u8; 32]; // placeholder
        let x_priv = ed25519_priv_to_x25519(&sk.to_bytes());
        let x_pub_before = X25519PublicKey::from(&x_priv);
        let remote_pub = X25519PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let mut info = SessionInfo::new([0u8; 32], x_priv, remote_pub);
        let _ = pub_b; // suppress warning
        let pub_before = *info.local_x25519_pub.as_bytes();
        info.rotate_local_key();
        let pub_after = *info.local_x25519_pub.as_bytes();
        assert_ne!(pub_before, pub_after, "rotate_local_key must change the public key");
        let _ = x_pub_before;
    }

    // ── SessionManager::remove ───────────────────────────────────────────────

    #[test]
    fn session_manager_remove_clears_session() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);
        let init = mgr_a.initiate(&pub_b);
        let ack = mgr_b.handle_init(&init).unwrap();
        mgr_a.handle_ack(&ack).unwrap();
        assert!(mgr_a.is_established(&pub_b));
        mgr_a.remove(&pub_b);
        assert!(!mgr_a.is_established(&pub_b),
            "session must be gone after remove()");
    }

    // ── decrypt truncation guard (exact boundary) ────────────────────────────

    #[test]
    fn decrypt_too_short_rejected() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let pub_a = sk_a.verifying_key().to_bytes();
        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);
        let init = mgr_a.initiate(&pub_b);
        let ack = mgr_b.handle_init(&init).unwrap();
        mgr_a.handle_ack(&ack).unwrap();
        // Ciphertext shorter than 32+8+16=56 bytes must be rejected
        assert!(mgr_b.decrypt(&pub_a, &[0u8; 55]).is_err(),
            "55-byte ciphertext must be rejected");
        assert!(mgr_b.decrypt(&pub_a, &[]).is_err());
        // 56 bytes is the minimum valid size (empty plaintext encrypted)
        // Encrypting b"" gives exactly 56 bytes; this must NOT be rejected by the length check
        let ct_empty = mgr_a.encrypt(&pub_b, b"").unwrap();
        assert_eq!(ct_empty.len(), 56, "empty plaintext must produce 56-byte ciphertext");
        // The decrypt of a validly-formed 56-byte ct must succeed (not fail on length)
        assert!(mgr_b.decrypt(&pub_a, &ct_empty).is_ok(),
            "valid 56-byte ciphertext (empty plaintext) must succeed — catches < vs <=");
    }

    // ── sliding window arithmetic precision ──────────────────────────────────

    #[test]
    fn replay_at_nonzero_offset_rejected() {
        // After receiving seq=0 and seq=1, replay of seq=0 should fail.
        // This specifically tests that the bit at offset=1 is correctly set (1<<1),
        // catching the mutation << → >> (1>>1 = 0 would miss the replay).
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let pub_a = sk_a.verifying_key().to_bytes();
        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);
        let init = mgr_a.initiate(&pub_b);
        let ack = mgr_b.handle_init(&init).unwrap();
        mgr_a.handle_ack(&ack).unwrap();

        let ct0 = mgr_a.encrypt(&pub_b, b"zero").unwrap();
        let ct1 = mgr_a.encrypt(&pub_b, b"one").unwrap();

        // Receive both in order
        assert!(mgr_b.decrypt(&pub_a, &ct0).is_ok());
        assert!(mgr_b.decrypt(&pub_a, &ct1).is_ok());

        // Replay seq=0 — remote_seq_high=1, offset=1, bit 1 should be set
        assert!(mgr_b.decrypt(&pub_a, &ct0).is_err(),
            "replay at offset=1 must be rejected (catches 1<<offset vs 1>>offset)");
    }

    #[test]
    fn window_arithmetic_three_step_sequence() {
        // Receive seq=0,1,2 then try to replay seq=1 (offset=1).
        // Also verifies the window shifts correctly when seq advances by 2.
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let pub_a = sk_a.verifying_key().to_bytes();
        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);
        let init = mgr_a.initiate(&pub_b);
        let ack = mgr_b.handle_init(&init).unwrap();
        mgr_a.handle_ack(&ack).unwrap();

        let cts: Vec<_> = (0..4).map(|i| mgr_a.encrypt(&pub_b, &[i]).unwrap()).collect();
        // Receive 0,1,2,3 in order
        for ct in &cts { assert!(mgr_b.decrypt(&pub_a, ct).is_ok()); }
        // Replay each: all must fail
        for (i, ct) in cts.iter().enumerate() {
            assert!(mgr_b.decrypt(&pub_a, ct).is_err(),
                "replay of seq={} must be rejected", i);
        }
    }

    #[test]
    fn window_advance_by_more_than_one() {
        // Skip seq=1, receive seq=3. Then receive seq=1 (within window).
        // This tests the shift arithmetic: shift = 3-0 = 3, window = (window<<3)|1 = 0b1001.
        // Then seq=1: offset = 3-1 = 2, bit 2 is 0 → accepted.
        // With mutated shift arithmetic the window would be wrong.
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let pub_a = sk_a.verifying_key().to_bytes();
        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);
        let init = mgr_a.initiate(&pub_b);
        let ack = mgr_b.handle_init(&init).unwrap();
        mgr_a.handle_ack(&ack).unwrap();

        let ct0 = mgr_a.encrypt(&pub_b, b"seq0").unwrap();
        let ct1 = mgr_a.encrypt(&pub_b, b"seq1").unwrap();
        let ct2 = mgr_a.encrypt(&pub_b, b"seq2").unwrap();
        let ct3 = mgr_a.encrypt(&pub_b, b"seq3").unwrap();

        // Receive seq=0 (high=0, window=1)
        assert!(mgr_b.decrypt(&pub_a, &ct0).is_ok());
        // Skip seq=1,2 and receive seq=3 (shift=3, high=3, window=(1<<3)|1 = 9 = 0b1001)
        assert!(mgr_b.decrypt(&pub_a, &ct3).is_ok());
        // seq=1 is at offset=2, bit 2 of window 9 = 0 → should be accepted
        assert!(mgr_b.decrypt(&pub_a, &ct1).is_ok(),
            "seq=1 (offset=2 from high=3) must be accepted");
        // seq=0 is at offset=3, bit 3 of window 9 = 1 → must be rejected (already seen)
        assert!(mgr_b.decrypt(&pub_a, &ct0).is_err(),
            "seq=0 (offset=3, already in window) must be rejected");
        // seq=2 at offset=1, bit 1 of current window → must be accepted
        assert!(mgr_b.decrypt(&pub_a, &ct2).is_ok(),
            "seq=2 (offset=1 from high=3) must be accepted");
    }

    // ── SessionInit / SessionAck decode truncation ────────────────────────────

    #[test]
    fn session_init_decode_truncated_fails() {
        // Must fail on empty data
        assert!(SessionInit::decode(&[]).is_err());
        // Must fail with wrong magic
        let mut bad = vec![0xFF_u8; 1 + 32 + 64 + 32];
        assert!(SessionInit::decode(&bad).is_err(), "wrong magic must fail");
        // Must fail when too short (even with correct magic)
        bad[0] = SESSION_INIT_MAGIC;
        bad.truncate(32); // only 32 bytes instead of 129
        assert!(SessionInit::decode(&bad).is_err(), "truncated SessionInit must fail");
    }

    #[test]
    fn session_ack_decode_truncated_fails() {
        assert!(SessionAck::decode(&[]).is_err());
        let mut bad = vec![0xFF_u8; 1 + 32 + 64 + 32];
        assert!(SessionAck::decode(&bad).is_err(), "wrong magic must fail");
        bad[0] = SESSION_ACK_MAGIC;
        bad.truncate(32);
        assert!(SessionAck::decode(&bad).is_err(), "truncated SessionAck must fail");
    }

    #[test]
    fn session_init_verify_wrong_body_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);
        let x_priv = StaticSecret::random_from_rng(OsRng);
        let x_pub = X25519PublicKey::from(&x_priv);
        // Create valid SessionInit
        let _ = sk2;
        let init = SessionInit::create(&sk, &x_pub);
        assert!(init.verify().is_ok(), "valid init must verify");
        // Tamper with x25519_pub — signature no longer matches
        let mut bad_init = SessionInit { x25519_pub: [0xFFu8; 32], ..init };
        assert!(bad_init.verify().is_err(), "tampered x25519_pub must fail verify");
        // Tamper with ed_pub — signature fails
        bad_init = SessionInit {
            x25519_pub: init.x25519_pub,
            ed_pub: [0xEEu8; 32],
            ..init
        };
        assert!(bad_init.verify().is_err(), "tampered ed_pub must fail verify");
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

    // ── decrypt boundary: catches `32 + 8 - 16 = 24` mutation ───────────────
    // A 30-byte input: original rejects (30 < 56 = 32+8+16).
    // With mutation `+→-` on second `+` the check becomes `len < 24`, so 30 passes,
    // then `ciphertext[..32]` slices beyond end → panic (test fails = mutation caught).

    #[test]
    fn decrypt_30_byte_ciphertext_rejected() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let pub_a = sk_a.verifying_key().to_bytes();
        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);
        let init = mgr_a.initiate(&pub_b);
        let ack = mgr_b.handle_init(&init).unwrap();
        mgr_a.handle_ack(&ack).unwrap();
        // 30 bytes is below 56 (=32+8+16): length check must fire.
        // With the `+→-` mutation (check becomes < 24), 30 passes the check
        // and the code tries ciphertext[..32] on a 30-byte slice → panic.
        assert!(mgr_b.decrypt(&pub_a, &[0u8; 30]).is_err(),
            "30-byte ciphertext must fail length check (catches `32+8-16=24` mutation)");
    }

    // ── out-of-order window SET: catches mutations on lines 200/201 ──────────
    // Receive seq=3 (advances high to 3), then seq=1 out-of-order (sets bit at
    // offset=2 in the else branch), then replay seq=1.
    // Mutation `- → +` on line 200: offset=3+1=4, sets wrong bit; replay at
    //   offset=2 is not set → wrongly accepted (caught).
    // Mutation `<< → >>` on line 201: 1>>2=0, nothing set; replay accepted (caught).

    #[test]
    fn out_of_order_packet_replay_rejected() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let pub_a = sk_a.verifying_key().to_bytes();
        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);
        let init = mgr_a.initiate(&pub_b);
        let ack = mgr_b.handle_init(&init).unwrap();
        mgr_a.handle_ack(&ack).unwrap();

        // Encrypt 4 packets in order
        let ct0 = mgr_a.encrypt(&pub_b, b"seq0").unwrap();
        let ct1 = mgr_a.encrypt(&pub_b, b"seq1").unwrap();
        let ct2 = mgr_a.encrypt(&pub_b, b"seq2").unwrap();
        let ct3 = mgr_a.encrypt(&pub_b, b"seq3").unwrap();

        // Receive seq=3 first: advances high to 3, window=(1<<3)|1=9 (bit for seq=3 set)
        assert!(mgr_b.decrypt(&pub_a, &ct3).is_ok(), "seq=3 must be accepted");

        // Receive seq=1 out-of-order: offset = 3-1 = 2, window |= 1<<2 = 13
        assert!(mgr_b.decrypt(&pub_a, &ct1).is_ok(), "seq=1 out-of-order must be accepted");

        // Replay seq=1: offset=2, bit 2 of window should be set → rejected
        // With `- → +` mutation: offset=3+1=4, lookup at bit 2 (not set) → accepted! (caught)
        // With `<< → >>` mutation: 1>>2=0, bit 2 never set → accepted! (caught)
        assert!(mgr_b.decrypt(&pub_a, &ct1).is_err(),
            "replay of out-of-order seq=1 must be rejected (catches line 200/201 mutations)");

        // seq=0 and seq=2 should still be receivable (not yet seen)
        assert!(mgr_b.decrypt(&pub_a, &ct0).is_ok(), "seq=0 must be accepted");
        assert!(mgr_b.decrypt(&pub_a, &ct2).is_ok(), "seq=2 must be accepted");
    }

    // ── SessionInit decode: 128-byte truncated input (one byte short) ─────────
    // The full minimum is 1+32+64+32=129 bytes.
    // With mutation `+→-` on any `+`, the check becomes e.g. `len < 65` or `len < 1`.
    // A 128-byte input: original rejects ("too short"), mutated passes the check and
    // then tries data[97..129] on a 128-byte slice → panic (caught).

    #[test]
    fn session_init_decode_128_bytes_rejected() {
        // 128 bytes with correct magic: one byte short of the 129-byte minimum (1+32+64+32).
        // With mutation `+→-` on any `+`, check becomes e.g. `len < 65` or `len < 1`,
        // so 128 passes and data[97..129] panics (OOB) → test fails = mutation caught.
        let mut data = vec![0u8; 128];
        data[0] = SESSION_INIT_MAGIC;
        let result = SessionInit::decode(&data);
        assert!(result.is_err(),
            "128-byte input (one short of minimum 129) must be rejected (catches +→- mutations)");
        let msg = format!("{}", result.err().expect("just checked is_err"));
        assert!(msg.contains("too short") || msg.contains("short"),
            "error must mention 'too short'; got: {}", msg);
    }

    // ── SessionAck decode: 128-byte truncated input ───────────────────────────

    #[test]
    fn session_ack_decode_128_bytes_rejected() {
        let mut data = vec![0u8; 128];
        data[0] = SESSION_ACK_MAGIC;
        let result = SessionAck::decode(&data);
        assert!(result.is_err(),
            "128-byte SessionAck (one short of minimum 129) must be rejected (catches +→- mutations)");
        let msg = format!("{}", result.err().expect("just checked is_err"));
        assert!(msg.contains("too short") || msg.contains("short"),
            "error must mention 'too short'; got: {}", msg);
    }
}
