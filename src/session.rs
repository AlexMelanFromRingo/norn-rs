// Session encryption for norn-rs
// X25519 DH + ML-KEM-768 hybrid KEM + ChaCha20-Poly1305 AEAD.
//
// PQ hybrid (v3 session protocol):
//   - Each node holds a long-term ML-KEM-768 keypair.
//   - SessionInit carries the initiator's ml_kem_pub (1184 bytes).
//   - SessionAck carries an ml_kem_ct (1088 bytes) — the responder
//     encapsulates a fresh shared secret against the initiator's pq pub.
//   - Both sides end up with `pq_shared` (32 bytes).
//   - Per-packet AEAD key = HKDF-Extract(salt = pq_shared,
//                                        ikm  = x25519_shared).
//     If either primitive holds, the key is indistinguishable from random.
//   - X25519 still ratchets per send (forward secrecy classical layer);
//     ML-KEM secret stays for the session lifetime (~5 min idle expiry).

use anyhow::{bail, Context, Result};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{KeyExport, MlKem768, TryKeyInit};
use rand::rngs::OsRng;
use sha2::{Digest as Sha2Digest, Sha256, Sha512};

type MlKemDk = ml_kem::DecapsulationKey<ml_kem::MlKem768>;
type MlKemEk = ml_kem::EncapsulationKey<ml_kem::MlKem768>;

/// Long-term-rotating ML-KEM-768 keypair held per SessionManager.
///
/// Used to receive PQ-encapsulated shared secrets during inbound
/// SessionInit / SessionAck. Rotated on a daily cadence by
/// `rotate_if_due()`; the prior decapsulation key is retained for
/// `ML_KEM_KEY_OVERLAP_MS` so in-flight Acks built against the just-
/// rotated pub still decap. Past PQ traffic becomes undecryptable once
/// both `prev_dk` and `dk` have rotated past the original.
struct PqKeys {
    dk: MlKemDk,
    ek_bytes: [u8; ML_KEM_PUB_BYTES],
    /// Just-rotated-out dk, kept for the overlap window. Cleared on the
    /// next rotation. zeroize-on-drop is provided by ml-kem's "zeroize"
    /// feature, so dropping clears the secret material.
    prev_dk: Option<MlKemDk>,
    /// When `dk` was generated (used to decide when to rotate).
    rotated_at: Instant,
}

/// Maximum age of the current ML-KEM keypair before it should rotate.
pub const ML_KEM_KEY_ROTATION_MS: u64 = 24 * 60 * 60 * 1000; // 24h
/// How long we keep the previous dk after rotation, to decap Acks that were
/// already in flight against the just-replaced pub.
pub const ML_KEM_KEY_OVERLAP_MS: u64 = 60_000; // 60s

/// Active rotation interval — accounts for the `NORN_ACCELERATE_ROTATIONS_SECS`
/// test knob. In production this equals `ML_KEM_KEY_ROTATION_MS`. In a
/// test cluster (see tests/cluster/) it can be cranked down to seconds so
/// rotation can be observed end-to-end inside a single CI run.
fn effective_ml_kem_rotation_ms() -> u64 {
    if let Some(secs) = crate::router::accelerate_rotations_secs() {
        return secs.saturating_mul(1000);
    }
    ML_KEM_KEY_ROTATION_MS
}

/// Active overlap window — scales down similarly under acceleration so the
/// prev_dk clear-out doesn't take a full real-minute when rotation runs
/// every few seconds.
fn effective_ml_kem_overlap_ms() -> u64 {
    if let Some(secs) = crate::router::accelerate_rotations_secs() {
        // Overlap = max(1s, 1/4 of rotation interval) — keeps overlap short
        // enough to actually trigger eviction in a test, long enough to
        // catch genuinely in-flight Acks.
        return (secs.saturating_mul(250)).max(1_000);
    }
    ML_KEM_KEY_OVERLAP_MS
}

impl PqKeys {
    fn generate() -> Self {
        let (dk, ek) = MlKem768::generate_keypair();
        let ek_arr = ek.to_bytes();
        let mut ek_bytes = [0u8; ML_KEM_PUB_BYTES];
        ek_bytes.copy_from_slice(ek_arr.as_slice());
        PqKeys { dk, ek_bytes, prev_dk: None, rotated_at: Instant::now() }
    }

    fn pub_bytes(&self) -> &[u8; ML_KEM_PUB_BYTES] { &self.ek_bytes }

    fn decap(&self, ct_bytes: &[u8; ML_KEM_CT_BYTES]) -> Result<[u8; ML_KEM_SHARED_BYTES]> {
        let ct = Array::try_from(ct_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("ml-kem: bad ct length"))?;
        // Current key first — common case.
        let shared = self.dk.decapsulate(&ct);
        // ML-KEM decap is "implicit rejection": it never fails per se, it
        // returns a pseudo-random value derived from the secret on bogus
        // ct. So we cannot tell from this alone whether the ct was really
        // for `dk` or `prev_dk`. Caller verifies via the AEAD tag on the
        // first session packet; if decryption fails the caller should
        // retry decap against prev_dk.
        let mut out = [0u8; ML_KEM_SHARED_BYTES];
        out.copy_from_slice(shared.as_slice());
        Ok(out)
    }

    /// Try `prev_dk` (if present) — used as a fallback when the first
    /// post-handshake packet fails AEAD with the secret derived from `dk`.
    /// This only runs during the overlap window and is rare in practice.
    #[allow(dead_code)] // wired in but only used by callers handling AEAD-fail retry
    fn decap_prev(&self, ct_bytes: &[u8; ML_KEM_CT_BYTES]) -> Option<[u8; ML_KEM_SHARED_BYTES]> {
        let prev = self.prev_dk.as_ref()?;
        let ct = Array::try_from(ct_bytes.as_slice()).ok()?;
        let shared = prev.decapsulate(&ct);
        let mut out = [0u8; ML_KEM_SHARED_BYTES];
        out.copy_from_slice(shared.as_slice());
        Some(out)
    }

    /// Rotate to a fresh keypair if the current one has exceeded
    /// ML_KEM_KEY_ROTATION_MS, or if the overlap window has elapsed and
    /// the prior key should be cleared. Returns true if anything changed.
    pub fn rotate_if_due(&mut self) -> bool {
        let elapsed_ms = self.rotated_at.elapsed().as_millis() as u64;
        let mut changed = false;

        // Clear prev_dk after overlap window so it can't decap any longer
        // (and so the StaticSecret is dropped / zeroized).
        if self.prev_dk.is_some() && elapsed_ms > effective_ml_kem_overlap_ms() {
            self.prev_dk = None;
            changed = true;
        }

        // Rotate when key has aged past ROTATION_MS.
        if elapsed_ms > effective_ml_kem_rotation_ms() {
            let (new_dk, new_ek) = MlKem768::generate_keypair();
            let new_ek_arr = new_ek.to_bytes();
            let mut new_ek_bytes = [0u8; ML_KEM_PUB_BYTES];
            new_ek_bytes.copy_from_slice(new_ek_arr.as_slice());

            // Move current → previous, install new.
            let mut old_dk = new_dk;
            std::mem::swap(&mut self.dk, &mut old_dk);
            self.prev_dk = Some(old_dk);
            self.ek_bytes = new_ek_bytes;
            self.rotated_at = Instant::now();
            changed = true;
        }

        changed
    }

    /// Test helper: force a rotation regardless of timer.
    #[cfg(test)]
    fn force_rotate(&mut self) {
        let (new_dk, new_ek) = MlKem768::generate_keypair();
        let new_ek_arr = new_ek.to_bytes();
        let mut new_ek_bytes = [0u8; ML_KEM_PUB_BYTES];
        new_ek_bytes.copy_from_slice(new_ek_arr.as_slice());
        let mut old_dk = new_dk;
        std::mem::swap(&mut self.dk, &mut old_dk);
        self.prev_dk = Some(old_dk);
        self.ek_bytes = new_ek_bytes;
        self.rotated_at = Instant::now();
    }

    /// Test helper: clear the prev_dk slot (simulates overlap-window expiry).
    #[cfg(test)]
    fn drop_prev(&mut self) {
        self.prev_dk = None;
    }
}

/// Encapsulate against a peer's serialized ML-KEM-768 encapsulation key.
/// Returns (ciphertext, shared_secret).
fn pq_encapsulate(
    ek_bytes: &[u8; ML_KEM_PUB_BYTES],
) -> Result<([u8; ML_KEM_CT_BYTES], [u8; ML_KEM_SHARED_BYTES])> {
    let ek_arr = Array::try_from(ek_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("ml-kem: bad ek length"))?;
    let ek = <MlKemEk as TryKeyInit>::new(&ek_arr)
        .map_err(|_| anyhow::anyhow!("ml-kem: invalid encapsulation key"))?;
    let (ct, shared) = ek.encapsulate();
    let mut ct_bytes = [0u8; ML_KEM_CT_BYTES];
    ct_bytes.copy_from_slice(ct.as_slice());
    let mut shared_bytes = [0u8; ML_KEM_SHARED_BYTES];
    shared_bytes.copy_from_slice(shared.as_slice());
    Ok((ct_bytes, shared_bytes))
}

/// Combine a per-packet X25519 shared secret with a per-session ML-KEM shared
/// secret into the AEAD key.
///
///   key = HKDF-Extract(salt = pq_shared, IKM = x25519_shared)
///         then HKDF-Expand for a domain-separated 32-byte output.
///
/// Hybrid guarantee: the output is indistinguishable from random if EITHER
/// the classical (X25519) or post-quantum (ML-KEM) component is secure.
fn derive_packet_key(
    x25519_shared: &[u8; 32],
    pq_shared: Option<&[u8; ML_KEM_SHARED_BYTES]>,
) -> [u8; 32] {
    let salt: Option<&[u8]> = pq_shared.map(|s| s.as_slice());
    let h = Hkdf::<Sha256>::new(salt, x25519_shared);
    let mut key = [0u8; 32];
    h.expand(b"norn:session-key:v3", &mut key)
        .expect("HKDF expand for 32 bytes is infallible");
    key
}
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// ML-KEM-768 wire sizes (FIPS 203).
pub const ML_KEM_PUB_BYTES: usize = 1184;
pub const ML_KEM_CT_BYTES: usize = 1088;
pub const ML_KEM_SHARED_BYTES: usize = 32;

/// Total bytes of an encoded SessionInit (v3) frame on the wire.
pub const SESSION_INIT_WIRE_BYTES: usize = 1 + 32 + 64 + 32 + 8 + 32 + ML_KEM_PUB_BYTES;
/// Total bytes of an encoded SessionAck (v3) frame on the wire.
pub const SESSION_ACK_WIRE_BYTES: usize = 1 + 32 + 64 + 32 + 8 + 32 + ML_KEM_CT_BYTES;

// Anti-amplification: response (Ack) MUST NOT be larger than the trigger (Init).
// SessionInit carries ml_kem_pub (1184 B); SessionAck carries ml_kem_ct (1088 B).
// So responder→initiator amplification factor < 1. No reflection vector.
const _: () = assert!(
    SESSION_ACK_WIRE_BYTES <= SESSION_INIT_WIRE_BYTES,
    "SessionAck must not exceed SessionInit in size (anti-amplification)"
);

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
/// Roadmap #4: a memoised X25519 shared secret, tagged with the public
/// keys it was derived from so [`SessionInfo::dh_shared`] can detect a
/// key rotation on either side and recompute. Plain bytes, `Copy` — no
/// more sensitive than `pq_shared`, which is also stored unwrapped.
#[derive(Clone, Copy)]
struct CachedDh {
    local_fp: [u8; 32],
    remote_fp: [u8; 32],
    shared: [u8; 32],
}

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

    /// Post-quantum shared secret derived during handshake. Once set, every
    /// per-packet AEAD key is HKDF-Extract(salt=pq_shared, ikm=x25519_shared)
    /// so the session remains confidential against a future quantum break of
    /// X25519 alone. None until the handshake completes.
    pq_shared: Option<[u8; ML_KEM_SHARED_BYTES]>,
    /// Secondary `pq_shared` candidate used only during the ML-KEM rotation
    /// overlap window. If we just rotated our ML-KEM keypair, an inbound Ack
    /// might have been encap'd against either our new or our just-retired
    /// pub. We decap with both, store both, and `decrypt` tries each in turn.
    /// Cleared as soon as a packet successfully decrypts with `pq_shared`
    /// (i.e. once we know which one was the right one).
    pq_shared_fallback: Option<[u8; ML_KEM_SHARED_BYTES]>,

    /// Roadmap #4: memoised `DH(local_x25519_priv, remote_x25519_pub)`.
    /// `None` until the first encrypt/decrypt; refreshed automatically
    /// by `dh_shared` whenever either key rotates.
    cached_dh: Option<CachedDh>,
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
            pq_shared: None,
            pq_shared_fallback: None,
            cached_dh: None,
        }
    }

    /// Test helper / introspection: is the PQ-hybrid secret set on this session?
    pub fn has_pq_shared(&self) -> bool {
        self.pq_shared.is_some()
    }

    fn compute_key(local_priv: &StaticSecret, remote_pub: &X25519PublicKey) -> [u8; 32] {
        let shared = local_priv.diffie_hellman(remote_pub);
        *shared.as_bytes()
    }

    /// Roadmap #4: X25519 shared secret for `DH(local_x25519_priv, remote)`,
    /// memoised.
    ///
    /// `encrypt`/`decrypt` would otherwise run a full X25519 scalar
    /// multiplication — ~55µs, the dominant cost in the encrypt
    /// benchmark — on *every* packet, even though `local_x25519_priv`
    /// and the peer's pub key only change on key rotation. The cache is
    /// self-validating: it records the public-key fingerprints the
    /// secret was derived from and recomputes whenever either side
    /// rotates, so there is no invalidation to forget at the key-
    /// mutation sites.
    fn dh_shared(&mut self, remote: &X25519PublicKey) -> [u8; 32] {
        let local_fp = *self.local_x25519_pub.as_bytes();
        let remote_fp = *remote.as_bytes();
        if let Some(c) = self.cached_dh {
            if c.local_fp == local_fp && c.remote_fp == remote_fp {
                return c.shared;
            }
        }
        let shared = Self::compute_key(&self.local_x25519_priv, remote);
        self.cached_dh = Some(CachedDh { local_fp, remote_fp, shared });
        shared
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
        // Roadmap #4: memoised DH (see `dh_shared`) — was a full ~55µs
        // X25519 scalar-mult on every single packet.
        let remote = self.remote_x25519_pub;
        let x25519_shared = self.dh_shared(&remote);
        // Hybrid: HKDF combines per-packet X25519 with per-session PQ secret.
        let key_bytes = derive_packet_key(&x25519_shared, self.pq_shared.as_ref());
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
        // equals DH(sender_priv, our_local_pub) by commutativity.
        // Roadmap #4: memoised — a steady (non-rotating) sender hits the
        // cache every packet; a sender rotation refreshes it once.
        let x25519_shared = self.dh_shared(&sender_x_pub);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&seq.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Anti-replay sliding window (64 slots).
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

        // PQ-hybrid: prefer the primary pq_shared candidate. If AEAD fails
        // AND we have a fallback (set during ML-KEM rotation overlap), retry
        // with the fallback and on success promote it to primary so the
        // session converges on the right key after the first packet.
        let primary_key = derive_packet_key(&x25519_shared, self.pq_shared.as_ref());
        let raw_ct = &ciphertext[40..];

        let mut buf = raw_ct.to_vec();
        let primary_ok = {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&primary_key));
            cipher.decrypt_in_place(nonce, &sender_x_pub_bytes, &mut buf).is_ok()
        };
        if !primary_ok {
            // Try fallback.
            if let Some(fb) = self.pq_shared_fallback.as_ref() {
                let fb_key = derive_packet_key(&x25519_shared, Some(fb));
                let mut fb_buf = raw_ct.to_vec();
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&fb_key));
                if cipher.decrypt_in_place(nonce, &sender_x_pub_bytes, &mut fb_buf).is_ok() {
                    // Fallback worked. Promote: the initiator must have
                    // encap'd against our previous ek; keep that as primary
                    // for this session and clear the fallback slot.
                    self.pq_shared = Some(*fb);
                    self.pq_shared_fallback = None;
                    buf = fb_buf;
                } else {
                    bail!("decrypt error: AEAD failed with both primary and fallback PQ keys");
                }
            } else {
                bail!("decrypt error: AEAD failed");
            }
        } else {
            // Primary worked → fallback no longer needed.
            self.pq_shared_fallback = None;
        }

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

// v3 protocol: bumped from v2 (0x73/0x61) to make PQ-incompatible peers fail
// loudly at the very first parse step. v2 receivers see "invalid magic" and
// reject; v3 receivers see the new variants and parse the extended wire.
pub const SESSION_INIT_MAGIC: u8 = 0x74; // 't' (v3, PQ hybrid)
pub const SESSION_ACK_MAGIC: u8 = 0x62;  // 'b' (v3, PQ hybrid)

/// Maximum clock skew tolerated for SessionInit/Ack timestamps, milliseconds.
/// Inits older than this (relative to local wall clock) are rejected as replays;
/// inits from too far in the future are also rejected (forward-skew abuse).
///
/// 5 minutes (not 60 s). Rationale: in the open Internet many real peers
/// have CMOS-drained clocks or no NTP (IoT, fresh VM clones, embedded
/// gear); a 60 s window silently excludes them from the mesh forever, which
/// is much worse than letting through a slightly stale Init. The actual
/// replay-protection comes from the per-session 64-bit seq + sliding window
/// in `SessionInfo` — a replayed Init only burns one ML-KEM encap on the
/// receiver (rate-limited by `SessionManager::rate_limited`), it cannot
/// resurrect any old session state because every Init has fresh keys.
pub const HANDSHAKE_TIME_WINDOW_MS: u64 = 5 * 60 * 1_000; // 5 min

/// SessionInit (v3, PQ hybrid) wire format:
///   [magic:1][ed_pub:32][sig:64][x25519_pub:32][timestamp_ms:8 LE]
///   [recipient_ed_pub:32][ml_kem_pub:1184]
/// sig covers everything *except* the sig field itself.
pub struct SessionInit {
    pub ed_pub: [u8; 32],
    pub signature: [u8; 64],
    pub x25519_pub: [u8; 32],
    pub timestamp_ms: u64,
    pub recipient_ed_pub: [u8; 32],
    pub ml_kem_pub: [u8; ML_KEM_PUB_BYTES],
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn build_init_sign_bytes(
    ed_pub: &[u8; 32],
    x25519_pub: &[u8; 32],
    timestamp_ms: u64,
    recipient_ed_pub: &[u8; 32],
    ml_kem_pub: &[u8; ML_KEM_PUB_BYTES],
) -> Vec<u8> {
    let mut sign_data = Vec::with_capacity(1 + 32 + 32 + 8 + 32 + ML_KEM_PUB_BYTES);
    sign_data.push(SESSION_INIT_MAGIC);
    sign_data.extend_from_slice(ed_pub);
    sign_data.extend_from_slice(x25519_pub);
    sign_data.extend_from_slice(&timestamp_ms.to_le_bytes());
    sign_data.extend_from_slice(recipient_ed_pub);
    sign_data.extend_from_slice(ml_kem_pub);
    sign_data
}

fn build_ack_sign_bytes(
    ed_pub: &[u8; 32],
    x25519_pub: &[u8; 32],
    timestamp_ms: u64,
    recipient_ed_pub: &[u8; 32],
    ml_kem_ct: &[u8; ML_KEM_CT_BYTES],
) -> Vec<u8> {
    let mut sign_data = Vec::with_capacity(1 + 32 + 32 + 8 + 32 + ML_KEM_CT_BYTES);
    sign_data.push(SESSION_ACK_MAGIC);
    sign_data.extend_from_slice(ed_pub);
    sign_data.extend_from_slice(x25519_pub);
    sign_data.extend_from_slice(&timestamp_ms.to_le_bytes());
    sign_data.extend_from_slice(recipient_ed_pub);
    sign_data.extend_from_slice(ml_kem_ct);
    sign_data
}

impl SessionInit {
    /// Create a SessionInit bound to a specific recipient.
    pub fn create(
        signing_key: &SigningKey,
        x25519_pub: &X25519PublicKey,
        recipient_ed_pub: &[u8; 32],
        ml_kem_pub: &[u8; ML_KEM_PUB_BYTES],
    ) -> Self {
        let ed_pub = signing_key.verifying_key().to_bytes();
        let x_bytes = *x25519_pub.as_bytes();
        let timestamp_ms = now_ms();
        let sign_data = build_init_sign_bytes(
            &ed_pub, &x_bytes, timestamp_ms, recipient_ed_pub, ml_kem_pub,
        );
        let signature = signing_key.sign(&sign_data).to_bytes();
        SessionInit {
            ed_pub, signature, x25519_pub: x_bytes,
            timestamp_ms, recipient_ed_pub: *recipient_ed_pub,
            ml_kem_pub: *ml_kem_pub,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + 64 + 32 + 8 + 32 + ML_KEM_PUB_BYTES);
        buf.push(SESSION_INIT_MAGIC);
        buf.extend_from_slice(&self.ed_pub);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&self.x25519_pub);
        buf.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        buf.extend_from_slice(&self.recipient_ed_pub);
        buf.extend_from_slice(&self.ml_kem_pub);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() || data[0] != SESSION_INIT_MAGIC {
            bail!("invalid SessionInit magic");
        }
        let need = 1 + 32 + 64 + 32 + 8 + 32 + ML_KEM_PUB_BYTES;
        if data.len() < need {
            bail!("SessionInit too short: {} (need {})", data.len(), need);
        }
        let mut pos = 1;
        let mut ed_pub = [0u8; 32];
        ed_pub.copy_from_slice(&data[pos..pos + 32]); pos += 32;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[pos..pos + 64]); pos += 64;
        let mut x25519_pub = [0u8; 32];
        x25519_pub.copy_from_slice(&data[pos..pos + 32]); pos += 32;
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&data[pos..pos + 8]); pos += 8;
        let timestamp_ms = u64::from_le_bytes(ts_bytes);
        let mut recipient_ed_pub = [0u8; 32];
        recipient_ed_pub.copy_from_slice(&data[pos..pos + 32]); pos += 32;
        let mut ml_kem_pub = [0u8; ML_KEM_PUB_BYTES];
        ml_kem_pub.copy_from_slice(&data[pos..pos + ML_KEM_PUB_BYTES]);
        Ok(SessionInit { ed_pub, signature, x25519_pub, timestamp_ms, recipient_ed_pub, ml_kem_pub })
    }

    /// Verify the signature *and* that the init is fresh and addressed to `expected_recipient`.
    pub fn verify(&self, expected_recipient: &[u8; 32]) -> Result<()> {
        // Constant-time compare: a timing oracle on this match would let an
        // attacker iteratively guess our pub_key byte by byte. Vanishingly
        // small leak channel in practice (we're 32 bytes random), but the
        // cost is zero.
        use subtle::ConstantTimeEq;
        if self.recipient_ed_pub.ct_eq(expected_recipient).unwrap_u8() == 0 {
            bail!("SessionInit not addressed to us");
        }
        let now = now_ms();
        let skew = (now as i64 - self.timestamp_ms as i64).unsigned_abs();
        if skew > HANDSHAKE_TIME_WINDOW_MS {
            bail!("SessionInit timestamp outside ±{}ms window (skew {}ms)",
                HANDSHAKE_TIME_WINDOW_MS, skew);
        }
        let vk = VerifyingKey::from_bytes(&self.ed_pub)?;
        let sign_data = build_init_sign_bytes(
            &self.ed_pub, &self.x25519_pub, self.timestamp_ms, &self.recipient_ed_pub,
            &self.ml_kem_pub,
        );
        vk.verify(&sign_data, &Signature::from_bytes(&self.signature))?;
        Ok(())
    }
}

/// SessionAck (v3, PQ hybrid) wire format:
///   [magic:1][ed_pub:32][sig:64][x25519_pub:32][timestamp_ms:8 LE]
///   [recipient_ed_pub:32][ml_kem_ct:1088]
///
/// The `ml_kem_ct` is the responder's encapsulation of a fresh shared secret
/// against the initiator's `ml_kem_pub` from the Init. The initiator decaps
/// it with their own ML-KEM dk; both sides then hold the same pq_shared.
pub struct SessionAck {
    pub ed_pub: [u8; 32],
    pub signature: [u8; 64],
    pub x25519_pub: [u8; 32],
    pub timestamp_ms: u64,
    pub recipient_ed_pub: [u8; 32],
    pub ml_kem_ct: [u8; ML_KEM_CT_BYTES],
}

impl SessionAck {
    pub fn create(
        signing_key: &SigningKey,
        x25519_pub: &X25519PublicKey,
        recipient_ed_pub: &[u8; 32],
        ml_kem_ct: &[u8; ML_KEM_CT_BYTES],
    ) -> Self {
        let ed_pub = signing_key.verifying_key().to_bytes();
        let x_bytes = *x25519_pub.as_bytes();
        let timestamp_ms = now_ms();
        let sign_data = build_ack_sign_bytes(
            &ed_pub, &x_bytes, timestamp_ms, recipient_ed_pub, ml_kem_ct,
        );
        let signature = signing_key.sign(&sign_data).to_bytes();
        SessionAck {
            ed_pub, signature, x25519_pub: x_bytes,
            timestamp_ms, recipient_ed_pub: *recipient_ed_pub,
            ml_kem_ct: *ml_kem_ct,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + 64 + 32 + 8 + 32 + ML_KEM_CT_BYTES);
        buf.push(SESSION_ACK_MAGIC);
        buf.extend_from_slice(&self.ed_pub);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&self.x25519_pub);
        buf.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        buf.extend_from_slice(&self.recipient_ed_pub);
        buf.extend_from_slice(&self.ml_kem_ct);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() || data[0] != SESSION_ACK_MAGIC {
            bail!("invalid SessionAck magic");
        }
        let need = 1 + 32 + 64 + 32 + 8 + 32 + ML_KEM_CT_BYTES;
        if data.len() < need {
            bail!("SessionAck too short: {} (need {})", data.len(), need);
        }
        let mut pos = 1;
        let mut ed_pub = [0u8; 32];
        ed_pub.copy_from_slice(&data[pos..pos + 32]); pos += 32;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[pos..pos + 64]); pos += 64;
        let mut x25519_pub = [0u8; 32];
        x25519_pub.copy_from_slice(&data[pos..pos + 32]); pos += 32;
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&data[pos..pos + 8]); pos += 8;
        let timestamp_ms = u64::from_le_bytes(ts_bytes);
        let mut recipient_ed_pub = [0u8; 32];
        recipient_ed_pub.copy_from_slice(&data[pos..pos + 32]); pos += 32;
        let mut ml_kem_ct = [0u8; ML_KEM_CT_BYTES];
        ml_kem_ct.copy_from_slice(&data[pos..pos + ML_KEM_CT_BYTES]);
        Ok(SessionAck { ed_pub, signature, x25519_pub, timestamp_ms, recipient_ed_pub, ml_kem_ct })
    }

    pub fn verify(&self, expected_recipient: &[u8; 32]) -> Result<()> {
        if &self.recipient_ed_pub != expected_recipient {
            bail!("SessionAck not addressed to us");
        }
        let now = now_ms();
        let skew = (now as i64 - self.timestamp_ms as i64).unsigned_abs();
        if skew > HANDSHAKE_TIME_WINDOW_MS {
            bail!("SessionAck timestamp outside ±{}ms window (skew {}ms)",
                HANDSHAKE_TIME_WINDOW_MS, skew);
        }
        let vk = VerifyingKey::from_bytes(&self.ed_pub)?;
        let sign_data = build_ack_sign_bytes(
            &self.ed_pub, &self.x25519_pub, self.timestamp_ms, &self.recipient_ed_pub,
            &self.ml_kem_ct,
        );
        vk.verify(&sign_data, &Signature::from_bytes(&self.signature))?;
        Ok(())
    }
}

// ──────────────────────────────────────────────
// SessionManager
// ──────────────────────────────────────────────

/// Reference-counted handle to one peer's session state. Returned
/// by [`SessionManager::get_session`] so callers can drop the outer
/// `SessionManager` lock before doing the expensive ChaCha20-Poly1305
/// work — which means N peers can decrypt on N cores concurrently
/// instead of serialising through one global mutex. Roadmap #2.
pub type SessionHandle = std::sync::Arc<std::sync::Mutex<SessionInfo>>;

pub struct SessionManager {
    pub sessions: HashMap<[u8; 32], SessionHandle>,
    our_signing_key: SigningKey,
    /// Long-term ML-KEM-768 keypair, generated once per process. The encap
    /// pub is advertised in every outbound SessionInit; the dk is used to
    /// decap inbound SessionAck ciphertexts. For PQ forward secrecy this
    /// keypair should rotate; a daily rotation hook is straightforward to
    /// add (TODO) and would zeroize the prior dk after the grace window.
    pq_keys: PqKeys,
    /// Per-pending-initiate cache of the encap secret the initiator chose
    /// when sending an Init. On a crossing-init race this lets us reuse the
    /// secret we already committed to rather than re-encapsulating against
    /// the peer (which would change pq_shared mid-flight).
    /// keyed by (our_seq) — currently unused; placeholder for future ratchet.
    #[allow(dead_code)]
    _pq_pending: HashMap<u64, [u8; ML_KEM_SHARED_BYTES]>,
    /// Per-source rate limit on inbound `handle_init` calls. `Init` triggers
    /// an ML-KEM-768 encap (~80 µs on modern hardware, but easy to amplify
    /// over a mesh-routed flood). Each entry stores the timestamps of recent
    /// init attempts by a given source ed_pub. If a source exceeds
    /// `MAX_INITS_PER_WINDOW` in the last `INIT_RATE_WINDOW`, further inits
    /// are rejected before the encap runs.
    ///
    /// Per-IDENTITY (not per-IP): the attacker still has to pay the
    /// Sybil-PoW cost (`min_peer_difficulty_bits`) to generate enough
    /// distinct ed_pubs to amplify around this cap.
    init_rate_log: HashMap<[u8; 32], Vec<std::time::Instant>>,
}

/// Per-source rate-limit window for inbound `handle_init`. Must be short
/// enough to make legitimate session re-establishment work (peers retry on
/// timeout); long enough to bound the encap-flood throughput.
pub const INIT_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
/// Maximum inbound inits per source ed_pub per `INIT_RATE_WINDOW`. At 10s
/// window × 4 inits = 0.4 ML-KEM encaps/sec/source — well above any
/// legitimate need, well below CPU-saturation territory.
pub const MAX_INITS_PER_WINDOW: usize = 4;
/// Hard cap on the rate-log map size — bounds memory under Sybil attempts.
const MAX_INIT_RATE_LOG_ENTRIES: usize = 4_096;

impl SessionManager {
    pub fn new(signing_key: SigningKey) -> Self {
        SessionManager {
            sessions: HashMap::new(),
            our_signing_key: signing_key,
            pq_keys: PqKeys::generate(),
            _pq_pending: HashMap::new(),
            init_rate_log: HashMap::new(),
        }
    }

    /// Record an init attempt from `source` and return whether the source is
    /// currently OVER the rate limit (true = reject before doing expensive work).
    fn rate_limited(&mut self, source: &[u8; 32]) -> bool {
        let now = std::time::Instant::now();
        let cutoff = now.checked_sub(INIT_RATE_WINDOW).unwrap_or(now);

        // Bound map size before insertion. Evict an arbitrary entry whose
        // window is empty when we hit the cap — keeps memory linear in the
        // number of CONCURRENTLY active sources, not lifetime sources.
        if !self.init_rate_log.contains_key(source)
            && self.init_rate_log.len() >= MAX_INIT_RATE_LOG_ENTRIES {
            let victim = self.init_rate_log.iter()
                .find(|(_, ts)| ts.iter().all(|t| *t < cutoff))
                .map(|(k, _)| *k);
            if let Some(v) = victim {
                self.init_rate_log.remove(&v);
            } else {
                // All slots actively in use → reject conservatively rather
                // than evict an active session's quota.
                return true;
            }
        }

        let entry = self.init_rate_log.entry(*source).or_default();
        entry.retain(|t| *t >= cutoff);
        if entry.len() >= MAX_INITS_PER_WINDOW {
            return true;
        }
        entry.push(now);
        false
    }

    pub fn our_signing_key(&self) -> &SigningKey {
        &self.our_signing_key
    }

    /// Bytes of our current ML-KEM encapsulation key (advertised in
    /// outbound SessionInit). 1184 bytes. Rotates on a daily cadence —
    /// call `maybe_rotate_pq_keys()` from maintenance.
    pub fn pq_pub_bytes(&self) -> &[u8; ML_KEM_PUB_BYTES] {
        self.pq_keys.pub_bytes()
    }

    /// Called by the maintenance loop. Rotates the ML-KEM keypair when it
    /// has aged past `ML_KEM_KEY_ROTATION_MS`, and clears the prior dk
    /// once the `ML_KEM_KEY_OVERLAP_MS` window has elapsed. Returns true
    /// if anything changed.
    pub fn maybe_rotate_pq_keys(&mut self) -> bool {
        self.pq_keys.rotate_if_due()
    }

    /// Test helper: force-rotate the long-term ML-KEM keypair.
    #[cfg(test)]
    pub fn _test_force_rotate_pq(&mut self) {
        self.pq_keys.force_rotate();
    }

    #[cfg(test)]
    pub fn _test_drop_prev_pq(&mut self) {
        self.pq_keys.drop_prev();
    }

    /// Handle an incoming SessionInit (v3) from remote. Returns SessionAck bytes
    /// to send back. Encapsulates a fresh PQ shared secret against the initiator's
    /// ml_kem_pub and stores it on the session for hybrid key derivation.
    pub fn handle_init(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let init = SessionInit::decode(data)?;
        // Per-source rate limit BEFORE the expensive sig-verify + ML-KEM
        // encap. We use the claimed `init.ed_pub` rather than the underlying
        // network endpoint — the latter is already throttled at the TCP
        // listener (see transport.rs MAX_PER_IP_HANDSHAKES). This layer
        // throttles MESH-routed inits (PKT_CONTROL flooded inside Traffic),
        // which bypass the listener entirely.
        //
        // Tradeoff: a Sybil attacker can rotate ed_pubs to evade the per-
        // source cap, but each new ed_pub still has to satisfy
        // min_peer_difficulty_bits — generating thousands of valid identities
        // is non-trivial. This rate limit + PoW combo is defence-in-depth.
        if self.rate_limited(&init.ed_pub) {
            bail!(
                "handle_init: source {:?} rate-limited (>{} inits in {:?})",
                &init.ed_pub[..4], MAX_INITS_PER_WINDOW, INIT_RATE_WINDOW,
            );
        }
        let our_pub = self.our_signing_key.verifying_key().to_bytes();
        init.verify(&our_pub)?;

        let remote_x25519_pub = X25519PublicKey::from(init.x25519_pub);

        // PQ: encap fresh secret against initiator's ml_kem_pub; we'll send
        // the ciphertext back in the Ack so they can decap to the same secret.
        let (ml_kem_ct, pq_shared) = pq_encapsulate(&init.ml_kem_pub)?;

        // Crossing-init resolution. In a crossing scenario both peers run
        // both handle_init (as responder for the OTHER's Init) and
        // handle_ack (as initiator for their OWN Init). Each handle_init
        // generates a DIFFERENT shared secret via encap → naive overwrite
        // makes the two sides settle on different keys.
        //
        // Convergence rule (deterministic, derived from pub_keys only):
        //   - In handle_init we ADOPT the encap secret iff pq_shared is
        //     currently None OR the remote's pub_key is lexicographically
        //     SMALLER than ours. (The smaller-pub side is the canonical
        //     initiator; that exchange's encap is the one we keep.)
        //   - In handle_ack we ADOPT the decap secret iff pq_shared is
        //     None OR our pub_key is smaller than the remote's. (Symmetric.)
        // With both rules, the four crossing-init micro-events always
        // converge on the same secret on both sides — see the
        // pq_shared_crossing_init_converges test below.
        if let Some(existing_arc) = self.sessions.get(&init.ed_pub) {
            let mut existing = existing_arc.lock().unwrap();
            existing.remote_x25519_pub = remote_x25519_pub;
            existing.established = true;
            let adopt = existing.pq_shared.is_none() || init.ed_pub < our_pub;
            if adopt {
                existing.pq_shared = Some(pq_shared);
                existing.pq_shared_fallback = None;
            }
            let local_pub = X25519PublicKey::from(&existing.local_x25519_priv);
            let ack = SessionAck::create(
                &self.our_signing_key, &local_pub, &init.ed_pub, &ml_kem_ct,
            );
            return Ok(ack.encode());
        }

        let local_priv = StaticSecret::random_from_rng(OsRng);
        let local_pub = X25519PublicKey::from(&local_priv);
        let mut info = SessionInfo::new(init.ed_pub, local_priv, remote_x25519_pub);
        info.established = true;
        // Fresh session (no prior pq_shared) — always adopt.
        info.pq_shared = Some(pq_shared);
        self.sessions
            .insert(init.ed_pub, std::sync::Arc::new(std::sync::Mutex::new(info)));

        let ack = SessionAck::create(
            &self.our_signing_key, &local_pub, &init.ed_pub, &ml_kem_ct,
        );
        Ok(ack.encode())
    }

    /// Handle an incoming SessionAck (v3). Decapsulates the ml_kem_ct with our
    /// long-term dk and stores pq_shared on the session.
    ///
    /// SECURITY: only accept ACK if we have a pending session (we initiated).
    pub fn handle_ack(&mut self, data: &[u8]) -> Result<()> {
        let ack = SessionAck::decode(data)?;
        let our_pub = self.our_signing_key.verifying_key().to_bytes();
        ack.verify(&our_pub)?;
        let remote_x_pub = X25519PublicKey::from(ack.x25519_pub);

        // Decap with the current dk. If we're inside an ML-KEM rotation
        // overlap window, ALSO decap with the prior dk so the SessionInfo
        // has a fallback to try if our peer encap'd against our just-rotated
        // pub. SessionInfo::decrypt picks the one that AEAD-validates and
        // discards the other.
        let pq_shared = self.pq_keys.decap(&ack.ml_kem_ct)?;
        let pq_shared_fallback = self.pq_keys.decap_prev(&ack.ml_kem_ct);

        match self.sessions.get(&ack.ed_pub) {
            Some(info_arc) => {
                let mut info = info_arc.lock().unwrap();
                info.remote_x25519_pub = remote_x_pub;
                info.established = true;
                // Symmetric counterpart of the handle_init rule (see comments
                // there). In a crossing scenario this Ack might be the
                // response to our NON-canonical Init; if so, the secret we'd
                // decap differs from the secret the OTHER side just stored
                // via their handle_init. Only overwrite if (a) we have no
                // pq_shared yet, or (b) our pub_key is smaller — i.e. we are
                // the canonical initiator and this is the canonical Ack.
                let adopt = info.pq_shared.is_none() || our_pub < ack.ed_pub;
                if adopt {
                    info.pq_shared = Some(pq_shared);
                    info.pq_shared_fallback = pq_shared_fallback;
                }
                Ok(())
            }
            None => bail!("unsolicited SessionAck from {:?} (no pending init)", &ack.ed_pub[..4]),
        }
    }

    /// Initiate session with remote: creates local session state, returns SessionInit bytes.
    pub fn initiate(&mut self, remote_ed_pub: &[u8; 32]) -> Vec<u8> {
        let local_priv = StaticSecret::random_from_rng(OsRng);
        let local_pub = X25519PublicKey::from(&local_priv);
        let remote_x_placeholder = X25519PublicKey::from([0u8; 32]);
        let info = SessionInfo::new(*remote_ed_pub, local_priv, remote_x_placeholder);
        self.sessions.insert(
            *remote_ed_pub,
            std::sync::Arc::new(std::sync::Mutex::new(info)),
        );
        SessionInit::create(
            &self.our_signing_key, &local_pub, remote_ed_pub, self.pq_keys.pub_bytes(),
        ).encode()
    }

    /// Return a refcounted handle to one peer's session.
    ///
    /// The crypto hot path uses this to drop the outer
    /// `SessionManager` lock before doing ChaCha20-Poly1305 work
    /// (multi-core parallelism — Roadmap #2). The returned
    /// `SessionHandle` carries its own per-peer mutex; lock it
    /// briefly to encrypt/decrypt.
    pub fn get_session(&self, remote_ed_pub: &[u8; 32]) -> Option<SessionHandle> {
        self.sessions.get(remote_ed_pub).cloned()
    }

    pub fn encrypt(&self, remote_ed_pub: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        let handle = self.sessions.get(remote_ed_pub).context("no session")?;
        let mut info = handle.lock().unwrap();
        if !info.established {
            bail!("session not established");
        }
        info.encrypt(plaintext)
    }

    pub fn decrypt(&self, remote_ed_pub: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let handle = self.sessions.get(remote_ed_pub).context("no session")?;
        let mut info = handle.lock().unwrap();
        if !info.established {
            bail!("session not established");
        }
        info.decrypt(ciphertext)
    }

    pub fn is_established(&self, remote_ed_pub: &[u8; 32]) -> bool {
        self.sessions
            .get(remote_ed_pub)
            .map(|s| s.lock().unwrap().established)
            .unwrap_or(false)
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

/// Process-wide handle to the session manager.
///
/// `RwLock` (not `Mutex`) so the hot-path encrypt/decrypt — which
/// only need to read the per-peer `SessionHandle` map — share a
/// read guard instead of serialising through one writer. The
/// per-peer `Mutex<SessionInfo>` reached via [`SessionHandle`]
/// handles exclusion for the actual ChaCha20-Poly1305 work, so
/// the outer lock is *only* held for the hashmap lookup.
///
/// Write guards are taken for session-table mutations:
/// `handle_init`, `handle_ack`, `initiate`, `get_or_initiate_bytes`,
/// `remove`. Those are rare relative to the per-packet path.
pub type SharedSessionManager = Arc<RwLock<SessionManager>>;

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

    fn dummy_ml_kem_pub() -> [u8; ML_KEM_PUB_BYTES] {
        // Generate a real keypair just to obtain a valid pub-key shape.
        let pq = PqKeys::generate();
        *pq.pub_bytes()
    }

    #[test]
    fn session_init_verify_wrong_body_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let recipient = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let x_priv = StaticSecret::random_from_rng(OsRng);
        let x_pub = X25519PublicKey::from(&x_priv);
        let ek = dummy_ml_kem_pub();
        let init = SessionInit::create(&sk, &x_pub, &recipient, &ek);
        assert!(init.verify(&recipient).is_ok(), "valid init must verify");
        // Tamper with x25519_pub — signature no longer matches
        let bad_init = SessionInit { x25519_pub: [0xFFu8; 32], ..init };
        assert!(bad_init.verify(&recipient).is_err(), "tampered x25519_pub must fail verify");
        // Tamper with ed_pub — signature fails
        let init = SessionInit::create(&sk, &x_pub, &recipient, &ek);
        let bad_init = SessionInit {
            x25519_pub: init.x25519_pub,
            ed_pub: [0xEEu8; 32],
            ..init
        };
        assert!(bad_init.verify(&recipient).is_err(), "tampered ed_pub must fail verify");
    }

    #[test]
    fn session_init_verify_tampered_ml_kem_pub_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let recipient = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let x_pub = X25519PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let init = SessionInit::create(&sk, &x_pub, &recipient, &dummy_ml_kem_pub());
        let bad_init = SessionInit { ml_kem_pub: [0xCDu8; ML_KEM_PUB_BYTES], ..init };
        assert!(bad_init.verify(&recipient).is_err(),
            "tampered ml_kem_pub must invalidate the signature");
    }

    #[test]
    fn session_init_rejects_wrong_recipient() {
        let sk = SigningKey::generate(&mut OsRng);
        let intended = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let other    = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let x_pub = X25519PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let init = SessionInit::create(&sk, &x_pub, &intended, &dummy_ml_kem_pub());
        // Wrong recipient must reject (anti cross-target replay)
        assert!(init.verify(&other).is_err(), "init bound to {:?} must not verify for {:?}", &intended[..4], &other[..4]);
        assert!(init.verify(&intended).is_ok());
    }

    #[test]
    fn session_init_rejects_stale_timestamp() {
        let sk = SigningKey::generate(&mut OsRng);
        let recipient = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let x_pub = X25519PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let mut init = SessionInit::create(&sk, &x_pub, &recipient, &dummy_ml_kem_pub());
        // Roll the timestamp 10 minutes into the past and re-sign to keep the sig valid.
        init.timestamp_ms = init.timestamp_ms.saturating_sub(10 * 60 * 1000);
        let sign_data = build_init_sign_bytes(
            &init.ed_pub, &init.x25519_pub, init.timestamp_ms, &init.recipient_ed_pub, &init.ml_kem_pub,
        );
        init.signature = sk.sign(&sign_data).to_bytes();
        let err = init.verify(&recipient).unwrap_err().to_string();
        assert!(err.contains("window"), "stale init must mention window: {err}");
    }

    #[test]
    fn pq_shared_present_after_handshake() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_a = sk_a.verifying_key().to_bytes();
        let pub_b = sk_b.verifying_key().to_bytes();

        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);

        let init = mgr_a.initiate(&pub_b);
        let ack = mgr_b.handle_init(&init).unwrap();
        mgr_a.handle_ack(&ack).unwrap();

        // Both sides should have pq_shared set, AND it should be identical.
        let pq_a = mgr_a.sessions.get(&pub_b).unwrap().lock().unwrap().pq_shared
            .expect("initiator must have pq_shared after Ack");
        let pq_b = mgr_b.sessions.get(&pub_a).unwrap().lock().unwrap().pq_shared
            .expect("responder must have pq_shared after Init");
        assert_eq!(pq_a, pq_b,
            "PQ hybrid: both sides MUST derive the same pq_shared from ML-KEM");
    }

    #[test]
    fn ml_kem_rotation_keeps_in_flight_decryptable() {
        // Initiator I sends Init advertising I's pq_pub.
        // Then I force-rotates its ML-KEM keypair (overlap window now holds
        // prev_dk = the old priv).
        // Responder R receives Init and sends Ack encap'd against the
        // OLD ek (because Init carried the old pq_pub).
        // I receives Ack and MUST still derive the right pq_shared via the
        // fallback path.
        let sk_i = SigningKey::generate(&mut OsRng);
        let sk_r = SigningKey::generate(&mut OsRng);
        let pub_i = sk_i.verifying_key().to_bytes();
        let pub_r = sk_r.verifying_key().to_bytes();

        let mut mgr_i = SessionManager::new(sk_i);
        let mut mgr_r = SessionManager::new(sk_r);

        let init = mgr_i.initiate(&pub_r);
        // I rotates BEFORE the Ack arrives (rare but real race during a
        // periodic rotation). The Ack will be against the OLD ek; without
        // the fallback path I would now derive a wrong pq_shared.
        mgr_i._test_force_rotate_pq();

        let ack = mgr_r.handle_init(&init).unwrap();
        mgr_i.handle_ack(&ack).unwrap();

        // pq_shared on I should be set; pq_shared_fallback may be set if
        // decap_prev was invoked (it is, since prev_dk exists).
        {
            let info_i = mgr_i.sessions.get(&pub_r).unwrap().lock().unwrap();
            assert!(info_i.pq_shared.is_some());
            assert!(info_i.pq_shared_fallback.is_some(),
                "decap_prev must be tried during overlap window");
        }

        // Encrypt + decrypt roundtrip must work. The first decrypt on I's
        // side should pick the fallback (because R encap'd against I's OLD
        // ek). On success, fallback promotes to primary.
        let ct_r = mgr_r.encrypt(&pub_i, b"hello-cross-rotation").unwrap();
        let pt_i = mgr_i.decrypt(&pub_r, &ct_r).expect("decrypt must succeed via fallback");
        assert_eq!(pt_i, b"hello-cross-rotation");

        // After promotion, fallback is cleared.
        assert!(
            mgr_i.sessions.get(&pub_r).unwrap().lock().unwrap().pq_shared_fallback.is_none(),
            "fallback must be cleared after first successful decrypt"
        );
    }

    #[test]
    fn ml_kem_rotation_after_overlap_drops_old_dk() {
        let mut mgr = SessionManager::new(SigningKey::generate(&mut OsRng));
        let pub_before = *mgr.pq_keys.pub_bytes();
        mgr._test_force_rotate_pq();
        let pub_after = *mgr.pq_keys.pub_bytes();
        assert_ne!(pub_before, pub_after, "rotation must change pub");
        assert!(mgr.pq_keys.prev_dk.is_some(),
            "prev_dk must be retained within the overlap window");
        mgr._test_drop_prev_pq();
        assert!(mgr.pq_keys.prev_dk.is_none(),
            "after the overlap expires, prev_dk must be cleared (forward secrecy)");
    }

    #[test]
    fn pq_shared_crossing_init_converges() {
        // Crossing-init scenario: A and B simultaneously initiate to each
        // other. Without the lex-tiebreak resolution in handle_init /
        // handle_ack, both sides would overwrite their pq_shared with a
        // different encap result (one each) — sessions would establish but
        // every Data packet's AEAD would fail because the two sides
        // derived different per-packet keys.
        //
        // We deterministically reproduce a crossing-init below by manually
        // exchanging the four message events (two Inits, two Acks) in an
        // arbitrary order, then assert both sides end up with the same
        // pq_shared. Test runs for every ordering permutation that could
        // happen on a real network.
        use std::cmp::Ordering;

        // Valid orderings must respect causality: B.Ack (event 1) before
        // A consumes it (event 2); A.Ack (event 0) before B consumes (event 3).
        for &order in &[
            (0, 1, 2, 3),  // both produce first, then both consume in order
            (0, 1, 3, 2),  // both produce, B consumes first
            (1, 0, 2, 3),  // B produces first
            (1, 0, 3, 2),  // B produces and consumes first
            (0, 3, 1, 2),  // A produce, B consume, B produce, A consume — interleaved
        ] {
            let sk_a = SigningKey::generate(&mut OsRng);
            let sk_b = SigningKey::generate(&mut OsRng);
            let pub_a = sk_a.verifying_key().to_bytes();
            let pub_b = sk_b.verifying_key().to_bytes();
            let mut mgr_a = SessionManager::new(sk_a);
            let mut mgr_b = SessionManager::new(sk_b);

            // Both sides initiate at the same time → two Inits in flight.
            let init_a = mgr_a.initiate(&pub_b);
            let init_b = mgr_b.initiate(&pub_a);

            // Each side's handle_init produces the Ack it would have sent.
            // We capture both Acks before processing any.
            let mut ack_from_a: Option<Vec<u8>> = None;
            let mut ack_from_b: Option<Vec<u8>> = None;
            type Event = Box<dyn FnMut(&mut SessionManager, &mut SessionManager,
                                       &mut Option<Vec<u8>>, &mut Option<Vec<u8>>,
                                       &[u8], &[u8])>;
            let mut events: Vec<Event> = Vec::new();
            // 0: A handles B.Init → produces A.Ack
            events.push(Box::new(|a, _b, afa, _afb, _ia, ib| {
                *afa = Some(a.handle_init(ib).unwrap());
            }));
            // 1: B handles A.Init → produces B.Ack
            events.push(Box::new(|_a, b, _afa, afb, ia, _ib| {
                *afb = Some(b.handle_init(ia).unwrap());
            }));
            // 2: A handles B.Ack
            events.push(Box::new(|a, _b, _afa, afb, _ia, _ib| {
                a.handle_ack(afb.as_ref().expect("B.Ack must be produced first")).unwrap();
            }));
            // 3: B handles A.Ack
            events.push(Box::new(|_a, b, afa, _afb, _ia, _ib| {
                b.handle_ack(afa.as_ref().expect("A.Ack must be produced first")).unwrap();
            }));

            // The orderings we test all keep init→ack causality intact:
            // event 2 (A.handle_ack of B.Ack) must come after event 1
            // (B's handle_init that produces B.Ack), and event 3 must come
            // after event 0.
            let (e0, e1, e2, e3) = order;
            for &i in &[e0, e1, e2, e3] {
                events[i](&mut mgr_a, &mut mgr_b, &mut ack_from_a, &mut ack_from_b,
                          &init_a, &init_b);
            }

            let pq_a = mgr_a.sessions.get(&pub_b).unwrap().lock().unwrap().pq_shared.unwrap();
            let pq_b = mgr_b.sessions.get(&pub_a).unwrap().lock().unwrap().pq_shared.unwrap();
            assert_eq!(pq_a, pq_b,
                "crossing-init order ({},{},{},{}) with A.pub_cmp_B = {:?}: sides MUST converge",
                e0, e1, e2, e3, pub_a.cmp(&pub_b));
            // Also verify an encrypted Data packet round-trips both ways
            // — that's the real-world consequence of pq_shared mismatch.
            assert_ne!(pub_a.cmp(&pub_b), Ordering::Equal);
            let ct = mgr_a.encrypt(&pub_b, b"hello after crossing-init").unwrap();
            assert_eq!(mgr_b.decrypt(&pub_a, &ct).unwrap(), b"hello after crossing-init");
            let ct2 = mgr_b.encrypt(&pub_a, b"reply").unwrap();
            assert_eq!(mgr_a.decrypt(&pub_b, &ct2).unwrap(), b"reply");
        }
    }

    #[test]
    fn pq_shared_changes_per_session() {
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();
        let mut mgr_a = SessionManager::new(sk_a);
        let mut mgr_b = SessionManager::new(sk_b);

        let init1 = mgr_a.initiate(&pub_b);
        let ack1 = mgr_b.handle_init(&init1).unwrap();
        mgr_a.handle_ack(&ack1).unwrap();
        let pq1 = mgr_a.sessions.get(&pub_b).unwrap().lock().unwrap().pq_shared.unwrap();

        // Tear down and redo.
        mgr_a.remove(&pub_b);
        let init2 = mgr_a.initiate(&pub_b);
        let ack2 = mgr_b.handle_init(&init2).unwrap();
        mgr_a.handle_ack(&ack2).unwrap();
        let pq2 = mgr_a.sessions.get(&pub_b).unwrap().lock().unwrap().pq_shared.unwrap();

        assert_ne!(pq1, pq2,
            "Each session must derive a fresh pq_shared (PQ ephemeral via fresh encapsulation)");
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

    // ── rate_limited unit tests ─────────────────────────────────────────────

    #[test]
    fn rate_limit_accepts_up_to_max_then_rejects() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut mgr = SessionManager::new(sk);
        let src = [0xAA_u8; 32];
        for i in 0..MAX_INITS_PER_WINDOW {
            assert!(!mgr.rate_limited(&src),
                "init #{} of {} must pass the rate limit", i, MAX_INITS_PER_WINDOW);
        }
        assert!(mgr.rate_limited(&src),
            "init #{} (one over MAX_INITS_PER_WINDOW) must be rate-limited",
            MAX_INITS_PER_WINDOW + 1);
    }

    #[test]
    fn rate_limit_isolates_sources() {
        // Different sources have INDEPENDENT quotas — one noisy attacker
        // must not starve every other peer.
        let sk = SigningKey::generate(&mut OsRng);
        let mut mgr = SessionManager::new(sk);
        let src_a = [0x01_u8; 32];
        let src_b = [0x02_u8; 32];

        for _ in 0..MAX_INITS_PER_WINDOW { let _ = mgr.rate_limited(&src_a); }
        assert!(mgr.rate_limited(&src_a),
            "A must be limited after filling its window");
        assert!(!mgr.rate_limited(&src_b),
            "B (fresh source) must still be allowed regardless of A's quota");
    }

    #[test]
    fn rate_limit_decays_after_window() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut mgr = SessionManager::new(sk);
        let src = [0xCC_u8; 32];
        // Backdate all timestamps past the window — the next call must clear
        // and accept.
        let old = std::time::Instant::now() - INIT_RATE_WINDOW - std::time::Duration::from_secs(1);
        mgr.init_rate_log.insert(src, vec![old; MAX_INITS_PER_WINDOW]);
        assert!(!mgr.rate_limited(&src),
            "old timestamps (>WINDOW) must be evicted, freeing the source's quota");
    }
}
