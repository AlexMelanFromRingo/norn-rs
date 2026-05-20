//! Roadmap #7 — opt-in transport obfuscation.
//!
//! norn already *encrypts* payloads, but the TCP transport still has a
//! recognisable shape: the NRN1 handshake is a fixed sequence of
//! fixed-size messages, and frames are length-prefixed with plain
//! varints. A provider running deep packet inspection can fingerprint
//! that and block the flows without ever decrypting anything.
//!
//! This module is the **first increment** of a defence: an opt-in,
//! pre-shared-key stream obfuscator that wraps the *entire* TCP byte
//! stream — NRN1 handshake included — in a keystream so that, to an
//! observer, the whole connection is indistinguishable from uniform
//! random bytes. There is no static signature left to match: no
//! plaintext handshake, no recognisable varint framing, no fixed
//! offsets.
//!
//! ## What it is — and is not
//!
//! Enabling `obfuscation_psk` makes every node that shares the PSK
//! obfuscate its TCP links. It defeats *signature-based* blocking.
//! It deliberately does **not** try to be obfs4 or defeat a
//! nation-state firewall:
//!
//! * Packet **sizes and timing** are unchanged — traffic analysis can
//!   still tell "two peers are exchanging a steady high-entropy
//!   stream". Length/timing padding is the next increment (roadmap #7).
//! * The connection still *opens* with a 16-byte cleartext nonce per
//!   direction; that is itself a (weak) signal.
//! * QUIC links are out of scope — QUIC carries its own TLS-shaped
//!   handshake; obfuscating it is a separate problem.
//!
//! ## Construction
//!
//! The PSK string is stretched once into a 32-byte key
//! (`derive_psk_key`). On every connection each side picks a random
//! 16-byte nonce and sends it in the clear; the per-connection,
//! per-direction key is `BLAKE2b(psk_key ‖ nonce)`. The keystream is
//! `BLAKE2b(conn_key ‖ counter)` in 64-byte blocks — a 64-bit counter,
//! so it never exhausts on a long-lived link. Each direction uses a
//! distinct nonce, so the two keystreams never overlap.
//!
//! This is a pure anti-fingerprinting layer: the payloads underneath
//! are already AEAD-protected, so the obfuscation keystream carries no
//! confidentiality burden — it only has to be unpredictable to an
//! observer who does not hold the PSK.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use blake2::{Blake2b512, Digest};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Length of the per-direction connection nonce exchanged in the clear.
const OBFS_NONCE_LEN: usize = 16;
/// Domain-separation tag mixed into the PSK stretch.
const PSK_DOMAIN: &[u8] = b"norn-obfs-v1-psk";

/// Stretch a user-supplied obfuscation PSK string into a 32-byte key.
/// Returns `None` for an empty PSK — that is the "obfuscation off"
/// signal, matching the `obfuscation_psk = ""` config default.
pub fn derive_psk_key(psk: &str) -> Option<[u8; 32]> {
    if psk.is_empty() {
        return None;
    }
    let mut h = Blake2b512::new();
    h.update(PSK_DOMAIN);
    h.update(psk.as_bytes());
    let full = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&full[..32]);
    Some(key)
}

/// `BLAKE2b(conn_key ‖ counter)`-in-counter-mode keystream. Infinite
/// for practical purposes (64-bit block counter) and never reused
/// across directions because each direction derives a distinct
/// `conn_key` from a distinct nonce.
struct KeyStream {
    /// `Blake2b512` pre-loaded with the connection key; cloned per
    /// block so the key-absorption work is done only once.
    base: Blake2b512,
    counter: u64,
    block: [u8; 64],
    /// Bytes of `block` already consumed; `64` means "refill".
    pos: usize,
}

impl KeyStream {
    fn new(conn_key: [u8; 32]) -> Self {
        let mut base = Blake2b512::new();
        base.update(conn_key);
        KeyStream { base, counter: 0, block: [0u8; 64], pos: 64 }
    }

    fn refill(&mut self) {
        let mut h = self.base.clone();
        h.update(self.counter.to_le_bytes());
        self.block.copy_from_slice(&h.finalize());
        self.counter = self.counter.wrapping_add(1);
        self.pos = 0;
    }

    /// XOR the keystream into `data` in place, advancing the stream by
    /// exactly `data.len()` bytes.
    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.pos >= 64 {
                self.refill();
            }
            *byte ^= self.block[self.pos];
            self.pos += 1;
        }
    }
}

/// Derive a per-connection, per-direction key from the PSK key and the
/// 16-byte nonce that side chose.
fn conn_key(psk_key: &[u8; 32], nonce: &[u8; OBFS_NONCE_LEN]) -> [u8; 32] {
    let mut h = Blake2b512::new();
    h.update(psk_key);
    h.update(nonce);
    let full = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&full[..32]);
    k
}

/// The two keystreams for one obfuscated connection, produced by
/// [`obfs_handshake`] and consumed by [`ObfsHandshake::wrap`].
pub struct ObfsHandshake {
    tx: KeyStream,
    rx: KeyStream,
}

impl ObfsHandshake {
    /// Wrap a reader/writer pair with this connection's keystreams.
    pub fn wrap<R, W>(self, reader: R, writer: W) -> (ObfsReader<R>, ObfsWriter<W>) {
        (
            ObfsReader::Obfs(Box::new(CipherReader { inner: reader, ks: self.rx })),
            ObfsWriter::Obfs(Box::new(CipherWriter {
                inner: writer,
                ks: self.tx,
                pending: Vec::new(),
                sent: 0,
            })),
        )
    }
}

/// Run the obfuscation nonce exchange on a freshly-connected stream:
/// send our random nonce, read the peer's, and derive both keystreams.
/// Both sides write before they read, and the nonce is only 16 bytes,
/// so this never deadlocks.
pub async fn obfs_handshake<S>(stream: &mut S, psk_key: &[u8; 32]) -> io::Result<ObfsHandshake>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use rand::RngCore;
    let mut tx_nonce = [0u8; OBFS_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut tx_nonce);
    stream.write_all(&tx_nonce).await?;
    stream.flush().await?;

    let mut rx_nonce = [0u8; OBFS_NONCE_LEN];
    stream.read_exact(&mut rx_nonce).await?;

    Ok(ObfsHandshake {
        tx: KeyStream::new(conn_key(psk_key, &tx_nonce)),
        rx: KeyStream::new(conn_key(psk_key, &rx_nonce)),
    })
}

// ── Reader ───────────────────────────────────────────────────────────────

/// Read half of a transport link — either plain or keystream-obfuscated.
/// One concrete type so `PacketConn::handle_conn` stays monomorphic.
pub enum ObfsReader<R> {
    Plain(R),
    /// Boxed so the obfuscated keystream state (a BLAKE2b hasher plus a
    /// block buffer) doesn't bloat the size of the plain variant.
    Obfs(Box<CipherReader<R>>),
}

impl<R> ObfsReader<R> {
    /// The non-obfuscated path (PSK not configured).
    pub fn plain(reader: R) -> Self {
        ObfsReader::Plain(reader)
    }
}

/// A reader that XORs the obfuscation keystream out of every byte it
/// receives. Byte-count preserving — the keystream advances by exactly
/// the number of bytes read, so it can never desync.
pub struct CipherReader<R> {
    inner: R,
    ks: KeyStream,
}

impl<R: AsyncRead + Unpin> AsyncRead for ObfsReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ObfsReader::Plain(r) => Pin::new(r).poll_read(cx, buf),
            ObfsReader::Obfs(r) => {
                // Read raw bytes from `inner`, then XOR the keystream out
                // of exactly the bytes that just arrived — the stream
                // advances by the read count, so it can never desync.
                let before = buf.filled().len();
                match Pin::new(&mut r.inner).poll_read(cx, buf) {
                    Poll::Ready(Ok(())) => {
                        r.ks.apply(&mut buf.filled_mut()[before..]);
                        Poll::Ready(Ok(()))
                    }
                    other => other,
                }
            }
        }
    }
}

// ── Writer ───────────────────────────────────────────────────────────────

/// Write half of a transport link — either plain or keystream-obfuscated.
pub enum ObfsWriter<W> {
    Plain(W),
    /// Boxed for the same reason as [`ObfsReader::Obfs`].
    Obfs(Box<CipherWriter<W>>),
}

impl<W> ObfsWriter<W> {
    /// The non-obfuscated path (PSK not configured).
    pub fn plain(writer: W) -> Self {
        ObfsWriter::Plain(writer)
    }
}

/// A writer that XORs the obfuscation keystream into every byte before
/// it hits the wire. `pending` holds at most one obfuscated `write`
/// worth of bytes when the socket applies backpressure, so the
/// keystream advances by exactly each accepted buffer — never desync.
pub struct CipherWriter<W> {
    inner: W,
    ks: KeyStream,
    pending: Vec<u8>,
    /// Bytes of `pending` already handed to `inner`.
    sent: usize,
}

impl<W: AsyncWrite + Unpin> CipherWriter<W> {
    /// Drain `pending` into `inner`. Returns `Ready(Ok(()))` only when
    /// `pending` is fully flushed.
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.sent < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.sent..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "obfs: inner writer accepted zero bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => self.sent += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ObfsWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ObfsWriter::Plain(w) => Pin::new(w).poll_write(cx, buf),
            ObfsWriter::Obfs(w) => {
                // Flush any leftover from a previous backpressured write
                // before accepting more — propagates backpressure.
                match w.drain(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
                if buf.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                // Obfuscate the whole buf into `pending`, best-effort flush.
                w.pending.extend_from_slice(buf);
                w.ks.apply(&mut w.pending);
                if let Poll::Ready(Err(e)) = w.drain(cx) {
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ObfsWriter::Plain(w) => Pin::new(w).poll_flush(cx),
            ObfsWriter::Obfs(w) => {
                match w.drain(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
                Pin::new(&mut w.inner).poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ObfsWriter::Plain(w) => Pin::new(w).poll_shutdown(cx),
            ObfsWriter::Obfs(w) => {
                match w.drain(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
                Pin::new(&mut w.inner).poll_shutdown(cx)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn derive_psk_key_empty_is_none() {
        assert!(derive_psk_key("").is_none(), "empty PSK = obfuscation off");
        assert!(derive_psk_key("hunter2").is_some());
    }

    #[test]
    fn derive_psk_key_is_deterministic_and_distinct() {
        assert_eq!(derive_psk_key("alpha"), derive_psk_key("alpha"));
        assert_ne!(derive_psk_key("alpha"), derive_psk_key("beta"));
    }

    #[test]
    fn keystream_round_trips_and_is_not_identity() {
        let key = [0x11u8; 32];
        let plain = b"the quick brown fox jumps over the lazy dog".to_vec();
        let mut buf = plain.clone();
        KeyStream::new(key).apply(&mut buf);
        assert_ne!(buf, plain, "keystream must actually change the bytes");
        KeyStream::new(key).apply(&mut buf);
        assert_eq!(buf, plain, "XOR with the same keystream must restore");
    }

    #[test]
    fn keystream_spans_many_blocks_consistently() {
        // Cross several 64-byte block boundaries; a one-shot apply and a
        // byte-at-a-time apply must agree.
        let key = [0x5Au8; 32];
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let mut one_shot = data.clone();
        KeyStream::new(key).apply(&mut one_shot);
        let mut piecemeal = data.clone();
        let mut ks = KeyStream::new(key);
        for b in piecemeal.iter_mut() {
            ks.apply(std::slice::from_mut(b));
        }
        assert_eq!(one_shot, piecemeal, "chunked and one-shot keystream must match");
    }

    /// Full duplex round-trip through both wrappers, the way the
    /// transport uses them.
    #[tokio::test]
    async fn obfuscated_stream_round_trips_over_a_pipe() {
        let psk = derive_psk_key("shared-mesh-secret").unwrap();
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);

        // Both ends run the nonce handshake concurrently.
        let psk_a = psk;
        let psk_b = psk;
        let ha = tokio::spawn(async move {
            let hs = obfs_handshake(&mut a, &psk_a).await.unwrap();
            (hs, a)
        });
        let hb = tokio::spawn(async move {
            let hs = obfs_handshake(&mut b, &psk_b).await.unwrap();
            (hs, b)
        });
        let (hs_a, a) = ha.await.unwrap();
        let (hs_b, b) = hb.await.unwrap();

        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let (mut a_read, mut a_write) = hs_a.wrap(ar, aw);
        let (mut b_read, mut b_write) = hs_b.wrap(br, bw);

        let msg = b"ANNOUNCE tree=0 root=deadbeef ... plus a longer tail of bytes \
                    so we cross several keystream blocks in one write".to_vec();
        let sent = msg.clone();
        let writer = tokio::spawn(async move {
            a_write.write_all(&sent).await.unwrap();
            a_write.flush().await.unwrap();
        });
        let mut got = vec![0u8; msg.len()];
        b_read.read_exact(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, msg, "obfuscated round-trip must be lossless");

        // And the reverse direction works on its own keystream.
        let reply = b"COORD r=0.5 theta=1.2".to_vec();
        let r2 = reply.clone();
        let writer2 = tokio::spawn(async move {
            b_write.write_all(&r2).await.unwrap();
            b_write.flush().await.unwrap();
        });
        let mut got2 = vec![0u8; reply.len()];
        a_read.read_exact(&mut got2).await.unwrap();
        writer2.await.unwrap();
        assert_eq!(got2, reply);
    }

    /// The bytes actually on the wire must not be the plaintext.
    #[tokio::test]
    async fn wire_bytes_are_obfuscated() {
        let psk = derive_psk_key("p").unwrap();
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);

        let cs = tokio::spawn(async move {
            let hs = obfs_handshake(&mut client, &psk).await.unwrap();
            (hs, client)
        });
        // Server side: drain the 16-byte nonce, then capture raw payload.
        let mut srv_nonce = [0u8; OBFS_NONCE_LEN];
        server.read_exact(&mut srv_nonce).await.unwrap();
        // Server still needs to send ITS nonce so the client handshake completes.
        server.write_all(&[0u8; OBFS_NONCE_LEN]).await.unwrap();
        let (hs, client) = cs.await.unwrap();

        // Wrap the whole client stream as the obfs writer — no split, so
        // dropping `writer` fully closes the duplex and `server` below
        // actually sees EOF (a lingering read-half would hang read_to_end).
        let (_r, mut writer) = hs.wrap(tokio::io::empty(), client);
        let plaintext = b"NRN1 hello plaintext marker".to_vec();
        writer.write_all(&plaintext).await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);

        let mut wire = Vec::new();
        server.read_to_end(&mut wire).await.unwrap();
        assert_eq!(wire.len(), plaintext.len(), "obfuscation is byte-count preserving");
        assert_ne!(wire, plaintext, "the plaintext must not appear on the wire");
        assert!(
            !wire.windows(4).any(|w| w == b"NRN1"),
            "no recognisable protocol marker may survive on the wire"
        );
    }

    /// A peer with the wrong PSK gets garbage, not the message.
    #[tokio::test]
    async fn wrong_psk_does_not_decode() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let good = derive_psk_key("correct-horse").unwrap();
        let bad = derive_psk_key("wrong-horse").unwrap();

        let ha = tokio::spawn(async move {
            let hs = obfs_handshake(&mut a, &good).await.unwrap();
            (hs, a)
        });
        let hb = tokio::spawn(async move {
            let hs = obfs_handshake(&mut b, &bad).await.unwrap();
            (hs, b)
        });
        let (hs_a, a) = ha.await.unwrap();
        let (hs_b, b) = hb.await.unwrap();

        let (_ar, aw) = tokio::io::split(a);
        let (br, _bw) = tokio::io::split(b);
        let (_, mut a_write) = hs_a.wrap(tokio::io::empty(), aw);
        let (mut b_read, _) = hs_b.wrap(br, tokio::io::sink());

        let msg = b"top secret".to_vec();
        a_write.write_all(&msg).await.unwrap();
        a_write.flush().await.unwrap();
        let mut got = vec![0u8; msg.len()];
        b_read.read_exact(&mut got).await.unwrap();
        assert_ne!(got, msg, "a mismatched PSK must not recover the plaintext");
    }
}
