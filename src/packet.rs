// Wire format definitions for norn-rs
// Uvarint length-prefix framing (same as Ironwood)

use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// Packet type bytes
pub const DUMMY: u8 = 0;
pub const KEEP_ALIVE: u8 = 1;
pub const SIG_REQ: u8 = 2;
pub const SIG_RES: u8 = 3;
pub const ANNOUNCE: u8 = 4;
pub const CUCKOO_FILTER: u8 = 5;
pub const PATH_LOOKUP: u8 = 6;
pub const PATH_NOTIFY: u8 = 7;
pub const PATH_BROKEN: u8 = 8;
pub const TRAFFIC: u8 = 9;
pub const TYPE_COORD_ANNOUNCE: u8 = 10;
pub const TYPE_ONION: u8 = 11;
pub const TYPE_ONION_KEY_ANNOUNCE: u8 = 12;
pub const TYPE_REPUTATION_REPORT: u8 = 13;
pub const TYPE_HOLE_PUNCH: u8 = 14;
/// "Don't try me for this tag" backtrack frame. Sent upstream when a forwarder
/// has no route for a routing_tag the cuckoo filter promised (false positive)
/// or when TTL runs out. Receiver caches (peer, tag) as a negative entry for
/// a short TTL so the next packet picks an alternative neighbour.
pub const TYPE_PATH_NEGATIVE: u8 = 15;

/// Encode a uvarint into a byte buffer.
// Skip all mutations of this function: two are permanently untestable —
//   `== 0 → != 0`: inverts the loop-exit condition; v stays 0 after the first
//     right-shift, so the else branch fires every iteration → infinite loop.
//   `| 0x80 → ^ 0x80`: equivalent mutation — `byte = v & 0x7F` always has bit 7 = 0,
//     so `byte | 0x80 == byte ^ 0x80` for every possible input.
// Neither can be caught by any finite test, so we skip rather than leave them as
// permanent timeout/missed entries in the mutation report.
#[mutants::skip]
pub fn encode_uvarint(mut v: u64, buf: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

/// Decode a uvarint from a byte slice, returning (value, bytes_consumed).
pub fn decode_uvarint(data: &[u8]) -> Result<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if shift >= 64 {
            bail!("uvarint overflow");
        }
        val |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((val, i + 1));
        }
    }
    bail!("uvarint truncated")
}

/// Read a length-prefixed frame from an async reader.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 1];
    let mut len_bytes = Vec::with_capacity(10);
    loop {
        reader.read_exact(&mut len_buf).await?;
        len_bytes.push(len_buf[0]);
        if len_buf[0] & 0x80 == 0 {
            break;
        }
        if len_bytes.len() > 9 {
            bail!("uvarint length prefix too long");
        }
    }
    let (length, _) = decode_uvarint(&len_bytes)?;
    if length == 0 {
        return Ok(vec![]);
    }
    if length > 1024 * 1024 {
        bail!("frame too large: {}", length);
    }
    let mut frame = vec![0u8; length as usize];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

/// Write a length-prefixed frame to an async writer.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    let mut buf = Vec::with_capacity(10 + data.len());
    encode_uvarint(data.len() as u64, &mut buf);
    buf.extend_from_slice(data);
    writer.write_all(&buf).await?;
    Ok(())
}

/// Write N length-prefixed frames as a single coalesced `write_all`.
///
/// This is the userspace TCP analogue of `sendmmsg(2)`: instead of N
/// independent length+payload write syscalls, we concatenate all N
/// `[varint_len][payload]` segments into one buffer and hand it to
/// the kernel in one shot. Saves the per-frame syscall, mio waker,
/// and tokio runtime poll round-trips that `perf` showed as the
/// dominant user-mode cost on the writer path (30 % of samples
/// were in `__libc_write` + `mio::Waker::wake` chain at our load).
///
/// Returns `Ok(())` only after the whole concatenated buffer has
/// been queued in the kernel TCP send buffer. On any `write_all`
/// error the partial state is undefined at the application layer
/// but TCP itself will half-close cleanly — the caller (the
/// per-peer writer task) tears the connection down and the mesh
/// `connected` counter decrements.
pub async fn write_frames_batched<W: AsyncWrite + Unpin>(
    writer: &mut W, frames: &[Vec<u8>],
) -> Result<()> {
    if frames.is_empty() {
        return Ok(());
    }
    if frames.len() == 1 {
        // Fast-path: skip the extra Vec build for the common
        // "channel had exactly one item ready" case.
        return write_frame(writer, &frames[0]).await;
    }
    // Pre-size: each frame is `varint_len + payload`. Varint is
    // 1-10 bytes; reserving 10 per frame keeps the upper bound
    // simple and is at most 10 % overhead for tiny frames.
    let total: usize = frames.iter().map(|f| 10 + f.len()).sum();
    let mut buf = Vec::with_capacity(total);
    for f in frames {
        encode_uvarint(f.len() as u64, &mut buf);
        buf.extend_from_slice(f);
    }
    writer.write_all(&buf).await?;
    Ok(())
}

// ──────────────────────────────────────────────
// Wire structs
// ──────────────────────────────────────────────

pub fn encode_path(path: &[u64]) -> Vec<u8> {
    let mut buf = Vec::new();
    for &hop in path {
        encode_uvarint(hop + 1, &mut buf);
    }
    buf.push(0);
    buf
}

pub fn decode_path(data: &[u8]) -> Result<(Vec<u64>, usize)> {
    let mut path = Vec::new();
    let mut pos = 0;
    loop {
        if pos >= data.len() {
            bail!("path not terminated");
        }
        let (val, consumed) = decode_uvarint(&data[pos..])?;
        // Guard: if decode_uvarint is mutated to return consumed=0, pos never
        // advances and the loop runs forever. Bailing on a too-long path also
        // prevents DoS from adversarial inputs.
        if consumed == 0 {
            bail!("decode_uvarint returned zero bytes consumed");
        }
        pos += consumed;
        if val == 0 {
            break;
        }
        if path.len() >= 1024 {
            bail!("path too long (> 1024 hops)");
        }
        path.push(val - 1);
    }
    Ok((path, pos))
}

#[derive(Clone, Debug)]
pub struct SigReq {
    pub tree_id: u8,
    pub seq: u64,
    pub timestamp_ms: u64,
    pub pub_key: [u8; 32],
}

impl SigReq {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![SIG_REQ, self.tree_id];
        encode_uvarint(self.seq, &mut buf);
        encode_uvarint(self.timestamp_ms, &mut buf);
        buf.extend_from_slice(&self.pub_key);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            bail!("SigReq too short");
        }
        let tree_id = data[0];
        let mut pos = 1;
        let (seq, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        let (timestamp_ms, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        if data.len() < pos + 32 {
            bail!("SigReq missing pub_key");
        }
        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(&data[pos..pos + 32]);
        Ok(SigReq { tree_id, seq, timestamp_ms, pub_key })
    }
}

#[derive(Clone, Debug)]
pub struct SigRes {
    pub tree_id: u8,
    pub seq: u64,
    pub timestamp_ms: u64,
    pub signature: [u8; 64],
    pub pub_key: [u8; 32],
}

impl SigRes {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![SIG_RES, self.tree_id];
        encode_uvarint(self.seq, &mut buf);
        encode_uvarint(self.timestamp_ms, &mut buf);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&self.pub_key);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            bail!("SigRes too short");
        }
        let tree_id = data[0];
        let mut pos = 1;
        let (seq, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        let (timestamp_ms, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        if data.len() < pos + 64 + 32 {
            bail!("SigRes missing sig/key");
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[pos..pos + 64]);
        pos += 64;
        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(&data[pos..pos + 32]);
        Ok(SigRes { tree_id, seq, timestamp_ms, signature, pub_key })
    }
}

#[derive(Clone, Debug)]
pub struct Announce {
    pub tree_id: u8,
    pub root: [u8; 32],
    pub root_seq: u64,
    pub path_cost: u64,
    pub sender: [u8; 32],
    pub signature: [u8; 64],
    pub depth: u32,
}

impl Announce {
    pub fn sign_bytes(&self) -> Vec<u8> {
        let mut buf = vec![self.tree_id];
        buf.extend_from_slice(&self.root);
        encode_uvarint(self.root_seq, &mut buf);
        encode_uvarint(self.path_cost, &mut buf);
        buf.extend_from_slice(&self.sender);
        encode_uvarint(self.depth as u64, &mut buf);
        buf
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![ANNOUNCE, self.tree_id];
        buf.extend_from_slice(&self.root);
        encode_uvarint(self.root_seq, &mut buf);
        encode_uvarint(self.path_cost, &mut buf);
        buf.extend_from_slice(&self.sender);
        buf.extend_from_slice(&self.signature);
        encode_uvarint(self.depth as u64, &mut buf);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 1 + 32 {
            bail!("Announce too short");
        }
        let tree_id = data[0];
        let mut pos = 1;
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let (root_seq, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        let (path_cost, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        if data.len() < pos + 32 + 64 {
            bail!("Announce missing sender/sig");
        }
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[pos..pos + 64]);
        pos += 64;
        let depth = if pos < data.len() {
            let (d, _) = decode_uvarint(&data[pos..])?;
            d as u32
        } else {
            0
        };
        Ok(Announce { tree_id, root, root_seq, path_cost, sender, signature, depth })
    }
}

/// Cuckoo filter gossip message, one per tree.
///
/// `generation` increments every 300 maintenance ticks (~5 min).
/// When a receiver sees a new generation, it discards its stored copy and
/// applies the incoming filter fresh — evicting stale entries from nodes
/// that have since disconnected.
#[derive(Clone, Debug)]
pub struct CuckooMsg {
    pub tree_id: u8,
    pub generation: u64,
    pub data: [u8; crate::cuckoo::FILTER_BYTES],
}

impl CuckooMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![CUCKOO_FILTER, self.tree_id];
        encode_uvarint(self.generation, &mut buf);
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            bail!("CuckooMsg too short");
        }
        let tree_id = data[0];
        let mut pos = 1;
        let (generation, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        if data.len() < pos + crate::cuckoo::FILTER_BYTES {
            bail!("CuckooMsg data too short: need {}, got {}", crate::cuckoo::FILTER_BYTES, data.len() - pos);
        }
        let cdata: [u8; crate::cuckoo::FILTER_BYTES] = data[pos..pos + crate::cuckoo::FILTER_BYTES]
            .try_into()
            .map_err(|_| anyhow::anyhow!("CuckooMsg slice error"))?;
        Ok(CuckooMsg { tree_id, generation, data: cdata })
    }
}

#[derive(Clone, Debug)]
pub struct PathLookup {
    pub target: [u8; 32],
    pub source: [u8; 32],
    pub id: u64,
    pub path: Vec<u64>,
}

impl PathLookup {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![PATH_LOOKUP];
        buf.extend_from_slice(&self.target);
        buf.extend_from_slice(&self.source);
        encode_uvarint(self.id, &mut buf);
        buf.extend_from_slice(&encode_path(&self.path));
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 64 {
            bail!("PathLookup too short");
        }
        let mut target = [0u8; 32];
        target.copy_from_slice(&data[0..32]);
        let mut source = [0u8; 32];
        source.copy_from_slice(&data[32..64]);
        let mut pos = 64;
        let (id, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        let (path, _) = decode_path(&data[pos..])?;
        Ok(PathLookup { target, source, id, path })
    }
}

#[derive(Clone, Debug)]
pub struct PathNotify {
    pub target: [u8; 32],
    pub source: [u8; 32],
    pub id: u64,
    pub path: Vec<u64>,
}

impl PathNotify {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![PATH_NOTIFY];
        buf.extend_from_slice(&self.target);
        buf.extend_from_slice(&self.source);
        encode_uvarint(self.id, &mut buf);
        buf.extend_from_slice(&encode_path(&self.path));
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 64 {
            bail!("PathNotify too short");
        }
        let mut target = [0u8; 32];
        target.copy_from_slice(&data[0..32]);
        let mut source = [0u8; 32];
        source.copy_from_slice(&data[32..64]);
        let mut pos = 64;
        let (id, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        let (path, _) = decode_path(&data[pos..])?;
        Ok(PathNotify { target, source, id, path })
    }
}

#[derive(Clone, Debug)]
pub struct PathBroken {
    pub target: [u8; 32],
    pub source: [u8; 32],
    pub id: u64,
}

impl PathBroken {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![PATH_BROKEN];
        buf.extend_from_slice(&self.target);
        buf.extend_from_slice(&self.source);
        encode_uvarint(self.id, &mut buf);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 64 {
            bail!("PathBroken too short");
        }
        let mut target = [0u8; 32];
        target.copy_from_slice(&data[0..32]);
        let mut source = [0u8; 32];
        source.copy_from_slice(&data[32..64]);
        let (id, _) = decode_uvarint(&data[64..])?;
        Ok(PathBroken { target, source, id })
    }
}

/// "Don't try me for this tag" frame. Sent by a forwarder UPSTREAM when it
/// could not route a packet for `routing_tag` — either its cuckoo claim was
/// a false positive, or it hit TTL with no progress. The upstream caches
/// (sender, routing_tag) so subsequent packets pick a different neighbour
/// instead of re-walking the dead end. This is the missing feedback channel
/// for the cuckoo-filter probabilistic-routing layer: it bounds FP cost to
/// one wasted forward per (peer, tag) per cache TTL, instead of permanently
/// losing every packet that lands on a stale FP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathNegative {
    pub routing_tag: [u8; 16],
    /// Hop count remaining (TTL) for the negative frame itself, so an
    /// adversary cannot create a routing loop by forging endless PathNegative.
    pub ttl: u8,
}

impl PathNegative {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 16 + 1);
        buf.push(TYPE_PATH_NEGATIVE);
        buf.extend_from_slice(&self.routing_tag);
        buf.push(self.ttl);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 16 + 1 {
            bail!("PathNegative too short");
        }
        let mut routing_tag = [0u8; 16];
        routing_tag.copy_from_slice(&data[..16]);
        let ttl = data[16];
        Ok(PathNegative { routing_tag, ttl })
    }
}

/// Traffic packet — full header privacy.
///
/// Both source and destination identities are hidden from intermediate nodes.
/// Intermediate nodes route only on the 16-byte `routing_tag`; they never see
/// the actual ed25519 pub keys of either party.
///
/// Wire: path | from(32) | enc_header(128) | routing_tag(16) | watermark | payload_len | payload
///
/// `enc_header` layout (128 bytes):
///   [epk: 32]                           — ephemeral X25519 pub key (per packet)
///   [AEAD_nonce0(source_ed_pub): 48]   — encrypted sender identity
///   [AEAD_nonce1(dest_ed_pub):   48]   — encrypted destination identity (self-confirmation)
///
///   key  = DH(epk_priv, dest_x25519_pub)   — only destination can derive this
///   aad  = epk bytes (authenticated)
///
/// `routing_tag` = BLAKE2b("norn:route" || dest_ed_pub)[..16]
///   — computable by anyone who knows the dest pub key (sender, routers with dest in table)
///   — cannot be reversed to recover full dest key by a passive observer
///
/// Intermediate nodes: route on routing_tag via cuckoo filters, never read enc_header.
/// Destination: decrypt enc_header → verify dest matches self → decrypt payload.
///
/// Payload is padded to a 256-byte block boundary BEFORE encryption:
///   [orig_len: 2 bytes LE][payload...][zero padding...]
/// This prevents payload-length-based traffic analysis.
#[derive(Clone, Debug)]
pub struct Traffic {
    /// Source routing path (hop indices)
    pub path: Vec<u64>,
    /// Immediate sender's public key (direct peer, for RTT tracking)
    pub from: [u8; 32],
    /// Encrypted source+dest header — 128 bytes, only destination can decrypt.
    /// Layout: epk(32) | AEAD_nonce0(source_ed_pub)(48) | AEAD_nonce1(dest_ed_pub)(48)
    pub enc_header: [u8; 128],
    /// Routing tag — 16-byte BLAKE2b hash of dest pub key, for cuckoo filter lookup.
    /// Intermediate nodes route on this; they cannot recover the full dest key.
    pub routing_tag: [u8; 16],
    /// Packet type: 0x00 = session control (unencrypted), 0x01 = session data (encrypted).
    ///
    /// This byte is visible to intermediate nodes — a known trade-off. Onion routing
    /// (planned for `feature/onion-routing`) will wrap the entire Traffic packet in
    /// additional encryption layers, hiding pkt_type from relays.
    pub pkt_type: u8,
    /// Sequence watermark for replay protection
    pub watermark: u64,
    /// Payload:
    ///   pkt_type 0x00: pad_payload(control_bytes)          — padded, NOT session-encrypted
    ///   pkt_type 0x01: session_encrypt(pad_payload(plain)) — padded then session-encrypted
    pub payload: Vec<u8>,
}

/// Session control packet (pkt_type = 0x00).
pub const PKT_CONTROL: u8 = 0x00;
/// Session data packet (pkt_type = 0x01).
pub const PKT_DATA: u8 = 0x01;

impl Traffic {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![TRAFFIC];
        buf.extend_from_slice(&encode_path(&self.path));
        buf.extend_from_slice(&self.from);
        buf.extend_from_slice(&self.enc_header);
        buf.extend_from_slice(&self.routing_tag);
        buf.push(self.pkt_type);
        encode_uvarint(self.watermark, &mut buf);
        encode_uvarint(self.payload.len() as u64, &mut buf);
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let (path, path_len) = decode_path(data)?;
        pos += path_len;
        // from(32) + enc_header(128) + routing_tag(16) + pkt_type(1) = 177 bytes minimum
        if data.len() < pos + 177 {
            bail!("Traffic too short: need {} bytes after path, got {}", 177, data.len() - pos);
        }
        let mut from = [0u8; 32];
        from.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let enc_header: [u8; 128] = data[pos..pos + 128].try_into()
            .map_err(|_| anyhow::anyhow!("Traffic enc_header slice error"))?;
        pos += 128;
        let routing_tag: [u8; 16] = data[pos..pos + 16].try_into()
            .map_err(|_| anyhow::anyhow!("Traffic routing_tag slice error"))?;
        pos += 16;
        let pkt_type = data[pos];
        pos += 1;
        let (watermark, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        let (payload_len, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        let payload_len_usize = usize::try_from(payload_len)
            .map_err(|_| anyhow::anyhow!("Traffic payload_len too large"))?;
        let payload_end = pos.checked_add(payload_len_usize)
            .ok_or_else(|| anyhow::anyhow!("Traffic payload_len overflow"))?;
        if payload_end > data.len() {
            bail!("Traffic payload truncated: need {}, got {}", payload_len_usize, data.len() - pos);
        }
        let payload = data[pos..payload_end].to_vec();
        Ok(Traffic { path, from, enc_header, routing_tag, pkt_type, watermark, payload })
    }
}

/// Compute the 16-byte routing tag for an ed25519 public key.
///
/// Used in two places:
/// 1. Cuckoo filter gossip — nodes add `routing_tag(own_pub_key)` to their filter
///    so the filter does not expose the raw pub key.
/// 2. Traffic / Onion packet headers — `routing_tag(dest_pub_key)` replaces the
///    plaintext dest field, hiding the full destination identity from relays.
///
/// The tag is a one-way function of the pub key (Blake2b domain-separated).
/// An observer who does NOT already know a destination's pub key cannot reverse
/// the tag to learn who the destination is.
pub fn routing_tag(pub_key: &[u8; 32]) -> [u8; 16] {
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U16;
    let mut h: Blake2b<U16> = Blake2b::new();
    h.update(b"norn:route");
    h.update(pub_key);
    h.finalize().into()
}

/// Network-wide flood announcing a node's current onion ephemeral X25519 pub.
///
/// Unlike `CoordAnnounce` (one-hop only), this frame is forwarded by every
/// node that receives a fresher copy, so senders many hops away learn the
/// current ephemeral pub of any node and can build forward-secret onions to
/// non-neighbour destinations.
///
/// Wire layout (149 bytes):
///   [origin: 32]                 — the announcing node's identity pub_key
///   [seq: u64 LE]                — monotonic; receivers keep only the highest
///   [valid_from_ms: u64 LE]      — sender wall-clock; used for expiry
///   [onion_eph_pub: 32]          — the advertised ephemeral pub
///   [sig: 64]                    — signature by `origin` over the prefix
///
/// Signature covers: origin || seq || valid_from_ms || onion_eph_pub.
///
/// Anti-replay / loop control:
///   - Receiver keeps `(origin, seq)` per origin; drops stale or duplicate.
///   - Refuses announces older than ONION_KEY_VALIDITY (e.g. 24 h).
///   - Caps per-origin known announces at 1 (latest only).
#[derive(Clone, Debug)]
pub struct OnionKeyAnnounce {
    pub origin: [u8; 32],
    pub seq: u64,
    pub valid_from_ms: u64,
    pub onion_eph_pub: [u8; 32],
    pub sig: [u8; 64],
}

impl OnionKeyAnnounce {
    pub fn sign_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 8 + 8 + 32);
        buf.extend_from_slice(&self.origin);
        buf.extend_from_slice(&self.seq.to_le_bytes());
        buf.extend_from_slice(&self.valid_from_ms.to_le_bytes());
        buf.extend_from_slice(&self.onion_eph_pub);
        buf
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + 8 + 8 + 32 + 64);
        buf.push(TYPE_ONION_KEY_ANNOUNCE);
        buf.extend_from_slice(&self.origin);
        buf.extend_from_slice(&self.seq.to_le_bytes());
        buf.extend_from_slice(&self.valid_from_ms.to_le_bytes());
        buf.extend_from_slice(&self.onion_eph_pub);
        buf.extend_from_slice(&self.sig);
        buf
    }

    /// Decode from bytes *without* the leading TYPE byte.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let need = 32 + 8 + 8 + 32 + 64;
        if data.len() < need {
            bail!("OnionKeyAnnounce too short: got {} (need {})", data.len(), need);
        }
        let mut pos = 0;
        let mut origin = [0u8; 32];
        origin.copy_from_slice(&data[pos..pos + 32]); pos += 32;
        let seq = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap()); pos += 8;
        let valid_from_ms = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap()); pos += 8;
        let mut onion_eph_pub = [0u8; 32];
        onion_eph_pub.copy_from_slice(&data[pos..pos + 32]); pos += 32;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[pos..pos + 64]);
        Ok(OnionKeyAnnounce { origin, seq, valid_from_ms, onion_eph_pub, sig })
    }
}

/// Hole-punch coordination frame.
///
/// Sent A → rendezvous (a node connected to both A and B) carrying B's
/// pub_key and A's externally-observed transport endpoint. The
/// rendezvous, if connected to B, forwards the same payload to B. Both
/// A and B then simultaneously initiate a QUIC connection to each other's
/// reported endpoint. Symmetric NATs only — does nothing for full-cone /
/// restricted-cone NATs, where the existing outbound dial already works.
///
/// The frame is signed by the *initiator* so the rendezvous can't forge an
/// endpoint, and the target can verify before opening an outbound socket.
///
/// Wire layout (165 + varlen endpoint):
///   [initiator: 32]              — A's pub_key
///   [target: 32]                 — B's pub_key
///   [valid_from_ms: u64 LE]      — wall clock at send
///   [endpoint_len: u8]           — length of the endpoint string (e.g. "1.2.3.4:9001")
///   [endpoint: endpoint_len]     — A's observed-public endpoint
///   [sig: 64]                    — Ed25519 over the prefix
#[derive(Clone, Debug)]
pub struct HolePunch {
    pub initiator: [u8; 32],
    pub target: [u8; 32],
    pub valid_from_ms: u64,
    pub endpoint: String,
    pub sig: [u8; 64],
}

impl HolePunch {
    pub fn sign_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 8 + 1 + self.endpoint.len());
        buf.extend_from_slice(&self.initiator);
        buf.extend_from_slice(&self.target);
        buf.extend_from_slice(&self.valid_from_ms.to_le_bytes());
        buf.push(self.endpoint.len() as u8);
        buf.extend_from_slice(self.endpoint.as_bytes());
        buf
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + 32 + 8 + 1 + self.endpoint.len() + 64);
        buf.push(TYPE_HOLE_PUNCH);
        buf.extend_from_slice(&self.initiator);
        buf.extend_from_slice(&self.target);
        buf.extend_from_slice(&self.valid_from_ms.to_le_bytes());
        let len = self.endpoint.len().min(u8::MAX as usize);
        buf.push(len as u8);
        buf.extend_from_slice(&self.endpoint.as_bytes()[..len]);
        buf.extend_from_slice(&self.sig);
        buf
    }

    /// Decode from bytes *without* the leading TYPE byte.
    pub fn decode(data: &[u8]) -> Result<Self> {
        // Minimum: initiator(32) + target(32) + ts(8) + len(1) + sig(64)
        // with zero-length endpoint = 137 bytes.
        let min = 32 + 32 + 8 + 1 + 64;
        if data.len() < min {
            bail!("HolePunch too short: got {} (need ≥ {})", data.len(), min);
        }
        let mut pos = 0;
        let mut initiator = [0u8; 32];
        initiator.copy_from_slice(&data[pos..pos + 32]); pos += 32;
        let mut target = [0u8; 32];
        target.copy_from_slice(&data[pos..pos + 32]); pos += 32;
        let valid_from_ms = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap()); pos += 8;
        let endpoint_len = data[pos] as usize; pos += 1;
        if data.len() < pos + endpoint_len + 64 {
            bail!("HolePunch truncated: endpoint_len {} but only {} bytes left",
                endpoint_len, data.len() - pos);
        }
        let endpoint = std::str::from_utf8(&data[pos..pos + endpoint_len])
            .map_err(|_| anyhow::anyhow!("HolePunch endpoint not UTF-8"))?
            .to_string();
        pos += endpoint_len;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[pos..pos + 64]);
        Ok(HolePunch { initiator, target, valid_from_ms, endpoint, sig })
    }
}

/// Reputation report flooded through the mesh: observer's signed claim
/// about an observed peer's local trust score. Receivers aggregate these
/// per `observed` into a "consensus trust" used to bias routing lookups.
///
/// Wire layout (180 bytes):
///   [observer: 32]
///   [observed: 32]
///   [score_q16: u16 LE]      — trust score in [0..1], quantised to u16 (×65535)
///   [seq: u64 LE]            — strictly monotonic per (observer, observed)
///   [valid_from_ms: u64 LE]  — observer wall-clock
///   [sig: 64]                — Ed25519 sig by `observer` over the prefix
///
/// Signature covers everything except itself. Receivers dedup by
/// (observer, observed, seq), drop stale (> 1h) reports, and forward
/// strictly-newer-seq reports to all peers except the sender.
#[derive(Clone, Debug)]
pub struct ReputationReport {
    pub observer: [u8; 32],
    pub observed: [u8; 32],
    pub score_q16: u16,
    pub seq: u64,
    pub valid_from_ms: u64,
    pub sig: [u8; 64],
}

impl ReputationReport {
    pub fn sign_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 2 + 8 + 8);
        buf.extend_from_slice(&self.observer);
        buf.extend_from_slice(&self.observed);
        buf.extend_from_slice(&self.score_q16.to_le_bytes());
        buf.extend_from_slice(&self.seq.to_le_bytes());
        buf.extend_from_slice(&self.valid_from_ms.to_le_bytes());
        buf
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + 32 + 2 + 8 + 8 + 64);
        buf.push(TYPE_REPUTATION_REPORT);
        buf.extend_from_slice(&self.observer);
        buf.extend_from_slice(&self.observed);
        buf.extend_from_slice(&self.score_q16.to_le_bytes());
        buf.extend_from_slice(&self.seq.to_le_bytes());
        buf.extend_from_slice(&self.valid_from_ms.to_le_bytes());
        buf.extend_from_slice(&self.sig);
        buf
    }

    /// Decode from bytes *without* the leading TYPE byte.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let need = 32 + 32 + 2 + 8 + 8 + 64;
        if data.len() < need {
            bail!("ReputationReport too short: got {} (need {})", data.len(), need);
        }
        let mut pos = 0;
        let mut observer = [0u8; 32];
        observer.copy_from_slice(&data[pos..pos + 32]); pos += 32;
        let mut observed = [0u8; 32];
        observed.copy_from_slice(&data[pos..pos + 32]); pos += 32;
        let score_q16 = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()); pos += 2;
        let seq = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap()); pos += 8;
        let valid_from_ms = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap()); pos += 8;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[pos..pos + 64]);
        Ok(ReputationReport { observer, observed, score_q16, seq, valid_from_ms, sig })
    }

    /// Score as f32 in [0, 1].
    pub fn score(&self) -> f32 {
        self.score_q16 as f32 / u16::MAX as f32
    }
}

/// Broadcast by each node: its hyperbolic coordinate, onion-ephemeral pub,
/// and signed by its long-term ed25519 key.
///
/// Wire layout (v2):
///   [coord: 16][tree_depth: u32 LE][onion_eph_pub: 32][sig: 64]
///
/// Signature covers: coord || tree_depth || onion_eph_pub. The receiver
/// authenticates the announced ephemeral pub against the sender's identity
/// before using it for onion DH.
#[derive(Clone, Debug)]
pub struct CoordAnnounce {
    pub coord: [u8; 16],
    pub tree_depth: u32,
    pub onion_eph_pub: [u8; 32],
    pub sig: [u8; 64],
}

impl CoordAnnounce {
    /// Bytes that the sender must sign (everything *but* the signature).
    pub fn sign_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + 4 + 32);
        buf.extend_from_slice(&self.coord);
        buf.extend_from_slice(&self.tree_depth.to_le_bytes());
        buf.extend_from_slice(&self.onion_eph_pub);
        buf
    }

    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.coord);
        buf.extend_from_slice(&self.tree_depth.to_le_bytes());
        buf.extend_from_slice(&self.onion_eph_pub);
        buf.extend_from_slice(&self.sig);
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let need = 16 + 4 + 32 + 64;
        if data.len() < need {
            bail!("CoordAnnounce too short: got {} (need {})", data.len(), need);
        }
        let mut coord = [0u8; 16];
        coord.copy_from_slice(&data[0..16]);
        let tree_depth = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let mut onion_eph_pub = [0u8; 32];
        onion_eph_pub.copy_from_slice(&data[20..52]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[52..116]);
        Ok(CoordAnnounce { coord, tree_depth, onion_eph_pub, sig })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uvarint_roundtrip() {
        for v in [0u64, 1, 127, 128, 255, 16383, 16384, u64::MAX / 2] {
            let mut buf = Vec::new();
            encode_uvarint(v, &mut buf);
            let (decoded, _) = decode_uvarint(&buf).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn path_roundtrip() {
        let path = vec![0u64, 1, 5, 100, 255];
        let encoded = encode_path(&path);
        let (decoded, _) = decode_path(&encoded).unwrap();
        assert_eq!(path, decoded);
    }

    #[tokio::test]
    async fn frame_roundtrip() {
        let data = b"hello world";
        let mut buf = Vec::new();
        write_frame(&mut buf, data).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, data);
    }

    #[test]
    fn announce_roundtrip() {
        let ann = Announce {
            tree_id: 1,
            root: [0xABu8; 32],
            root_seq: 42,
            path_cost: 1000,
            sender: [0xCDu8; 32],
            signature: [0u8; 64],
            depth: 3,
        };
        let enc = ann.encode();
        let dec = Announce::decode(&enc[1..]).unwrap();
        assert_eq!(dec.tree_id, 1);
        assert_eq!(dec.root, [0xABu8; 32]);
        assert_eq!(dec.root_seq, 42);
        assert_eq!(dec.path_cost, 1000);
        assert_eq!(dec.depth, 3);
    }

    #[test]
    fn traffic_roundtrip() {
        let traffic = Traffic {
            path: vec![1, 2, 3],
            from: [0xABu8; 32],
            enc_header: [0x11u8; 128],
            routing_tag: [0x22u8; 16],
            pkt_type: PKT_DATA,
            watermark: 999,
            payload: vec![1, 2, 3, 4, 5],
        };
        let enc = traffic.encode();
        let dec = Traffic::decode(&enc[1..]).unwrap();
        assert_eq!(dec.path, vec![1, 2, 3]);
        assert_eq!(dec.from, [0xABu8; 32]);
        assert_eq!(dec.enc_header, [0x11u8; 128]);
        assert_eq!(dec.routing_tag, [0x22u8; 16]);
        assert_eq!(dec.pkt_type, PKT_DATA);
        assert_eq!(dec.watermark, 999);
        assert_eq!(dec.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn cuckoo_msg_roundtrip() {
        let data = [0xABu8; crate::cuckoo::FILTER_BYTES];
        let msg = CuckooMsg { tree_id: 2, generation: 42, data };
        let enc = msg.encode();
        let dec = CuckooMsg::decode(&enc[1..]).unwrap();
        assert_eq!(dec.tree_id, 2);
        assert_eq!(dec.generation, 42);
        assert_eq!(dec.data, data);
    }

    // ── SigReq ───────────────────────────────────────────────────────────────

    #[test]
    fn sigreq_roundtrip_all_fields() {
        let req = SigReq {
            tree_id: 2,
            seq: 0xDEAD_BEEF,
            timestamp_ms: 1_700_000_000_123,
            pub_key: [0xABu8; 32],
        };
        let enc = req.encode();
        assert_eq!(enc[0], SIG_REQ);
        let dec = SigReq::decode(&enc[1..]).unwrap();
        assert_eq!(dec.tree_id, req.tree_id);
        assert_eq!(dec.seq, req.seq);
        assert_eq!(dec.timestamp_ms, req.timestamp_ms);
        assert_eq!(dec.pub_key, req.pub_key);
    }

    #[test]
    fn sigreq_decode_truncated_fails() {
        // Empty / too-short data must error
        assert!(SigReq::decode(&[]).is_err());
        assert!(SigReq::decode(&[0u8; 1]).is_err());
        // tree_id byte present but no pub_key
        assert!(SigReq::decode(&[0u8, 1, 1]).is_err());
    }

    // Kills `< 2 → <= 2` mutation on line 135.
    // With original `< 2`: 2-byte input passes the initial check and fails later
    // with "missing pub_key". With `<= 2`: 2-byte input fails at "too short".
    // A 2-byte input [tree_id=0, seq_varint=0] fails either way, but the error
    // message distinguishes the mutation.
    #[test]
    fn sigreq_decode_2_bytes_fails_at_pubkey_not_too_short() {
        // [tree_id=0, seq_uvarint=0] → 2 bytes. Both seq and timestamp parse as 0
        // (pos reaches 3 after parsing 1-byte seq and 1-byte timestamp from a 2-byte slice
        // — actually with data=[0,0]: data[0]=tree_id, data[1..]=seq. seq=0 (n=1), pos=2.
        // timestamp: data[2..] is empty → decode_uvarint on empty → error.
        // Either way, error must NOT be "too short".
        let err = SigReq::decode(&[0u8; 2]).unwrap_err().to_string();
        assert!(!err.contains("too short"),
            "2-byte SigReq must fail at seq/ts/pubkey parse, not 'too short'; got: {err}");
    }

    // ── SigRes ───────────────────────────────────────────────────────────────

    #[test]
    fn sigres_roundtrip_all_fields() {
        let res = SigRes {
            tree_id: 1,
            seq: 999,
            timestamp_ms: 42_000,
            signature: [0x5Au8; 64],
            pub_key: [0x3Cu8; 32],
        };
        let enc = res.encode();
        assert_eq!(enc[0], SIG_RES);
        let dec = SigRes::decode(&enc[1..]).unwrap();
        assert_eq!(dec.tree_id, res.tree_id);
        assert_eq!(dec.seq, res.seq);
        assert_eq!(dec.timestamp_ms, res.timestamp_ms);
        assert_eq!(dec.signature, res.signature);
        assert_eq!(dec.pub_key, res.pub_key);
    }

    #[test]
    fn sigres_decode_truncated_fails() {
        assert!(SigRes::decode(&[]).is_err());
        assert!(SigRes::decode(&[0u8, 1, 1]).is_err()); // missing sig + key
    }

    // Kills `< 2 → <= 2` mutation on line 173 (SigRes).
    #[test]
    fn sigres_decode_2_bytes_fails_at_parse_not_too_short() {
        let err = SigRes::decode(&[0u8; 2]).unwrap_err().to_string();
        assert!(!err.contains("too short"),
            "2-byte SigRes must fail at seq/ts/sig parse, not 'too short'; got: {err}");
    }

    // Kills `64 + 32 → 64 - 32 = 32` mutation on line 182.
    // With mutation: data.len() < pos + 32 instead of pos + 96. An input with
    // exactly a signature (64 bytes) but no pub_key passes the mutated check
    // and then panics on data[pos..pos+64] read. Original rejects it as
    // "SigRes missing sig/key".
    #[test]
    fn sigres_decode_sig_only_missing_pubkey_fails() {
        // [tree_id=0, seq=0 (1B), ts=0 (1B), sig=[0;64]] = 67 bytes, no pub_key
        let mut data = vec![0u8]; // tree_id
        data.push(0u8); // seq = 0
        data.push(0u8); // timestamp_ms = 0
        data.extend_from_slice(&[0x5Au8; 64]); // signature (64 bytes)
        // NO pub_key: data.len() = 1+1+1+64 = 67, pos = 3 after parsing
        // Original: 67 < 3 + 96 → true → bail "SigRes missing sig/key"
        // Mutation: 67 < 3 + 32 → false → tries to read sig OK, then pub_key panics
        assert!(SigRes::decode(&data).is_err(),
            "SigRes with sig but no pub_key must fail");
    }

    // ── Announce::sign_bytes ─────────────────────────────────────────────────

    #[test]
    fn announce_sign_bytes_changes_with_fields() {
        let base = Announce {
            tree_id: 0, root: [0xAAu8; 32], root_seq: 1, path_cost: 100,
            sender: [0xBBu8; 32], signature: [0u8; 64], depth: 1,
        };
        let mut changed_root = base.clone();
        changed_root.root = [0xCCu8; 32];
        let mut changed_seq = base.clone();
        changed_seq.root_seq = 2;
        let mut changed_cost = base.clone();
        changed_cost.path_cost = 200;

        assert_ne!(base.sign_bytes(), changed_root.sign_bytes(), "root change must affect sign_bytes");
        assert_ne!(base.sign_bytes(), changed_seq.sign_bytes(), "seq change must affect sign_bytes");
        assert_ne!(base.sign_bytes(), changed_cost.sign_bytes(), "cost change must affect sign_bytes");
    }

    #[test]
    fn announce_decode_truncated_fails() {
        assert!(Announce::decode(&[]).is_err());
        assert!(Announce::decode(&[0u8; 5]).is_err());
        // Kills `+ → *` on line 245: `1 * 32 = 32` → `32 < 32` is false → panics reading data[1..33].
        assert!(Announce::decode(&[0u8; 32]).is_err());
    }

    // Kills `< → <=` on line 245.
    // 33 bytes = 1 + 32 passes the initial `< 1+32=33` guard but fails later at
    // root_seq decode (data[33..] is empty). With `<= 33` it bails "too short" instead.
    #[test]
    fn announce_decode_33_bytes_fails_past_initial_check() {
        let err = Announce::decode(&[0u8; 33]).unwrap_err().to_string();
        assert!(!err.contains("too short"),
            "33-byte Announce must fail past initial guard (at root_seq), not 'too short'; got: {err}");
    }

    // Kills `< → ==` and both `+ → -` mutations on line 257.
    // With `< → ==`: `pos+95 == pos+96` → false → reads sender OK, panics on sig.
    // With `+ → -` variants: guard weakened → passes → panics reading truncated sig.
    #[test]
    fn announce_decode_partial_sig_fails() {
        // tree_id(1) + root(32) + root_seq_0(1) + path_cost_0(1) = pos=35; then 95 more = 130 total
        let mut data = vec![0u8]; // tree_id
        data.extend_from_slice(&[0u8; 32]); // root
        data.push(0u8); // root_seq = 0
        data.push(0u8); // path_cost = 0
        data.extend_from_slice(&[0u8; 95]); // sender(32) + partial sig(63), no full sig
        // data.len() = 130 = pos(35) + 95, one byte short of pos+96
        assert!(Announce::decode(&data).is_err(), "announce with partial sig must fail");
    }

    // Kills `< → <=` on line 257 AND `< → <=` on line 266 (depth check).
    // data.len() == pos + 96 exactly:
    //   Line 257: `pos+96 < pos+96` = false (passes). With `<=` → true → bails (CAUGHT).
    //   Line 266: pos=131, data.len()=131, `131 < 131` = false → depth=0.
    //             With `<=` → `131 <= 131` = true → tries decode_uvarint on empty → error (CAUGHT).
    #[test]
    fn announce_decode_exactly_sender_sig_passes() {
        // tree_id(1) + root(32) + root_seq_0(1) + path_cost_0(1) + sender(32) + sig(64) = 131
        let mut data = vec![0u8]; // tree_id
        data.extend_from_slice(&[0xAAu8; 32]); // root
        data.push(0u8); // root_seq = 0
        data.push(0u8); // path_cost = 0
        data.extend_from_slice(&[0xBBu8; 32]); // sender
        data.extend_from_slice(&[0xCCu8; 64]); // signature; no depth byte
        // data.len() = 131 = pos(35) + 96, no depth byte
        let result = Announce::decode(&data);
        assert!(result.is_ok(), "exact-size announce (sender+sig, no depth) must decode: {:?}", result.err());
        let ann = result.unwrap();
        assert_eq!(ann.sender, [0xBBu8; 32], "sender must be parsed correctly");
        assert_eq!(ann.depth, 0, "missing depth byte means depth=0");
    }

    // Kills the remaining `+ → -` mutations on line 257 (confirmed by partial-sig test).
    // Explicitly tests that an announce truncated after the sender (no sig) fails.
    #[test]
    fn announce_decode_truncated_after_sender_fails() {
        // tree_id(1) + root(32) + root_seq_0(1) + path_cost_0(1) + sender(32) = 67 bytes; no sig
        let mut data = vec![0u8]; // tree_id
        data.extend_from_slice(&[0u8; 32]); // root
        data.push(0u8); // root_seq
        data.push(0u8); // path_cost
        data.extend_from_slice(&[0u8; 32]); // sender only, no sig
        // data.len() = 67 = pos(35) + 32
        assert!(Announce::decode(&data).is_err(), "announce without signature must fail");
    }

    // ── PathLookup / PathNotify / PathBroken ─────────────────────────────────

    #[test]
    fn path_lookup_roundtrip() {
        let lookup = PathLookup {
            target: [0x11u8; 32],
            source: [0x22u8; 32],
            id: 0xCAFE_BABE,
            path: vec![1, 2, 3],
        };
        let enc = lookup.encode();
        assert_eq!(enc[0], PATH_LOOKUP);
        let dec = PathLookup::decode(&enc[1..]).unwrap();
        assert_eq!(dec.target, lookup.target);
        assert_eq!(dec.source, lookup.source);
        assert_eq!(dec.id, lookup.id);
        assert_eq!(dec.path, lookup.path);
    }

    #[test]
    fn path_lookup_decode_truncated_fails() {
        assert!(PathLookup::decode(&[]).is_err());
        assert!(PathLookup::decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn path_notify_roundtrip() {
        let notify = PathNotify {
            target: [0x33u8; 32],
            source: [0x44u8; 32],
            id: 12345,
            path: vec![4, 5, 6],
        };
        let enc = notify.encode();
        assert_eq!(enc[0], PATH_NOTIFY);
        let dec = PathNotify::decode(&enc[1..]).unwrap();
        assert_eq!(dec.target, notify.target);
        assert_eq!(dec.source, notify.source);
        assert_eq!(dec.id, notify.id);
        assert_eq!(dec.path, notify.path);
    }

    #[test]
    fn path_notify_decode_truncated_fails() {
        assert!(PathNotify::decode(&[]).is_err());
        assert!(PathNotify::decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn path_broken_roundtrip() {
        let broken = PathBroken {
            target: [0x55u8; 32],
            source: [0x66u8; 32],
            id: 0xBEEF,
        };
        let enc = broken.encode();
        assert_eq!(enc[0], PATH_BROKEN);
        let dec = PathBroken::decode(&enc[1..]).unwrap();
        assert_eq!(dec.target, broken.target);
        assert_eq!(dec.source, broken.source);
        assert_eq!(dec.id, broken.id);
    }

    #[test]
    fn path_broken_decode_truncated_fails() {
        assert!(PathBroken::decode(&[]).is_err());
        assert!(PathBroken::decode(&[0u8; 31]).is_err()); // needs 64 bytes
    }

    // ── PathNegative roundtrip ──────────────────────────────────────────────

    #[test]
    fn path_negative_roundtrip() {
        let neg = PathNegative { routing_tag: [0xABu8; 16], ttl: 4 };
        let enc = neg.encode();
        assert_eq!(enc[0], TYPE_PATH_NEGATIVE);
        let dec = PathNegative::decode(&enc[1..]).unwrap();
        assert_eq!(dec, neg);
    }

    #[test]
    fn path_negative_decode_truncated_fails() {
        // Needs 17 bytes (16 tag + 1 ttl).
        assert!(PathNegative::decode(&[]).is_err());
        assert!(PathNegative::decode(&[0u8; 16]).is_err(), "16 bytes missing ttl");
    }

    #[test]
    fn path_negative_encode_size_is_18() {
        // 1 type byte + 16 tag + 1 ttl = 18 bytes. Cheaper than a Traffic frame
        // by an order of magnitude — backtrack must not become a DoS vector.
        let neg = PathNegative { routing_tag: [0u8; 16], ttl: 4 };
        assert_eq!(neg.encode().len(), 18,
            "PathNegative wire size must be 18 bytes (1 type + 16 tag + 1 ttl)");
    }

    // ── PathLookup / PathNotify / PathBroken 64-byte boundary ────────────────
    //
    // Kills `< → <=` mutations on the `if data.len() < 64` guards.
    // With exactly 64 bytes: the initial guard passes (64 < 64 = false), but then
    // `decode_uvarint(&data[64..])` on empty slice fails with "truncated", NOT "too short".
    // With `<= 64` mutation: 64 <= 64 = true → bails "too short". Different error message.

    #[test]
    fn path_lookup_decode_64_bytes_fails_past_initial_check() {
        let err = PathLookup::decode(&[0u8; 64]).unwrap_err().to_string();
        assert!(!err.contains("too short"),
            "64-byte PathLookup must fail at id parse (empty slice), not 'too short'; got: {err}");
    }

    #[test]
    fn path_notify_decode_64_bytes_fails_past_initial_check() {
        let err = PathNotify::decode(&[0u8; 64]).unwrap_err().to_string();
        assert!(!err.contains("too short"),
            "64-byte PathNotify must fail at id parse (empty slice), not 'too short'; got: {err}");
    }

    #[test]
    fn path_broken_decode_64_bytes_fails_past_initial_check() {
        let err = PathBroken::decode(&[0u8; 64]).unwrap_err().to_string();
        assert!(!err.contains("too short"),
            "64-byte PathBroken must fail at id parse (empty slice), not 'too short'; got: {err}");
    }

    // ── Traffic 177-byte boundary (line 488) ─────────────────────────────────
    //
    // Kills `< → <=` on `if data.len() < pos + 177`.
    // With pos=1 (one-byte zero-path) and data.len()=178: original passes (178 < 178 = false),
    // then decode_uvarint for watermark on empty data[178..] fails. Error is NOT "too short".
    // With `<= 177` mutation: 178 <= 178 = true → bails "Traffic too short".

    #[test]
    fn traffic_decode_exactly_177_fails_past_length_check() {
        let mut data = vec![0u8]; // zero-path (1 byte, pos=1 after decode)
        data.extend_from_slice(&[0u8; 177]); // from(32)+enc_header(128)+routing_tag(16)+pkt_type(1)
        // data.len() = 178 = pos(1) + 177; no watermark byte
        let err = Traffic::decode(&data).unwrap_err().to_string();
        assert!(!err.contains("too short"),
            "Traffic with exactly pos+177 bytes must fail at watermark decode, not 'too short'; got: {err}");
    }

    // ── Traffic payload boundary (line 506) ──────────────────────────────────
    //
    // Kills `< → >` on `if data.len() < pos + payload_len`.
    // With extra trailing bytes: data.len() > pos + payload_len.
    // Original (< → false): decodes payload correctly.
    // Mutation (> → true): bails "Traffic payload truncated" even though data is sufficient.

    #[test]
    fn traffic_decode_with_trailing_bytes_succeeds() {
        let mut data = vec![0u8]; // zero-path
        data.extend_from_slice(&[0u8; 32]);  // from
        data.extend_from_slice(&[0u8; 128]); // enc_header
        data.extend_from_slice(&[0u8; 16]);  // routing_tag
        data.push(0u8);                       // pkt_type = 0
        data.push(0u8);                       // watermark = 0 (uvarint)
        data.push(3u8);                       // payload_len = 3 (uvarint)
        data.extend_from_slice(&[1u8, 2, 3]); // payload (3 bytes)
        data.extend_from_slice(&[0u8; 10]);   // 10 extra trailing bytes
        // data.len() = 193, pos after decoding headers = 180, payload_len = 3
        // 193 > 180 + 3 = 183 → original: 193 < 183 = false → OK
        //                        mutation: 193 > 183 = true → bail "truncated" (CAUGHT)
        let result = Traffic::decode(&data);
        assert!(result.is_ok(), "Traffic with trailing bytes must decode OK: {:?}", result.err());
        assert_eq!(result.unwrap().payload, vec![1u8, 2, 3]);
    }

    // ── read_frame bounds ────────────────────────────────────────────────────

    #[tokio::test]
    async fn read_frame_empty_fails() {
        let buf: &[u8] = &[];
        assert!(read_frame(&mut std::io::Cursor::new(buf)).await.is_err());
    }

    #[tokio::test]
    async fn read_frame_length_mismatch_fails() {
        // Frame uses uvarint length prefix — claim 100 bytes but only provide 5
        let mut buf = Vec::new();
        encode_uvarint(100, &mut buf);
        buf.extend_from_slice(&[1u8; 5]); // only 5 bytes, not 100
        assert!(read_frame(&mut std::io::Cursor::new(buf)).await.is_err());
    }

    // ── uvarint edge cases ───────────────────────────────────────────────────

    #[test]
    fn uvarint_zero_and_max() {
        for v in [0u64, 1, u64::MAX] {
            let mut buf = Vec::new();
            encode_uvarint(v, &mut buf);
            let (decoded, used) = decode_uvarint(&buf).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(used, buf.len());
        }
    }

    #[test]
    fn decode_uvarint_empty_fails() {
        assert!(decode_uvarint(&[]).is_err());
    }

    // ── routing_tag uniqueness ────────────────────────────────────────────────

    #[test]
    fn routing_tag_differs_for_different_keys() {
        let t1 = routing_tag(&[0u8; 32]);
        let t2 = routing_tag(&[1u8; 32]);
        assert_ne!(t1, t2, "different pub keys must give different routing tags");
    }

    // ── CoordAnnounce ─────────────────────────────────────────────────────────

    #[test]
    fn coord_announce_roundtrip() {
        let ann = CoordAnnounce {
            coord: [0xABu8; 16],
            tree_depth: 42,
            onion_eph_pub: [0x77u8; 32],
            sig: [0x5Cu8; 64],
        };
        let mut buf = Vec::new();
        ann.encode_into(&mut buf);
        let dec = CoordAnnounce::decode(&buf).unwrap();
        assert_eq!(dec.coord, ann.coord);
        assert_eq!(dec.tree_depth, ann.tree_depth);
        assert_eq!(dec.onion_eph_pub, ann.onion_eph_pub);
        assert_eq!(dec.sig, ann.sig);
    }

    #[test]
    fn coord_announce_tree_depth_is_little_endian() {
        let ann = CoordAnnounce {
            coord: [0u8; 16],
            tree_depth: 0x01020304,
            onion_eph_pub: [0u8; 32],
            sig: [0u8; 64],
        };
        let mut buf = Vec::new();
        ann.encode_into(&mut buf);
        // bytes 16..20 must be LE representation of 0x01020304
        assert_eq!(buf[16], 0x04, "LE byte 0");
        assert_eq!(buf[17], 0x03, "LE byte 1");
        assert_eq!(buf[18], 0x02, "LE byte 2");
        assert_eq!(buf[19], 0x01, "LE byte 3");
        let dec = CoordAnnounce::decode(&buf).unwrap();
        assert_eq!(dec.tree_depth, 0x01020304);
    }

    // ── Anti-amplification audit: wire-size invariants ──────────────────────
    //
    // Reflection-amplification attacks rely on a UDP-style design where an
    // attacker can spoof a source address and have the server reply with
    // more bytes than the request. norn-rs runs over TCP for all session
    // traffic (no source spoofing possible), but we additionally enforce
    // that no protocol response is much bigger than its trigger.
    //
    // These tests fail compilation if the wire format grows unexpectedly,
    // so a future change that opens an amplification window will be caught
    // at review time.

    #[test]
    fn coord_announce_size_bounded() {
        // Sent to direct peers only, signed. 116 bytes is small and fixed.
        let need = 16 + 4 + 32 + 64;
        assert_eq!(need, 116, "CoordAnnounce wire size has grown unexpectedly");
    }

    #[test]
    fn onion_key_announce_size_bounded() {
        // Flooded but only on first-sight per (origin, seq). Bounded fan-out
        // because each receiver forwards only once.
        let need = 32 + 8 + 8 + 32 + 64;
        assert_eq!(need, 144, "OnionKeyAnnounce wire size has grown unexpectedly");
    }

    #[test]
    fn sigreq_vs_sigres_amplification_bounded() {
        // SigReq:  type(1) + tree_id(1) + varint(seq, ≤9) + varint(ts, ≤9) + pub(32) ≤ 52 bytes
        // SigRes:  type(1) + tree_id(1) + varint(seq, ≤9) + varint(ts, ≤9) + sig(64) + pub(32) ≤ 116 bytes
        // Amplification factor ≤ 116/35 ≈ 3.3× for typical (1-byte varint) inputs.
        // Since SigReq is rate-limited per-peer (one per KEEPALIVE_TICKS) and
        // TCP can't be source-spoofed, no reflection attack is possible.
        let req = SigReq { tree_id: 0, seq: 1, timestamp_ms: 1, pub_key: [0u8; 32] };
        let res = SigRes { tree_id: 0, seq: 1, timestamp_ms: 1, signature: [0u8; 64], pub_key: [0u8; 32] };
        let req_size = req.encode().len();
        let res_size = res.encode().len();
        assert!(res_size < 4 * req_size,
            "SigRes/SigReq amplification factor {} exceeds 4×; would be a UDP-reflection problem if any UDP path opened",
            res_size as f64 / req_size as f64);
    }

    // ── HolePunch ───────────────────────────────────────────────────────────

    #[test]
    fn hole_punch_roundtrip() {
        let hp = HolePunch {
            initiator: [0x11u8; 32],
            target: [0x22u8; 32],
            valid_from_ms: 1_700_000_000_000,
            endpoint: "203.0.113.5:9001".to_string(),
            sig: [0x33u8; 64],
        };
        let enc = hp.encode();
        assert_eq!(enc[0], TYPE_HOLE_PUNCH);
        let dec = HolePunch::decode(&enc[1..]).unwrap();
        assert_eq!(dec.initiator, hp.initiator);
        assert_eq!(dec.target, hp.target);
        assert_eq!(dec.valid_from_ms, hp.valid_from_ms);
        assert_eq!(dec.endpoint, hp.endpoint);
        assert_eq!(dec.sig, hp.sig);
    }

    #[test]
    fn hole_punch_decode_too_short() {
        let min = 32 + 32 + 8 + 1 + 64;
        let data = vec![0u8; min - 1];
        assert!(HolePunch::decode(&data).is_err());
    }

    #[test]
    fn hole_punch_decode_truncated_endpoint() {
        // Claims endpoint_len=10 but only provides 5 bytes after.
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 32]); // initiator
        data.extend_from_slice(&[0u8; 32]); // target
        data.extend_from_slice(&[0u8; 8]);  // ts
        data.push(10);                       // endpoint_len = 10
        data.extend_from_slice(b"hello");    // only 5 bytes
        data.extend_from_slice(&[0u8; 64]);  // sig
        assert!(HolePunch::decode(&data).is_err(),
            "truncated endpoint must be rejected");
    }

    // ── ReputationReport ────────────────────────────────────────────────────

    #[test]
    fn reputation_report_roundtrip() {
        let r = ReputationReport {
            observer: [0x11u8; 32],
            observed: [0x22u8; 32],
            score_q16: 32_768,
            seq: 17,
            valid_from_ms: 1_700_000_000_000,
            sig: [0x33u8; 64],
        };
        let enc = r.encode();
        assert_eq!(enc[0], TYPE_REPUTATION_REPORT);
        let dec = ReputationReport::decode(&enc[1..]).unwrap();
        assert_eq!(dec.observer, r.observer);
        assert_eq!(dec.observed, r.observed);
        assert_eq!(dec.score_q16, r.score_q16);
        assert_eq!(dec.seq, r.seq);
        assert_eq!(dec.valid_from_ms, r.valid_from_ms);
        assert_eq!(dec.sig, r.sig);
    }

    #[test]
    fn reputation_score_q16_dequantises_to_expected_range() {
        let mut r = ReputationReport {
            observer: [0u8; 32], observed: [0u8; 32], score_q16: 0,
            seq: 0, valid_from_ms: 0, sig: [0u8; 64],
        };
        r.score_q16 = 0;
        assert!((r.score() - 0.0).abs() < 1e-6);
        r.score_q16 = u16::MAX;
        assert!((r.score() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn reputation_report_decode_too_short() {
        let need = 32 + 32 + 2 + 8 + 8 + 64;
        let data = vec![0u8; need - 1];
        assert!(ReputationReport::decode(&data).is_err());
    }

    // ── OnionKeyAnnounce ────────────────────────────────────────────────────

    #[test]
    fn onion_key_announce_roundtrip() {
        let ann = OnionKeyAnnounce {
            origin: [0x11u8; 32],
            seq: 42,
            valid_from_ms: 1_700_000_000_000,
            onion_eph_pub: [0x22u8; 32],
            sig: [0x33u8; 64],
        };
        let enc = ann.encode();
        assert_eq!(enc[0], TYPE_ONION_KEY_ANNOUNCE);
        let dec = OnionKeyAnnounce::decode(&enc[1..]).unwrap();
        assert_eq!(dec.origin, ann.origin);
        assert_eq!(dec.seq, ann.seq);
        assert_eq!(dec.valid_from_ms, ann.valid_from_ms);
        assert_eq!(dec.onion_eph_pub, ann.onion_eph_pub);
        assert_eq!(dec.sig, ann.sig);
    }

    #[test]
    fn onion_key_announce_decode_too_short() {
        // Need 32+8+8+32+64 = 144 bytes; one less must fail.
        let need = 32 + 8 + 8 + 32 + 64;
        let data = vec![0u8; need - 1];
        assert!(OnionKeyAnnounce::decode(&data).is_err(),
            "{}-byte input must be rejected (need {})", need - 1, need);
        let data = vec![0u8; need];
        assert!(OnionKeyAnnounce::decode(&data).is_ok(),
            "{}-byte input must succeed", need);
    }

    #[test]
    fn onion_key_announce_sign_bytes_changes_with_each_field() {
        let base = OnionKeyAnnounce {
            origin: [0u8; 32], seq: 1, valid_from_ms: 0,
            onion_eph_pub: [0u8; 32], sig: [0u8; 64],
        };
        let mut changed = base.clone();
        changed.seq = 2;
        assert_ne!(base.sign_bytes(), changed.sign_bytes(), "seq change must affect sign_bytes");
        let mut changed = base.clone();
        changed.valid_from_ms = 1;
        assert_ne!(base.sign_bytes(), changed.sign_bytes(), "ts change must affect sign_bytes");
        let mut changed = base.clone();
        changed.onion_eph_pub = [1u8; 32];
        assert_ne!(base.sign_bytes(), changed.sign_bytes(), "eph change must affect sign_bytes");
        let mut changed = base.clone();
        changed.origin = [1u8; 32];
        assert_ne!(base.sign_bytes(), changed.sign_bytes(), "origin change must affect sign_bytes");
    }

    #[test]
    fn coord_announce_decode_truncated_fails() {
        // v2 layout: 16 (coord) + 4 (tree_depth) + 32 (onion_eph_pub) + 64 (sig) = 116 bytes
        let need = 16 + 4 + 32 + 64;
        assert!(CoordAnnounce::decode(&[0u8; 115]).is_err(), "{} - 1 bytes must fail", need);
        assert!(CoordAnnounce::decode(&[0u8; 0]).is_err(), "empty must fail");
        assert!(CoordAnnounce::decode(&vec![0u8; need]).is_ok(), "{} bytes must succeed", need);
    }

    // ── Traffic decode boundary ───────────────────────────────────────────────

    #[test]
    fn traffic_decode_truncated_after_path_fails() {
        // After empty path (zero terminator = 1 byte), need 177 bytes; provide only 176
        let mut data = vec![0u8]; // empty path
        data.extend_from_slice(&[0u8; 176]); // one short
        assert!(Traffic::decode(&data).is_err(), "too-short traffic must fail");
    }

    #[test]
    fn traffic_decode_minimal_succeeds() {
        let mut data = vec![0u8]; // empty path (zero terminator)
        data.extend_from_slice(&[0u8; 32]);  // from
        data.extend_from_slice(&[0u8; 128]); // enc_header
        data.extend_from_slice(&[0u8; 16]);  // routing_tag
        data.push(0u8);                       // pkt_type
        data.push(0u8);                       // watermark (uvarint 0)
        data.push(0u8);                       // payload_len (uvarint 0)
        let result = Traffic::decode(&data);
        assert!(result.is_ok(), "minimal traffic must decode: {:?}", result.err());
        let t = result.unwrap();
        assert_eq!(t.path, Vec::<u64>::new());
        assert_eq!(t.pkt_type, 0);
        assert_eq!(t.payload, Vec::<u8>::new());
    }

    // ── encode_path / decode_path ─────────────────────────────────────────────

    #[test]
    fn empty_path_roundtrip() {
        let path: Vec<u64> = vec![];
        let encoded = encode_path(&path);
        assert_eq!(encoded, vec![0u8], "empty path must encode as single zero byte");
        let (decoded, consumed) = decode_path(&encoded).unwrap();
        assert_eq!(decoded, path);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn encode_path_hop_zero_encodes_as_one() {
        // hop=0 must encode as 1 (not 0, which is the terminator)
        let path = vec![0u64];
        let encoded = encode_path(&path);
        assert_ne!(encoded[0], 0, "hop=0 must encode as non-zero (hop+1=1)");
        let (decoded, _) = decode_path(&encoded).unwrap();
        assert_eq!(decoded, path);
    }

    #[test]
    fn decode_path_not_terminated_fails() {
        // A path with no zero terminator must fail
        let mut buf = Vec::new();
        encode_uvarint(5, &mut buf); // val=5, no terminator
        assert!(decode_path(&buf).is_err(), "unterminated path must fail");
    }

    // ── uvarint multi-byte encoding ────────────────────────────────────────────

    #[test]
    fn uvarint_continuation_bit_correct() {
        // Value 128 = 0x80 needs 2 bytes: [0x80, 0x01]
        let mut buf = Vec::new();
        encode_uvarint(128, &mut buf);
        assert_eq!(buf.len(), 2, "128 needs 2 bytes");
        assert_eq!(buf[0] & 0x80, 0x80, "first byte must have continuation bit set");
        assert_eq!(buf[1] & 0x80, 0x00, "last byte must NOT have continuation bit");
        let (val, n) = decode_uvarint(&buf).unwrap();
        assert_eq!(val, 128);
        assert_eq!(n, 2);
    }

    #[test]
    fn uvarint_large_value_roundtrip() {
        let v = 0x0FFF_FFFF_FFFF_FFFFu64;
        let mut buf = Vec::new();
        encode_uvarint(v, &mut buf);
        let (decoded, _) = decode_uvarint(&buf).unwrap();
        assert_eq!(decoded, v, "large uvarint must roundtrip");
    }

    #[test]
    fn uvarint_7bit_shift_is_correct() {
        // 0x3FFF = 0b_0011_1111_1111_1111 → 2 bytes
        // If shift were << 6 instead of << 7, the high bits would be wrong.
        let v = 0x3FFFu64;
        let mut buf = Vec::new();
        encode_uvarint(v, &mut buf);
        assert_eq!(buf.len(), 2, "0x3FFF needs 2 bytes with 7-bit groups");
        let (decoded, _) = decode_uvarint(&buf).unwrap();
        assert_eq!(decoded, v, "shift=7 must be correct, got {:#x}", decoded);
    }

    // ── CuckooMsg ─────────────────────────────────────────────────────────────

    #[test]
    fn cuckoo_msg_generation_roundtrips_for_large_values() {
        for g in [0u64, 1, 0xFFFF_FFFF, u64::MAX / 2] {
            let data = [0u8; crate::cuckoo::FILTER_BYTES];
            let msg = CuckooMsg { tree_id: 0, generation: g, data };
            let enc = msg.encode();
            let dec = CuckooMsg::decode(&enc[1..]).unwrap();
            assert_eq!(dec.generation, g, "generation {} must roundtrip", g);
        }
    }

    #[test]
    fn cuckoo_msg_decode_truncated_fails() {
        assert!(CuckooMsg::decode(&[]).is_err());
        assert!(CuckooMsg::decode(&[0u8; 10]).is_err());
    }

    // ── read_frame size guard (kills > vs == and > vs >= mutations) ───────────

    #[tokio::test]
    async fn read_frame_exactly_1mb_passes_size_guard() {
        // length = 1024*1024 must NOT trigger "frame too large" (condition is > 1MB, not >=).
        // We only check that the error is NOT "frame too large" — it will be
        // UnexpectedEof since we provide no payload bytes.
        // Mutation `> with >=` would fail this with "frame too large".
        let limit = 1024u64 * 1024;
        let mut buf = Vec::new();
        encode_uvarint(limit, &mut buf);
        // No payload bytes — expect UnexpectedEof, not "frame too large"
        let err = read_frame(&mut std::io::Cursor::new(buf)).await.unwrap_err();
        assert!(!err.to_string().contains("too large"),
            "exactly-1MB frame must pass size guard (not 'too large'), got: {}", err);
    }

    #[tokio::test]
    async fn read_frame_over_1mb_fails_with_too_large() {
        // length = 1024*1024+1 must fail with "frame too large".
        // Mutation `> with ==` would NOT fail this (1MB+1 != 1MB).
        let over = 1024u64 * 1024 + 1;
        let mut buf = Vec::new();
        encode_uvarint(over, &mut buf);
        let err = read_frame(&mut std::io::Cursor::new(buf)).await.unwrap_err();
        assert!(err.to_string().contains("too large"),
            "1MB+1 frame must fail with 'too large', got: {}", err);
    }

    #[tokio::test]
    async fn read_frame_overlong_varint_fails() {
        // A length prefix with 10+ continuation bytes (all 0xFF) must be rejected
        // by the `len_bytes.len() > 9` guard.
        // Mutation `> with ==` would only reject exactly-10-bytes; 11 bytes would pass.
        // Mutation `> with >=` would reject 9-byte prefixes (valid u64).
        let buf = vec![0xFFu8; 11]; // 11 bytes all with continuation bit set
        let err = read_frame(&mut std::io::Cursor::new(buf)).await.unwrap_err();
        assert!(err.to_string().contains("too long") || err.to_string().contains("overflow"),
            "overlong varint must be rejected, got: {}", err);
    }

    // ── varint length guard line 62: kills > → == and > → >= ─────────────────

    // Kills `> 9 → >= 9` mutation.
    // With original `> 9`: 9 continuation bytes + 1 terminal = valid 10-byte read (9
    // bytes have continuation bit, 10th terminates). The guard fires when len > 9,
    // i.e., after reading 10th byte (len=10 > 9). But the 10th byte terminates the loop
    // BEFORE the guard is checked. So 9 cont + 1 terminal succeeds the guard!
    // Wait — let me re-read: the guard is checked AFTER pushing each byte. For the
    // 10th byte: push (len=10), check if terminal (yes → break before guard). The
    // guard is only reached if the byte is NOT terminal. So for exactly 9 bytes all
    // with continuation + 1 terminal byte, the guard is never triggered.
    // With `>= 9`: after byte 9 (len=9, continuation), check 9>=9 → true → bail.
    // This test checks that a 9-continuation + 1-terminal-byte sequence is rejected
    // only by the frame size guard (the value encoded is huge), NOT by "too long".
    #[tokio::test]
    async fn read_frame_9_continuation_bytes_fails_at_size_not_too_long() {
        // 9 bytes with continuation bit (0xFF) + 1 terminal byte with value 1.
        // This encodes a huge value (bits 0-62 all set + bit 63 from terminal).
        // The value exceeds 1MB → fails with "frame too large", not "too long".
        // With `>= 9` mutation: after the 9th byte (len=9), bail "too long" → CAUGHT.
        let mut buf = vec![0xFFu8; 9]; // 9 continuation bytes
        buf.push(0x01u8);              // terminal byte: value bit 63 = 1
        let err = read_frame(&mut std::io::Cursor::new(buf)).await.unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("too long"),
            "9 continuation bytes must NOT fail with 'too long' (guard is > 9, not >= 9); got: {msg}");
        assert!(msg.contains("too large") || msg.contains("overflow"),
            "9 cont bytes must fail at size guard or overflow, got: {msg}");
    }

    // Kills `> 9 → == 9` mutation.
    // With `== 9`: the guard fires only at exactly 10 bytes; for 11 continuation
    // bytes (len=10 after byte 10, check: 10 == 9? No → continue) it would NOT fire.
    // 11 continuation bytes with no terminal → the reader would block on the 12th byte.
    // Instead: use exactly 10 bytes to trigger the `> 9` guard.
    // Actually simpler: 10 continuation bytes (buf=[0xFF;10]) → after 10th byte:
    // len=10, not terminal, check 10 > 9? Yes → bail "too long" (original).
    // With `== 9`: check 10 == 9? No → continue → reader blocks waiting for byte 11.
    // Since Cursor has no byte 11, read_exact returns UnexpectedEof.
    // So with `== 9` mutation: error is "UnexpectedEof" not "too long".
    #[tokio::test]
    async fn read_frame_10_continuation_bytes_fails_with_too_long() {
        let buf = vec![0xFFu8; 10]; // 10 continuation bytes, no terminal
        let err = read_frame(&mut std::io::Cursor::new(buf)).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("too long"),
            "10 continuation bytes must fail with 'too long' (len > 9); got: {msg}");
    }

    // ── write_frames_batched round-trips ─────────────────────────────

    #[tokio::test]
    async fn write_frames_batched_empty_is_noop() {
        let mut out = Vec::new();
        write_frames_batched(&mut out, &[]).await.unwrap();
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn write_frames_batched_single_matches_write_frame() {
        // Single-frame fast path must be byte-identical to write_frame
        // so consumers parsing the stream don't see a different
        // wire shape depending on how many siblings happened to be
        // queued at flush time.
        let payload = vec![0x42u8; 137];
        let mut batched = Vec::new();
        write_frames_batched(&mut batched, &[payload.clone()]).await.unwrap();
        let mut single = Vec::new();
        write_frame(&mut single, &payload).await.unwrap();
        assert_eq!(batched, single);
    }

    #[tokio::test]
    async fn write_frames_batched_many_roundtrips() {
        // Drive multiple varied-size frames through the coalescer and
        // verify the reader-side `read_frame` recovers each one in
        // order. This is the property the writer task relies on.
        let payloads: Vec<Vec<u8>> = vec![
            b"hello".to_vec(),
            vec![0u8; 1400],
            (0..200u16).map(|i| i as u8).collect(),
            vec![],          // zero-length is a valid Traffic frame (keepalive)
            vec![0xFEu8; 65000],
        ];
        let mut buf = Vec::new();
        write_frames_batched(&mut buf, &payloads).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        for expected in &payloads {
            let got = read_frame(&mut cursor).await.unwrap();
            assert_eq!(&got, expected, "frame mismatch in batched stream");
        }
    }
}
