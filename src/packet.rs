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

/// Encode a uvarint into a byte buffer.
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
        pos += consumed;
        if val == 0 {
            break;
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
        if data.len() < 1 {
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
        if data.len() < pos + payload_len as usize {
            bail!("Traffic payload truncated: need {}, got {}", payload_len, data.len() - pos);
        }
        let payload = data[pos..pos + payload_len as usize].to_vec();
        Ok(Traffic { path, from, enc_header, routing_tag, pkt_type, watermark, payload })
    }
}

/// Broadcast by each node: its hyperbolic coordinate + signed by its key.
#[derive(Clone, Debug)]
pub struct CoordAnnounce {
    pub coord: [u8; 16],
    pub tree_depth: u32,
    pub sig: [u8; 64],
}

impl CoordAnnounce {
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.coord);
        buf.extend_from_slice(&self.tree_depth.to_le_bytes());
        buf.extend_from_slice(&self.sig);
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 16 + 4 + 64 {
            bail!("CoordAnnounce too short: got {}", data.len());
        }
        let mut coord = [0u8; 16];
        coord.copy_from_slice(&data[0..16]);
        let tree_depth = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[20..84]);
        Ok(CoordAnnounce { coord, tree_depth, sig })
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
}
