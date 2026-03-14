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

/// Traffic packet.
///
/// Source privacy: the sender's identity (`source`) is encrypted with the
/// destination's X25519 public key (derived from its ed25519 key).
/// Intermediate nodes forward `enc_source` opaquely — they cannot read who
/// sent the packet, only where it is going (`dest`).
///
/// Wire: path | from(32) | enc_source(80) | dest(32) | watermark | payload
///
/// `enc_source` layout: [epk: 32][ChaCha20Poly1305(source_ed_pub)(48)]
///   epk  = ephemeral X25519 pub key generated by sender per-packet
///   key  = DH(epk_priv, dest_x25519_pub)
///   aad  = epk (authenticated)
///
/// Intermediate nodes: leave enc_source untouched, route on `dest`.
/// Destination: decrypt enc_source → source ed25519 pub key.
#[derive(Clone, Debug)]
pub struct Traffic {
    /// Source routing path (hop indices)
    pub path: Vec<u64>,
    /// Immediate sender's public key (direct peer, for keepalive tracking)
    pub from: [u8; 32],
    /// Encrypted source identity — only destination can decrypt.
    /// 80 bytes: epk(32) + AEAD(source_ed_pub)(32+16)
    pub enc_source: [u8; 80],
    /// Ultimate destination public key (needed for routing, visible to all)
    pub dest: [u8; 32],
    /// Sequence watermark for replay protection
    pub watermark: u64,
    /// Encrypted application payload
    pub payload: Vec<u8>,
}

impl Traffic {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![TRAFFIC];
        buf.extend_from_slice(&encode_path(&self.path));
        buf.extend_from_slice(&self.from);
        buf.extend_from_slice(&self.enc_source);
        buf.extend_from_slice(&self.dest);
        encode_uvarint(self.watermark, &mut buf);
        encode_uvarint(self.payload.len() as u64, &mut buf);
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let (path, path_len) = decode_path(data)?;
        pos += path_len;
        // from(32) + enc_source(80) + dest(32) = 144 bytes minimum
        if data.len() < pos + 144 {
            bail!("Traffic too short");
        }
        let mut from = [0u8; 32];
        from.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let enc_source: [u8; 80] = data[pos..pos + 80].try_into()
            .map_err(|_| anyhow::anyhow!("Traffic enc_source slice error"))?;
        pos += 80;
        let mut dest = [0u8; 32];
        dest.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let (watermark, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        let (payload_len, n) = decode_uvarint(&data[pos..])?;
        pos += n;
        if data.len() < pos + payload_len as usize {
            bail!("Traffic payload truncated");
        }
        let payload = data[pos..pos + payload_len as usize].to_vec();
        Ok(Traffic { path, from, enc_source, dest, watermark, payload })
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
