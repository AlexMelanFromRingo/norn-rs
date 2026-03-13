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
    // Read uvarint length byte by byte
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

/// Encode a path as zero-terminated uvarints (sequence of hop indices).
pub fn encode_path(path: &[u64]) -> Vec<u8> {
    let mut buf = Vec::new();
    for &hop in path {
        encode_uvarint(hop + 1, &mut buf); // shift by 1 so 0 is terminator
    }
    buf.push(0); // terminator
    buf
}

/// Decode a zero-terminated uvarint path.
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
        path.push(val - 1); // undo shift
    }
    Ok((path, pos))
}

#[derive(Clone, Debug)]
pub struct SigReq {
    pub tree_id: u8,
    pub seq: u64,
    pub timestamp_ms: u64,
    /// The sender's ed25519 public key
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
        // data[0] = SIG_REQ already stripped by caller; data starts at tree_id
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
    /// ed25519 signature of (tree_id || seq || timestamp_ms || req_pub_key)
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

/// Spanning-tree announce, one per tree.
#[derive(Clone, Debug)]
pub struct Announce {
    pub tree_id: u8,
    pub root: [u8; 32],
    pub root_seq: u64,
    /// Cumulative path cost (effective_ms) from root to sender
    pub path_cost: u64,
    /// Sender's ed25519 public key
    pub sender: [u8; 32],
    /// ed25519 signature over (tree_id || root || root_seq || path_cost || sender)
    pub signature: [u8; 64],
}

impl Announce {
    pub fn sign_bytes(&self) -> Vec<u8> {
        let mut buf = vec![self.tree_id];
        buf.extend_from_slice(&self.root);
        encode_uvarint(self.root_seq, &mut buf);
        encode_uvarint(self.path_cost, &mut buf);
        buf.extend_from_slice(&self.sender);
        buf
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![ANNOUNCE, self.tree_id];
        buf.extend_from_slice(&self.root);
        encode_uvarint(self.root_seq, &mut buf);
        encode_uvarint(self.path_cost, &mut buf);
        buf.extend_from_slice(&self.sender);
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        // data[0] = tree_id (ANNOUNCE byte already stripped)
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
        Ok(Announce { tree_id, root, root_seq, path_cost, sender, signature })
    }
}

/// Cuckoo filter gossip message, one per tree.
#[derive(Clone, Debug)]
pub struct CuckooMsg {
    pub tree_id: u8,
    pub data: [u8; 2048],
}

impl CuckooMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![CUCKOO_FILTER, self.tree_id];
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 1 + 2048 {
            bail!("CuckooMsg too short: got {}", data.len());
        }
        let tree_id = data[0];
        let mut cdata = [0u8; 2048];
        cdata.copy_from_slice(&data[1..1 + 2048]);
        Ok(CuckooMsg { tree_id, data: cdata })
    }
}

#[derive(Clone, Debug)]
pub struct PathLookup {
    /// Target public key (full 32 bytes)
    pub target: [u8; 32],
    /// Source public key
    pub source: [u8; 32],
    /// Lookup ID (random, for dedup)
    pub id: u64,
    /// Path back to source (encoded)
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
        let (path, path_len) = decode_path(&data[pos..])?;
        let _ = path_len;
        Ok(PathLookup { target, source, id, path })
    }
}

#[derive(Clone, Debug)]
pub struct PathNotify {
    pub target: [u8; 32],
    pub source: [u8; 32],
    pub id: u64,
    /// Path from source to target
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
        let (path, path_len) = decode_path(&data[pos..])?;
        let _ = path_len;
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
        let mut pos = 64;
        let (id, n) = decode_uvarint(&data[pos..])?;
        let _ = n;
        Ok(PathBroken { target, source, id })
    }
}

#[derive(Clone, Debug)]
pub struct Traffic {
    /// Source routing path (hop indices)
    pub path: Vec<u64>,
    /// Sender's public key
    pub from: [u8; 32],
    /// Ultimate source (for session key lookup)
    pub source: [u8; 32],
    /// Ultimate destination
    pub dest: [u8; 32],
    /// Sequence watermark for replay protection
    pub watermark: u64,
    /// Encrypted payload
    pub payload: Vec<u8>,
}

impl Traffic {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![TRAFFIC];
        buf.extend_from_slice(&encode_path(&self.path));
        buf.extend_from_slice(&self.from);
        buf.extend_from_slice(&self.source);
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
        if data.len() < pos + 32 + 32 + 32 {
            bail!("Traffic too short");
        }
        let mut from = [0u8; 32];
        from.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let mut source = [0u8; 32];
        source.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
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
        Ok(Traffic { path, from, source, dest, watermark, payload })
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
        };
        let enc = ann.encode();
        // Strip the ANNOUNCE byte
        let dec = Announce::decode(&enc[1..]).unwrap();
        assert_eq!(dec.tree_id, 1);
        assert_eq!(dec.root, [0xABu8; 32]);
        assert_eq!(dec.root_seq, 42);
        assert_eq!(dec.path_cost, 1000);
    }
}
