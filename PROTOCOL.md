# norn-rs wire protocol

This document is the normative reference for the `norn-rs` protocol as of
version **0.3.0** (with onion v3 extensions). Implementations claiming
compatibility MUST match this specification byte-for-byte.

Notation:
* `u8`, `u16`, `u32`, `u64` are little-endian.
* `[N]` is N bytes verbatim.
* `varint` is an unsigned LEB128 (uvarint) of at most 9 encoded bytes
  (representing values up to `u64::MAX`).
* All multi-byte fixed-size scalars are little-endian unless noted.

## 1. Identity and addressing

Every node has an Ed25519 long-term keypair. The IPv6 address is derived
deterministically from the public key:

1. `hash = BLAKE2b-512(pub_key)`
2. `ones = leading 1-bits of hash`
3. `addr[0] = 0x02`, `addr[1] = ones` (capped at 255)
4. `addr[2..16] = 112 bits of hash, starting at bit (ones + 1)`

The address lies in `200::/8` (and the equivalent `300::/8` is reserved for
subnet announcements). The two together form a `200::/7` overlay range.

The **routing tag** is a 16-byte hash used in place of the full key on the
wire for privacy:

```
routing_tag = BLAKE2b-128("norn:route" || pub_key)
```

## 2. Transport framing

Underlying transport is TCP. Every frame is:

```
[length: varint][payload: length bytes]
```

Constraints:
* The length varint MUST be ≤ 9 encoded bytes.
* `length` MUST be ≤ `1 048 576` (1 MiB). Receivers MUST close the connection
  on violation.

### 2.1 Authenticated handshake

The very first frames on a TCP connection are the authenticated handshake.
Each side sends and reads the following bytes (not length-prefixed,
exchanged in parallel):

```
Hello (68 bytes):
  [magic: 4 = "NRN1"]
  [our_pub: 32]
  [our_nonce: 32 — fresh random]
```

After receiving the peer Hello:

```
Sig (64 bytes):
  ED25519_sign(our_priv,
      "norn:handshake:v1" || our_nonce || their_nonce || our_pub || their_pub)
```

Each side MUST:
* reject a Hello whose magic is not `NRN1`;
* reject a Hello whose `our_pub` equals our own pub (self-loop);
* reject a Hello whose pub fails Ed25519 point validation;
* reject if the peer Sig does not verify;
* abort the entire handshake if it does not complete within **10 seconds**.

Listeners MUST enforce an in-process cap of **256** simultaneous
unauthenticated handshakes; excess incoming TCP connections MUST be dropped.

## 3. Framed messages

After the handshake, every length-prefixed frame is a single message whose
first byte selects the type:

| Byte | Name             | Description                                |
|-----:|------------------|--------------------------------------------|
| 0x00 | DUMMY            | Cover traffic; discarded by receiver.      |
| 0x01 | KEEP_ALIVE       | Updates peer last-rx timestamp; no body.   |
| 0x02 | SIG_REQ          | RTT ping (`§4.1`).                          |
| 0x03 | SIG_RES          | RTT pong (`§4.2`).                          |
| 0x04 | ANNOUNCE         | Spanning-tree announce (`§5`).             |
| 0x05 | CUCKOO_FILTER    | Routing-set gossip (`§6`).                 |
| 0x06 | PATH_LOOKUP      | Request a path to a target (`§7`).         |
| 0x07 | PATH_NOTIFY      | Reply to a successful lookup (`§7`).       |
| 0x08 | PATH_BROKEN      | Report a broken path (`§7`).               |
| 0x09 | TRAFFIC          | Encrypted user payload (`§8`).             |
| 0x0A | COORD_ANNOUNCE   | Hyperbolic coordinate broadcast (`§9`).    |
| 0x0B | ONION            | Onion-wrapped Traffic packet (`§10`).      |

## 4. Sig request / response

### 4.1 SIG_REQ (0x02)

```
[tree_id: u8]
[seq: varint]
[timestamp_ms: varint]
[requester_pub_key: 32]
```

### 4.2 SIG_RES (0x03)

```
[tree_id: u8]
[seq: varint]
[timestamp_ms: varint]
[signature: 64]
[responder_pub_key: 32]
```

The responder signs `tree_id || seq || timestamp_ms || requester_pub_key`.
Receivers MUST verify the signature against `responder_pub_key` before using
any field. The seq MUST match the most recent outstanding request.

## 5. ANNOUNCE (0x04)

```
[tree_id: u8]
[root: 32]                    — claimed root pub_key
[root_seq: varint]
[path_cost: varint]           — cumulative cost from root to sender
[sender: 32]
[signature: 64]               — sender signs sign_bytes (below)
[depth: varint, optional]     — sender's hop depth, present iff bytes remain
```

`sign_bytes = tree_id || root || varint(root_seq) || varint(path_cost) || sender || varint(depth)`

Three trees (`K = 3`) named **Urd**, **Verdandi**, **Skuld** (`TREE_SEEDS`
in `router.rs`) operate in parallel for redundancy.

## 6. CUCKOO_FILTER (0x05)

```
[tree_id: u8]
[generation: varint]
[data: 4096]                  — 512 buckets × 4 slots × 2 bytes
```

A receiver that sees a `generation` strictly greater than the one previously
seen from this peer MUST replace the stored filter rather than merging it,
so that stale entries are evicted across regenerations (~every 5 minutes).

## 7. PATH messages

```
PathLookup (0x06):
  [target: 32][source: 32][id: varint][path: encoded_path]

PathNotify (0x07): same layout
PathBroken (0x08): [target: 32][source: 32][id: varint]
```

`encoded_path = (varint(hop + 1))* 0x00`

Path length MUST NOT exceed 1024 hops.

## 8. TRAFFIC (0x09)

```
[path: encoded_path]
[from: 32]                    — immediate sender's pub_key
[enc_header: 128]             — see §8.1
[routing_tag: 16]             — BLAKE2b-128("norn:route" || dest_pub_key)
[pkt_type: u8]                — 0x00 control, 0x01 data
[watermark: varint]
[payload_len: varint]
[payload: payload_len bytes]
```

### 8.1 enc_header

128 bytes:

```
[epk: 32]                                      — ephemeral X25519 pub key
[AEAD_n0(source_ed_pub, AAD=epk): 48]         — encrypted source identity
[AEAD_n1(dest_ed_pub,   AAD=epk): 48]         — encrypted dest identity (self-confirm)
```

`AEAD_nN` uses `ChaCha20-Poly1305` with nonce `[N: u64 LE | 0u32]` and key
`DH(epk_priv, dest_x25519_pub)`. Only the destination can derive this key.

### 8.2 Forwarding rules

* If `routing_tag == routing_tag(our_pub)`, the packet is for us:
  * `pkt_type == 0x00`: unpad and dispatch as a session control message
    (SessionInit / SessionAck v2). The session magic MUST match (see §11).
  * `pkt_type == 0x01`: session-decrypt the payload, unpad, and deliver to
    the application.
* Otherwise, forward:
  * Drop if `path.len() >= 32` (TTL).
  * Drop if our pub_key prefix already appears in `path` (loop).
  * Drop if `lookup_by_tag(routing_tag)` is `None` or returns the same peer
    that just sent us this packet (2-cycle).
  * Otherwise, append our 8-byte pub_key prefix to `path` and re-encode.

## 9. COORD_ANNOUNCE (0x0A)

v2 layout (116 bytes):

```
[coord: 16]                   — (r: f64 LE, theta: f64 LE)
[tree_depth: u32 LE]
[onion_eph_pub: 32]           — sender's current onion ephemeral X25519 pub
[sig: 64]                     — sender signs (coord || tree_depth || onion_eph_pub)
```

Receivers MUST:
* verify the signature;
* reject coords containing NaN or Inf;
* bound the coord table to 16 384 entries (evict a non-peer entry when full);
* record `onion_eph_pub` against the announcing peer for later onion building.

## 10. ONION (0x0B)

```
[routing_tag: 16]             — current layer's intended recipient
[epk: 32]                     — per-layer ephemeral X25519 pub
[aead_len: varint]
[aead_payload: aead_len]
[padding…]                    — zeros, to a fixed total wire size
```

**Fixed cell size**: every onion frame MUST be padded to exactly
`ONION_CELL_SIZE = 1280` bytes (including the leading 0x0B type byte). This
removes the per-hop size signal that lets a global passive observer
correlate packets across consecutive links. `aead_len` tells the receiver
where the AEAD payload ends; trailing bytes are zero padding and ignored.

**Forward-secret relay key**: `aead_payload` is encrypted to the relay's
*current advertised onion ephemeral pub* (from §9 CoordAnnounce). Relays
rotate this keypair every hour and zeroize the prior key after one further
rotation period. Past onion traffic that transited a relay becomes
undecryptable once two rotations have elapsed (forward secrecy).

Relays MUST attempt decryption with: (1) the current onion ephemeral priv,
(2) the previous ephemeral priv (one-rotation graceful window), (3) the
identity-derived X25519 priv as a fallback for senders that have not yet
heard the relay's CoordAnnounce. The fallback path provides confidentiality
but NOT forward secrecy for those layers.

**Replay cache**: each relay maintains an LRU of 4 096
BLAKE2b("norn:onion-replay" || epk || aead_payload[..16]) digests and
silently drops any onion cell whose digest has been seen recently. This
prevents tagging-by-replay attacks.

`aead_payload` decrypts (ChaCha20-Poly1305, nonce all-zero, AAD = `epk`,
key = `DH(epk_priv, relay_eph_pub)` from sender side, `DH(relay_eph_priv, epk)`
from relay side) to one of:

* `[0x01][inner_len: varint][inner: inner_len]` — relay layer: `inner` is the
  next OnionPacket (without the leading TYPE_ONION byte). Forward toward
  the inner `routing_tag`.
* `[0x00][traffic_len: varint][traffic: traffic_len]` — exit layer: `traffic`
  is a complete TRAFFIC frame (including the leading 0x09 byte). Dispatch
  locally.

Onion-forwarding is subject to the same in-flight cap, 2-cycle rejection,
and 0–49 ms jitter as TRAFFIC forwarding.

## 11. Session handshake (v2)

Carried inside TRAFFIC packets with `pkt_type = 0x00`. Two messages:

### 11.1 SessionInit

```
[magic: 1 = 0x73 's']
[ed_pub: 32]                  — sender's identity
[signature: 64]
[x25519_pub: 32]              — sender's current x25519 pub
[timestamp_ms: u64 LE]
[recipient_ed_pub: 32]        — intended responder's identity
```

`signature` covers:
`magic || ed_pub || x25519_pub || timestamp_ms || recipient_ed_pub`.

Receivers MUST:
* match `recipient_ed_pub` against their own pub_key;
* reject if `|now - timestamp_ms| > 60 000 ms`;
* verify the signature.

### 11.2 SessionAck

Identical layout with `magic = 0x61` ('a'). Receivers MUST only accept an
Ack for which a corresponding `initiate()` is pending — unsolicited Acks
are dropped.

## 12. Session encryption

Every data-carrying packet is:

```
[sender_x25519_pub: 32][seq: u64 LE][ciphertext: payload + 16-byte tag]
```

Key = `DH(local_x25519_priv, remote_x25519_pub)`.
Nonce = `[seq: u64 LE | 0u32]`. AAD = `sender_x25519_pub`.

Receivers maintain a 64-slot sliding replay window per session, anchored at
the highest `seq` accepted.

X25519 keypairs are rotated every 100 sends. The previous key is dropped
immediately (and zeroized by `x25519-dalek`).

## 13. Discovery

Optional UDP multicast on `ff02::1:9` (per the linkway):

```
[magic: 4 = "NORN"][pub_key: 32][tcp_port: u16 LE]
```

Beacons are unauthenticated — they are only a hint. The receiver dials and
performs the full TCP handshake before treating the peer as authentic.
