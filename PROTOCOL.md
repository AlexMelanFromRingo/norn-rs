# norn-rs wire protocol

This document is the normative reference for the `norn-rs` protocol as of
version **0.11.x** (the current flag-day wire format). Implementations claiming
compatibility MUST match this specification byte-for-byte.

### 0.11 changes vs 0.10 (flag-day — wire-incompatible with 0.10.x)

Makes hyperbolic greedy routing load-bearing (it was effectively a no-op before):

* **Coordinate format v5 (tree-position embedding).** COORD_ANNOUNCE's `theta` is
  now derived from the node's position in the tree (parent's θ + a depth-shrinking
  per-node offset) instead of a random key-hash, so descendants cluster under their
  ancestor and greedy has a real gradient. Same 117-byte layout as v4; only the
  version byte (→5) and θ semantics change. ρ stays depth-derived.
* **Coordinate dissemination at session setup.** SessionInit/SessionAck (§11) each
  carry the sender's 16-byte coord (advisory, *not* in the signed payload), so a
  source learns a multi-hop destination's coordinate and can stamp `dest_coord`
  (§8) → transit routes greedily. O(active sessions), no flooding.

### 0.10 changes vs 0.5 (flag-day — wire-incompatible with 0.9.x)

* **Coordinate format v4 (hyperboloid).** COORD_ANNOUNCE (§9) gains a leading
  format-version byte and carries an unsaturating radial coordinate (`rho`,
  linear in tree depth) on the hyperboloid model, replacing the old Poincaré
  `r = tanh(depth·0.5)` (which saturated to 1.0 in f64 at depth ≳ 38 and lost
  precision near the boundary). Distances are computed cancellation-free.
* **Transit greedy ("Path A").** TRAFFIC (§8) carries the destination's
  hyperbolic coordinate (1 presence byte + 16 bytes) so transit nodes can route
  greedily by hyperbolic distance instead of relying solely on cuckoo-filter
  reachability; cuckoo remains the local-minimum fallback. Privacy note: a relay
  learns the destination's coordinate *region*, not its identity — the opt-in
  Sphinx layer hides even that.
* **CAPABILITIES** (TYPE 0x11) — additive, signed, flooded capability announce
  (e.g. `CAP_ONION_SPHINX`); legacy nodes drop the unknown type (zero impact).
  Auto-negotiates the opt-in Sphinx onion format per path.
* **PATH_NEGATIVE** (TYPE 0x0F) — per-link negative-cache signal for fast
  eviction of routes toward departed targets.
* **SessionInit retransmission** (no wire change) — a lost SessionInit is
  re-sent on a maintenance tick with exponential backoff (1 s base, ×2, 30 s cap)
  until the handshake establishes.

### 0.5 changes vs 0.4

* **QUIC transport** alongside TCP. URI scheme `quic://host:port`.
  Encrypted byte pipe via rustls with self-signed certs; authentication
  still binds to Ed25519 via NRN1 (TLS cert is opportunistic).
* **mDNS / DNS-SD discovery** on `_norn._tcp.local`.
* **Reputation gossip** (TYPE 0x0D) — flooded signed trust reports;
  consensus trust biases routing alongside local trust.
* **HolePunch frame** (TYPE 0x0E) — minimal NAT-traversal primitive: A
  asks rendezvous R to relay endpoint info to B for simultaneous QUIC
  open. Operator-driven (callback hook).

### 0.4 changes vs 0.3

* ML-KEM-768 long-term keypair now rotates every ~24h with a 60s overlap
  window. No wire change — the rotation is purely a local operational
  hardening; mid-rotation Acks decap via the prior dk and the responder
  carries a `pq_shared_fallback` on `SessionInfo` until the first packet
  validates.
* Sybil-resistance threshold: an inbound peer's pub_key MUST satisfy
  `min_peer_difficulty_bits` (operator-set, 0 = off) before its TCP
  connection is accepted. The check is the leading-ones count of
  BLAKE2b(pub_key) — same metric already used in `addr[1]`.
* All `routing_tag` and `recipient_ed_pub` matches use constant-time
  comparison (`subtle::ConstantTimeEq`).
* Anti-amplification: pinned wire-size invariants (`SESSION_INIT_WIRE_BYTES`
  ≥ `SESSION_ACK_WIRE_BYTES`); static assert ensures responses cannot
  exceed requests in size.

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
| 0x0C | ONION_KEY_ANNOUNCE | Network-wide onion ephemeral pub flood (`§14`). |
| 0x0D | REPUTATION_REPORT  | Signed trust observation flooded mesh-wide (`§15`). |
| 0x0E | HOLE_PUNCH         | NAT-traversal endpoint-exchange relay (`§16`). |
| 0x0F | PATH_NEGATIVE      | Per-link negative-cache signal (fast dead-route eviction). |
| 0x11 | CAPABILITIES       | Signed, flooded capability announce (e.g. Sphinx onion, `§17`). |

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
[dest_coord_present: u8]      — 0 = absent, 1 = present (v0.10 transit greedy)
[dest_coord: 16]             — destination HypCoord (§9), ONLY when present
[watermark: varint]
[payload_len: varint]
[payload: payload_len bytes]
```

`dest_coord` (v0.10 "Path A") lets transit nodes route greedily by hyperbolic
distance when the cuckoo filter alone can't place the destination. It is the
destination's coordinate *region*, not its identity; the opt-in Sphinx onion
layer hides it.

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

v5 layout (117 bytes):

```
[version: u8 = 5]             — COORD_FORMAT_V5 (authenticated)
[coord: 16]                   — HypCoord (rho: f64 LE, theta: f64 LE) — hyperboloid
[tree_depth: u32 LE]
[onion_eph_pub: 32]           — sender's current onion ephemeral X25519 pub
[sig: 64]                     — sender signs (version || coord || tree_depth || onion_eph_pub)
```

`rho` is the radial hyperbolic distance (linear in tree depth, unsaturating).
`theta` (v5) is **tree-position-derived** — the parent's θ plus a depth-shrinking
per-node offset — so descendants cluster under their ancestor and greedy has a
gradient (v4 used a random key-hash θ with no tree relation). Distances are
computed cancellation-free on the hyperboloid model.

Receivers MUST:
* reject any `version` byte other than `COORD_FORMAT_V5` (5);
* verify the signature;
* verify `rho` matches the depth-derived value; treat `theta` as ADVISORY (it is
  tree-position-derived and cannot be recomputed without the announcer's parent
  context — a θ-spoof sinkhole is caught by trust-decay + active probing);
* reject coords containing NaN or Inf;
* bound the coord table to 16 384 entries (evict a non-peer entry when full);
* record `onion_eph_pub` against the announcing peer for later onion building.

## 10. ONION (0x0B)

This is the **legacy** onion format (the default build). Its per-layer cleartext
`aead_len` shrinks each hop — a hop-depth distinguisher. An **opt-in** Sphinx mix
format (constant-size cell, no depth leak) replaces it when built
`--features sphinx` and negotiated via CAPABILITIES (§17); see
`docs/onion-sphinx-design.md`. Both ride the same `0x0B` dispatch.

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

## 11. Session handshake (v3 — PQ hybrid)

Carried inside TRAFFIC packets with `pkt_type = 0x00`. Two messages, both
sign-then-encapsulate.

### 11.1 SessionInit (1369 bytes)

```
[magic: 1 = 0x74 't' (v3)]
[ed_pub: 32]                       — sender's identity
[signature: 64]
[x25519_pub: 32]                   — sender's current x25519 pub
[timestamp_ms: u64 LE]
[recipient_ed_pub: 32]             — intended responder's identity
[ml_kem_pub: 1184]                 — sender's ML-KEM-768 encapsulation key
[sender_coord: 16]                 — sender's HypCoord (v0.11; advisory, NOT signed)
```

`signature` covers everything except the sig field **and the trailing
sender_coord** (an advisory routing hint, not security-critical):
`magic || ed_pub || x25519_pub || timestamp_ms || recipient_ed_pub || ml_kem_pub`.
The recipient records `sender_coord` so it can stamp `dest_coord` on reverse
traffic (greedy routing, §0.11 changes).

Receivers MUST:
* match `recipient_ed_pub` against their own pub_key;
* reject if `|now - timestamp_ms| > 60 000 ms`;
* verify the Ed25519 signature;
* ML-KEM-encapsulate a fresh shared secret against `ml_kem_pub`; the
  resulting ciphertext goes into the Ack and the shared secret becomes
  `pq_shared` on the responder's side.

### 11.2 SessionAck (1273 bytes)

Same layout but with `magic = 0x62` ('b') and the `ml_kem_pub` field replaced
(the trailing advisory `sender_coord: 16` is still present):

```
[ml_kem_ct: 1088]                  — ciphertext from responder's encap
[sender_coord: 16]                 — responder's HypCoord (v0.11; advisory, NOT signed)
```

The anti-amplification invariant still holds: both messages grew by 16 B, so
`SESSION_ACK_WIRE_BYTES (1273) ≤ SESSION_INIT_WIRE_BYTES (1369)`.

Initiators MUST:
* only accept an Ack for which a corresponding `initiate()` is pending —
  unsolicited Acks are dropped;
* ML-KEM-decapsulate `ml_kem_ct` with their long-term decapsulation key;
  the resulting shared secret becomes `pq_shared` on the initiator's side.

Both sides now hold the same 32-byte `pq_shared`.

## 12. Session encryption

Every data-carrying packet is:

```
[sender_x25519_pub: 32][seq: u64 LE][ciphertext: payload + 16-byte tag]
```

Key derivation (PQ hybrid):

```
x25519_shared = DH(local_x25519_priv, sender_x25519_pub_from_packet)
aead_key      = HKDF-Extract+Expand-SHA256(
                    salt = pq_shared,        # 32 bytes, from §11
                    ikm  = x25519_shared,
                    info = "norn:session-key:v3",
                    L    = 32)
```

`aead_key` feeds ChaCha20-Poly1305 with `nonce = [seq: u64 LE | 0u32]` and
`AAD = sender_x25519_pub`.

Hybrid security guarantee: the session is confidential against any adversary
unable to break BOTH X25519 (classical DH) AND ML-KEM-768 (post-quantum
KEM). A future quantum break of X25519 alone does not compromise the
session.

Receivers maintain a 64-slot sliding replay window per session, anchored at
the highest `seq` accepted.

X25519 keypairs are rotated every 100 sends (forward secrecy at the
classical layer). The ML-KEM keypair is long-term per process; rotating it
on a daily cadence (with a graceful overlap window) is a recommended
operational hardening.

## 14. ONION_KEY_ANNOUNCE (0x0C)

Network-wide flood that advertises a node's current onion ephemeral X25519
public key. Without this, an onion sender can only build a forward-secret
onion to a *direct* neighbour (the only nodes whose ephemeral pub it learns
via CoordAnnounce). Multi-hop FS onions require this frame.

Wire layout (145 bytes):

```
[origin: 32]              — announcing node's identity
[seq: u64 LE]             — strictly monotonic per origin
[valid_from_ms: u64 LE]   — sender wall-clock
[onion_eph_pub: 32]       — current ephemeral pub
[sig: 64]                 — Ed25519 sig over (origin||seq||valid_from_ms||onion_eph_pub)
```

Forwarding rules:
* Reject if `origin == own pub_key` (anti-spoof/self-loop).
* Verify the Ed25519 signature against `origin`.
* Drop if `now - valid_from_ms` exceeds 24 h (stale).
* Drop if `valid_from_ms` is more than 60 s in the future (skew abuse).
* Keep per-origin only the highest `seq` seen.
* On first-sight of a strictly newer `(origin, seq)`, forward to every
  peer except the sender.

## 15. REPUTATION_REPORT (0x0D)

Per-peer signed trust observation flooded through the mesh. Receivers
aggregate per `observed` into a "consensus trust" that biases routing.

Wire layout (180 bytes):

```
[observer: 32]
[observed: 32]
[score_q16: u16 LE]      — score in [0..1], quantised to u16
[seq: u64 LE]            — monotonic per (observer, observed)
[valid_from_ms: u64 LE]
[sig: 64]                — Ed25519 over the prefix
```

Forwarding rules:
* Reject if `observer == observed` (no self-praise).
* Reject if `observer == own pub_key` (no spoofing as us).
* Reject if signature doesn't verify against `observer`.
* Reject if `valid_from_ms` outside ±60 s skew window or older than 1 h.
* Forward on first-sight of strictly newer (observer, observed, seq).

Receivers de-quantise `score_q16` back to a float in `[TRUST_MIN..TRUST_MAX]`
and compute `consensus_trust(observed) = mean(score over observers)`,
which is averaged with local trust for routing decisions.

## 16. HOLE_PUNCH (0x0E)

NAT-traversal coordination frame. A peer A behind NAT sends a HolePunch
addressed to a target B via a rendezvous R that is connected to both.
R relays the frame to B; both A and B then simultaneously open outbound
QUIC connections to each other's reported endpoints.

Wire layout (≥ 137 bytes):

```
[initiator: 32]
[target: 32]
[valid_from_ms: u64 LE]
[endpoint_len: u8]
[endpoint: endpoint_len]    — A's externally-observed transport endpoint
[sig: 64]                   — Ed25519 over the prefix
```

Forwarding rules:
* If `target == own pub_key` → fire the optional `on_hole_punch` callback.
* Else if we have a route to `target` → forward the same frame onward.
* Else → drop.
* In all cases, verify signature and ±60 s freshness first; reject invalid.

The frame is signed by the initiator so the rendezvous cannot forge an
endpoint.

## 13. Discovery

Optional UDP multicast on `ff02::1:9` (per the linkway):

```
[magic: 4 = "NORN"][pub_key: 32][tcp_port: u16 LE]
```

Beacons are unauthenticated — they are only a hint. The receiver dials and
performs the full TCP handshake before treating the peer as authentic.

## 17. CAPABILITIES (0x11)

Additive, signed, mesh-flooded announce of a node's optional capabilities,
modelled on ONION_KEY_ANNOUNCE (§14). A legacy node that doesn't know the type
drops it (zero impact); no existing signed announce changed. Used to
auto-negotiate the **opt-in** Sphinx onion format per path: a sender builds a
Sphinx onion only when every hop (relays + destination) has gossiped the
capability and the path fits `MAX_HOPS`, else it falls back to the legacy onion
(§10).

```
[origin: 32]                  — capability owner's ed25519 pub
[caps: u32 LE]                — capability bitmask (CAP_ONION_SPHINX = 1<<0)
[seq: u64 LE]                 — monotonic dedup counter
[valid_from_ms: u64 LE]      — freshness timestamp
[sig: 64]                     — origin signs (origin || caps || seq || valid_from_ms)
```

Receivers verify the signature, dedup by `(origin, seq)`, and record
`origin → caps`. The frame exists only in builds compiled `--features sphinx`; a
default build neither emits nor requires it.
