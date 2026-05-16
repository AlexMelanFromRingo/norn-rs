# Security Policy

## Threat model

`norn-rs` is an overlay mesh that aims for cjdns / Yggdrasil-level properties
plus stronger source-, destination-, and traffic-analysis resistance through
onion routing and traffic padding. This document spells out what the network
is and is not designed to resist.

### Adversary capabilities considered

| Capability                                                | In scope | Notes |
|-----------------------------------------------------------|:--------:|-------|
| Passive eavesdropping on the underlay (any IP transport)  |    ✓     | All packets are end-to-end encrypted with ChaCha20-Poly1305. |
| Active man-in-the-middle on the underlay (TCP)            |    ✓     | TCP handshake binds the ed25519 identity to the session via challenge-response signatures (see `transport.rs::handshake`). |
| Malicious peer (knows their own keys, can send any frame) |    ✓     | Forwarding is loop-bounded, rate-limited, and per-packet AEAD-authenticated; cuckoo poisoning is contained but **not** fully prevented (see below). |
| Multiple cooperating malicious peers                      |    ◐     | Path-selection randomness limits passive correlation; full Sybil resistance is **not** claimed. |
| Compromise of one onion relay                             |    ✓     | Relay sees neither origin nor destination, only its immediate neighbours. |
| Compromise of *all* relays on a circuit                   |    ✗     | This deanonymises the flow — a property shared with Tor. |
| Compromise of node’s long-term ed25519 private key        |    ◐     | Address derivation makes the key the identity; loss of the key = loss of the identity *going forward*. Past traffic is largely forward-secret: session-layer x25519 rotates every 100 sends, and onion-layer keys are now a rotating ephemeral keypair separate from the long-term identity (rotated hourly with a one-rotation graceful window). The remaining gap is the *fallback* onion path used when the sender hasn't yet learned the recipient's advertised ephemeral pub. |
| Global passive adversary observing all link-level traffic |    ◐     | Padding (256-byte blocks), forwarding jitter, and cover traffic make timing/size correlation harder but not infeasible. |
| Quantum adversary                                         |    ◐     | Sessions use a PQ-hybrid X25519 + ML-KEM-768 key (HKDF-Extract). Confidential as long as either primitive holds. Authentication (Ed25519 signatures on announces and handshakes) is still classical — a CRQC would break identity forgery for newly-issued messages. |

### Properties claimed

* **Confidentiality** of payload between source and destination (AEAD with X25519-derived keys).
* **Authenticity** of every encrypted packet, every signed control message, every announce, and every node-to-node TCP handshake.
* **Replay protection**:
  * Per-session 64-slot sliding window on Traffic packets.
  * SessionInit / SessionAck carry timestamps; reject if outside a ±60 s window.
  * Per-connection challenge-response nonce binds handshake signatures to *this* TCP socket, preventing cross-connection replay.
* **Source and destination hiding** at intermediate hops via `enc_header` (encrypted with ephemeral X25519) and `routing_tag` (BLAKE2b digest of destination key).
* **Forward secrecy at the session layer**: x25519 keypairs are rotated every 100 sends; old keypairs are zeroized on drop.
* **DoS resistance**:
  * Frame size capped at 1 MiB.
  * Uvarint length prefix capped at 9 bytes.
  * Path length capped at 1 024 hops; forwarding TTL capped at 32 hops.
  * In-flight forwarding tasks capped at 4 096.
  * Pending TCP handshakes capped at 256, each with a 10 s timeout.
  * Pending PathLookup dedup set capped at 10 000 entries; coord table at 16 384.
  * Idle sessions expire after 5 min.

### Resolved in this release (v0.3)

All previously-listed "Known weaknesses" are closed:

* **Onion-layer forward secrecy** (CLOSED). Onion peel now uses a rotating
  per-node ephemeral X25519 keypair distinct from the Ed25519 identity.
  Rotates every hour; the prior key is held one further rotation period for
  in-flight onions, then zeroized. Past onion traffic becomes undecryptable
  two rotations later.
* **Network-wide ephemeral-pub propagation** (CLOSED). New
  `OnionKeyAnnounce` (0x0C) frame is signed by the origin and flooded
  through the mesh, so senders learn the current ephemeral pub of *any*
  node (not just direct neighbours). The identity-derived key remains a
  peel fallback purely for warm-start scenarios.
* **Variable-size onion cells** (CLOSED). Every onion frame is padded to a
  constant `ONION_CELL_SIZE = 1280` bytes regardless of remaining depth.
* **Onion replay** (CLOSED). Each relay keeps a 4 096-entry LRU of recent
  cell digests and silently drops duplicates.
* **Cuckoo gossip poisoning** (CLOSED). Per-peer trust scoring + an
  *active prober* that picks a (peer P, identity Q) pair where P claims to
  reach Q, sends a PathLookup(Q) only via P, and decays P's trust on
  timeout / boosts on success. Routing lookups rank by trust-adjusted
  cost — a lying peer falls to the bottom of the list within minutes.
* **Hyperbolic coordinate spoofing** (CLOSED). CoordAnnounce coords MUST
  match `from_tree_depth(claimed_depth, sender_pub)` exactly; mismatches
  are rejected and trigger a trust decay. The claimed `tree_depth` is
  cross-checked against the depth on file from the sender's most recent
  Announce (±2 tolerance for transient races).
* **Post-quantum hybrid** (CLOSED). Session handshake v3 carries an
  ML-KEM-768 encapsulation key in the Init and a ciphertext in the Ack;
  both sides derive a 32-byte `pq_shared` that mixes into every per-packet
  AEAD key via HKDF-Extract+Expand-SHA256. The session is confidential as
  long as EITHER X25519 OR ML-KEM-768 holds.

### Resolved since v0.3

* **Long-term ML-KEM keypair rotation** (CLOSED). The ML-KEM-768 keypair
  rotates every ~24h via `PqKeys::rotate_if_due`. The previous dk is
  retained for a 60-second overlap window so in-flight Acks targeted at
  the just-rotated pub still decap (`SessionInfo::pq_shared_fallback`),
  then is zeroized.
* **Sybil resistance via built-in PoW** (CLOSED). Inbound peers must
  satisfy `min_peer_difficulty_bits` — the leading-ones count of
  BLAKE2b(pub_key) — before they're accepted at the transport layer.
  Each bit doubles the cost of generating an admissible identity. Same
  mechanism used by Yggdrasil/cjdns; off by default (0 bits) to avoid
  locking out existing keys on upgrade, opt-in via config.
* **Constant-time comparisons** (CLOSED). `subtle::ConstantTimeEq` for
  routing_tag and recipient_ed_pub matches, removing the timing side
  channel that a short-circuiting `==` would otherwise present.

### Remaining known weaknesses

1. **Active probe-based Sybil hardening** — the PoW threshold raises the
   per-identity cost but does not detect cooperating malicious peers
   with valid (just-expensive) keys. Combined with `trust` decay this is
   acceptable for v0.4; an explicit reputation gossip layer remains
   future work.
2. **Side-channel hardening of underlying crypto crates** — RustCrypto
   primitives document constant-time properties, but the host's CPU /
   compiler pipeline can still leak via cache timing. No explicit
   wbox/blinding countermeasures at the session layer.
3. **Formal verification** — the PQ-hybrid HKDF construction follows
   standard practice but has not been mechanically verified against a
   security game (ProVerif / Tamarin).

## Reporting a vulnerability

Send security reports to **security@norn-mesh.invalid** (placeholder — replace
before publishing).

Please include:
* a description of the issue and its impact;
* steps to reproduce, ideally a PoC against a recent commit hash;
* whether you intend to disclose publicly and on what timeline.

We aim to:
* acknowledge within **72 hours**;
* provide a remediation plan within **14 days**;
* ship a patched release within **90 days** of acknowledgement.

We do not currently run a bug bounty.

### What we will not consider

* Theoretical attacks against ed25519, X25519, ChaCha20-Poly1305, BLAKE2b, or
  Blake2s used as specified in their reference papers.
* DoS against a single victim that requires the attacker to already be a
  configured peer of that victim *and* to send at line rate (rate limiting
  per-peer is delegated to operators).
* Anything explicitly listed under *Known weaknesses* unless you have a
  fundamentally new attack vector.

## Supported versions

| Version | Status        |
|---------|---------------|
| 0.3.x   | active        |
| 0.2.x   | security only |
| < 0.2   | unsupported   |

## Crypto agility

All on-the-wire crypto primitives are fixed for a given protocol version.
The TCP handshake magic (`NRN1`) and the SessionInit/Ack v2 magics encode
the version, so cross-version peers fail loudly at parse time rather than
silently producing incompatible state.
