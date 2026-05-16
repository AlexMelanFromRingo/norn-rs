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
| Quantum adversary                                         |    ✗     | All asymmetric primitives are classical (ed25519, x25519). |

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

### Resolved in this release (v0.3 onion v3)

These items were on the previous "Known weaknesses" list and are now closed:

* **Onion-layer forward secrecy** (CLOSED — partial). Onion peel now uses a
  rotating per-node ephemeral X25519 keypair, distinct from the long-term
  Ed25519 identity. The keypair rotates every hour; the prior key is held
  for one further rotation period for in-flight onions, then zeroized. Past
  onion traffic becomes undecryptable two rotations later.
  *Remaining gap:* the identity-derived key is kept as a peel fallback for
  cells from senders that haven't yet learned the relay's current ephemeral.
  Closing this fully requires network-wide propagation of onion ephemeral
  pubs (current propagation is one-hop via CoordAnnounce).
* **Variable-size onion cells** (CLOSED). Every onion frame is padded to a
  constant `ONION_CELL_SIZE = 1280` bytes regardless of remaining depth.
  Removes the per-hop size signal that previously let a global observer
  count circuit length.
* **Onion replay** (CLOSED). Each relay keeps a 4 096-entry LRU of recent
  cell digests and silently drops duplicates. Prevents tagging-by-replay.
* **Cuckoo gossip poisoning** (PARTIAL). Per-peer trust scores bias routing
  lookups: peers that miss keepalives or otherwise misbehave are
  de-prioritised. An auto-prober that issues PathLookups to verify advertised
  routes remains future work.

### Known weaknesses (open issues)

These are *deliberately* unresolved in the current release; PRs welcome.

1. **Network-wide ephemeral-pub propagation** — CoordAnnounce only reaches
   direct peers, so an onion sender that wants to use a non-neighbour as
   destination falls back to the identity-derived key. This degrades FS for
   that hop.
   *Fix:* a signed `OnionKeyAnnounce` flooded like Announce, or piggyback
   the announce on PathNotify.
2. **Hyperbolic coordinate spoofing** — peers self-report their coordinates.
   A malicious peer can claim a coordinate close to any target, biasing
   greedy routing.
   *Mitigation in current code:* coord signatures are verified; non-finite
   coords are rejected; coord-table size is bounded.
3. **Active route validation for cuckoo poisoning** — the trust framework
   exists but trust currently moves only on liveness probes (SigReq/Res).
   A peer that responds to pings but lies about route claims escapes
   detection.
   *Fix:* periodic PathLookup probes against a random claimed tag; decay
   trust on missing PathNotify.
4. **No post-quantum hybrid** — when this becomes practical (e.g. X-Wing or
   ML-KEM-768), the session handshake should add a PQ KEM alongside x25519.

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
