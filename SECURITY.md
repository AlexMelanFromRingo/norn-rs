# Security Policy

## Threat model

`norn-rs` is an overlay mesh that aims for cjdns / Yggdrasil-level properties —
self-certifying ed25519 identities, hop-by-hop authenticated encryption, and a
lightweight hyperbolic + greedy routing core — plus a post-quantum-hybrid session
layer and an **opt-in** onion-routing layer for source/destination hiding. This
document spells out what the network is and is not designed to resist.

> Scope note. The differentiator is *lightweight* routing (flat per-node state).
> The mesh deliberately does **not** add a DHT, heavy flooding, or per-node O(N)
> routing tables; security mechanisms below are designed to fit inside that model.

### Adversary capabilities considered

| Capability                                                | In scope | Notes |
|-----------------------------------------------------------|:--------:|-------|
| Passive eavesdropping on the underlay (TCP / QUIC)        |    ✓     | Payload is end-to-end encrypted with ChaCha20-Poly1305 over PQ-hybrid session keys. |
| Active man-in-the-middle on the underlay                  |    ✓     | The transport handshake binds the ed25519 identity to the session via a per-connection challenge-response signature (`transport.rs`; `quic.rs`). Signatures are checked with `verify_strict`. |
| Malicious peer (knows their own keys, can send any frame) |    ✓     | Forwarding is loop-/TTL-bounded, rate-limited, and per-packet AEAD-authenticated; every signed control message is `verify_strict`-checked before it mutates state. Cuckoo poisoning is contained by trust scoring + active probing, **not** fully prevented. |
| Multiple cooperating malicious peers                      |    ◐     | Local trust decay + a **signed reputation-gossip** consensus (PoW-weighted observers, trimmed mean, quorum — resists bad-mouthing/self-promotion below ~25 % weight) bias **every** primary routing path (greedy, cuckoo, XOR) away from network-condemned peers. Full Sybil resistance is still **not** claimed: a coalition controlling the *only* closer neighbour / sole route still carries that traffic. |
| Compromise of one onion relay (opt-in onion path)         |    ✓     | A relay sees neither origin nor destination, only its immediate neighbours. |
| Compromise of *all* relays on an onion circuit            |    ✗     | Deanonymises the flow — a property shared with Tor. |
| Transit relay on a non-onion path                         |    ◐     | Sees ciphertext + routing metadata only (the `routing_tag` digest and, since v0.10, the destination's hyperbolic **coordinate region** used for greedy transit) — never plaintext, never the destination identity. The opt-in Sphinx layer hides even the coordinate. |
| Compromise of a node's long-term ed25519 private key      |    ◐     | The key *is* the identity; losing it loses the identity going forward. Past traffic is largely forward-secret (session x25519 rotates every 100 sends; the long-term ML-KEM keypair rotates periodically; onion peel keys are rotating ephemerals). |
| Global passive adversary observing all links              |    ◐     | Frame padding, forwarding jitter, and cover traffic raise the bar on size/timing correlation but do not make it infeasible. |
| Quantum adversary                                         |    ◐     | Sessions use a PQ-hybrid X25519 + ML-KEM-768 key (HKDF) — confidential as long as **either** primitive holds. Authentication is now **also** PQ-hybrid: the handshake carries an ML-DSA-65 signature (independent of Ed25519) and verifiers TOFU-pin the ML-DSA key, so established/repeat sessions resist a CRQC. Residual: *first contact* and the underlay transport handshake are still classically authenticated. |

### Properties claimed

* **Confidentiality** of payload between source and destination (AEAD with keys
  derived from a PQ-hybrid X25519 + ML-KEM-768 shared secret via HKDF).
* **Authenticity** of every encrypted packet, every signed control message, every
  announce, and every node-to-node transport handshake — all signature checks use
  `verify_strict` (rejects non-canonical R, small-order A, malleable signatures).
* **Replay protection**:
  * Per-session 64-slot sliding window on Traffic packets (the window check is
    overflow-safe against a hostile wire-supplied `seq`).
  * SessionInit / SessionAck carry timestamps; rejected outside a ±60 s window.
  * Per-connection challenge-response nonce binds handshake signatures to *this*
    socket, preventing cross-connection replay.
* **Source/destination hiding** is available via the **opt-in** onion layer
  (`PacketConn::write_to_onion`): `enc_header` (ephemeral-X25519-encrypted next-hop)
  + `routing_tag` (BLAKE2b digest of the destination key). The *default* data
  plane uses hop-by-hop session encryption only — relays see ciphertext + routing
  metadata, not plaintext.
* **Forward secrecy (session layer)**: x25519 keypairs rotate every 100 sends and
  are zeroized on drop. The long-term **ML-KEM-768 keypair also rotates**
  periodically (`PqKeys::rotate_if_due`), keeping the prior decapsulation key for
  one short overlap window so in-flight Acks still decap, then zeroizing it.
* **Anti-sinkhole**: CoordAnnounce coordinates MUST equal
  `from_tree_depth(claimed_depth, sender_pub)`; mismatches are rejected and decay
  the sender's trust. The claimed depth is cross-checked (±2) against the depth on
  file from the sender's last Announce.
* **DoS resistance** (caps enforced at the parse/insert site):
  * Frame size capped at 1 MiB; uvarint length prefix capped at 9 bytes.
  * Path length capped at 1 024 hops; forwarding TTL capped at 32 hops.
  * In-flight forwarding tasks capped at 4 096; idle sessions expire after 5 min.
  * Transport: ≤ 256 pending unauthenticated handshakes total **and** ≤ 4 per
    source IP, each with a 10 s timeout; discovery-triggered dials give up after
    repeated failures (bounded task growth).
  * Per-source `handle_init` rate limit (caps ML-KEM encaps an attacker can force).
  * Dedup / coord tables bounded; per-peer lock-poison recovery keeps one panicked
    task from cascading the node down (`*_or_recover`; `norn_mutex_poison_total`).
* **Sybil cost**: opt-in proof-of-work admission (`min_peer_difficulty_bits` =
  leading-ones of BLAKE2b(pub_key)); each bit doubles identity-generation cost.
  Off by default to avoid locking out existing keys on upgrade.
* **Constant-time comparisons** (`subtle::ConstantTimeEq`) for `routing_tag` and
  recipient-key matches.

### Hardening implemented (cumulative)

The session/handshake and routing hardening is in place and (for the handshake)
**machine-checked**:

* **Post-quantum hybrid handshake** — SessionInit carries an ML-KEM-768
  encapsulation key, SessionAck a ciphertext; both sides derive `pq_shared` mixed
  into every per-packet AEAD key. Confidential while *either* X25519 or ML-KEM holds.
* **Post-quantum hybrid authentication (TOFU)** — SessionInit/Ack also carry an
  **ML-DSA-65** (FIPS 204, NIST level 3) signature alongside the Ed25519 one,
  over the same handshake bytes (`pq_sign.rs`). Each node's ML-DSA key is derived
  from a 32-byte seed **independent of its Ed25519 identity** (a CRQC that breaks
  Ed25519 cannot also forge it). Verifiers **TOFU-pin** each identity's ML-DSA key
  (per Ed25519 id; bounded at 8192 with eviction), so established and repeat
  sessions are post-quantum authenticated. The ml_dsa_pub is inside the
  Ed25519-signed bytes, so a classical MITM cannot substitute it at first contact.
  Residual gap: *first contact* still trusts the classical Ed25519 channel, and
  the underlay transport handshake (`transport.rs`/`quic.rs`) stays Ed25519-only.
* **Formal verification (done)** — the v3 handshake is modelled in **ProVerif**
  (session-key secrecy, capability-gossip authenticity) and **Tamarin** (mutual
  authentication, injective key agreement, perfect forward secrecy). The Tamarin
  run also confirmed the Init/Ack signature domain separation is security-critical.
  See [`docs/FORMAL.md`](docs/FORMAL.md).
* **Onion forward secrecy + propagation** — onion peel uses a rotating ephemeral
  X25519 keypair distinct from the identity; the current ephemeral pub is flooded
  via a signed `OnionKeyAnnounce`. Legacy onion cells are padded to a constant
  1280 bytes; each relay drops replayed cell digests (O(1) dedup).
* **Sphinx mix format (opt-in, `--features sphinx`)** — closes the legacy onion's
  per-layer `aead_len` hop-depth leak with a constant-size Sphinx cell. Auto-
  negotiated per path via a signed `CapabilityAnnounce`; falls back to the legacy
  onion on a mixed-version mesh. Zero cost in a default build (the module is
  `#[cfg]`-gated out). See `docs/onion-sphinx-*.md`.
* **Coordinate model v4** — hyperboloid coordinates (cancellation-free distance),
  replacing the saturating Poincaré radial term; spoof-bound as above.
* **Long-term ML-KEM keypair rotation**, **opt-in Sybil PoW**, **`verify_strict`
  everywhere**, **constant-time matches**, and the **replay-window overflow fix**
  are all in place (see CHANGELOG and the repo-level `REVIEW-FINDINGS.md`).

### Remaining known weaknesses

1. **Cooperating valid-key Sybils** — PoW raises per-identity cost but does not
   detect multiple expensive-but-valid colluding peers. Mitigated by `trust`
   decay + active probing **and** a signed reputation-gossip consensus
   (PoW-weighted, trimmed-mean, quorum-gated) that — as of v0.12.1 — biases
   *every* primary routing path (greedy/cuckoo/XOR), not just tag-forwarding.
   Residual: a coalition that controls the only closer neighbour or sole route
   to a target still carries that traffic, so this is mitigation, not a
   guarantee.
2. **Legacy-onion hop-depth leak in a *default* build** — the per-layer `aead_len`
   shrinks ~67 B/hop, a correlation distinguisher for an on-path observer. Mitigated
   by QUIC link encryption; fully closed by building `--features sphinx`. (Note:
   norn's onion is reachable only via `PacketConn::write_to_onion` and is not wired
   into a default data plane today.)
3. **Side-channel hardening of the crypto crates** — RustCrypto primitives document
   constant-time properties, but cache/timing leakage at the CPU level is not
   countered with explicit blinding at the session layer.
4. **Traffic analysis** — padding + jitter + cover traffic raise the bar but a
   global passive adversary can still attempt size/timing correlation.

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

* Theoretical attacks against ed25519, X25519, ML-KEM-768, ChaCha20-Poly1305,
  BLAKE2b/Blake2s, or SHA-2 used as specified in their reference papers.
* DoS against a single victim that requires the attacker to already be a configured
  peer of that victim *and* to send at line rate (per-peer rate limiting beyond the
  built-in caps is delegated to operators).
* Anything explicitly listed under *Remaining known weaknesses* unless you have a
  fundamentally new attack vector.

## Supported versions

`v0.10.0` was a **flag-day wire change** (coordinate format v4 + transit greedy);
v0.10.x does not interoperate with v0.9.x.

| Version | Status        |
|---------|---------------|
| 0.10.x  | active        |
| < 0.10  | unsupported (wire-incompatible) |

## Crypto agility

On-the-wire crypto primitives are fixed for a given protocol version. The transport
handshake magic (`NRN1`), the SessionInit/Ack magics, and the CoordAnnounce
format-version byte encode the version, so mismatched peers fail loudly at parse
time rather than silently producing incompatible state.
