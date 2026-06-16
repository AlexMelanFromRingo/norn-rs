# Changelog

All notable changes to norn-rs are documented here. Versions follow Cargo's
0.x semver: the **minor** number is bumped for breaking (wire/protocol) changes,
the **patch** number for backward-compatible fixes.

## v0.12.1

> Backward-compatible (no wire change). Local routing-decision change only —
> v0.12.1 and v0.12.0 nodes interoperate.

**Trust-aware primary routing.** The Sybil-hardened reputation consensus
(signed gossip, PoW-weighted observers, trimmed mean, quorum) already existed
but was applied to only one path — tag-forwarding (`lookup_by_tag_excluding`).
The primary `lookup(dst)` data path was **trust-blind** across all three of its
strategies, so ~half of transit (greedy, load-bearing since v0.11) and the whole
full-key path ignored the network's verdict on a peer.

- `greedy_next_hop` now ranks the strictly-closer candidates by
  `distance / combined_trust` instead of pure distance, routing around a
  network-condemned relay when an honest alternative exists. It only re-ranks
  **within** the strictly-closer set, so greedy loop-freedom and convergence are
  preserved (worst case: a few extra hops).
- The cuckoo fallback and XOR last-resort in `lookup` now use
  `trust_adjusted_cost_with(combined_trust)` (XOR distance stays the primary key
  for correctness; trust only breaks ties), matching the tag-forwarding path.
- New `combined_trust` helper blends local trust with consensus (the single
  signal every path now ranks by); de-duplicates the prior inline logic.

No new wire messages, no new flooding (reputation gossip already exists), no new
per-node state (the reputation table is already bounded). Honest residual: a
coalition controlling the *only* closer neighbour / sole route still carries
that traffic — the "Multiple cooperating malicious peers" row in SECURITY.md
stays ◐.

---

## v0.12.0

> ⚠️ **Breaking, flag-day release.** The session handshake wire format changed
> incompatibly — **all nodes must upgrade together**. A v0.12 node and a v0.11
> node cannot complete a session (SessionInit/Ack now ~+5.3 KB each). Mismatched
> peers fail loudly at parse time.

Adds **post-quantum hybrid authentication** to the session handshake. Until now
only *confidentiality* was PQ-hybrid (X25519 + ML-KEM-768); *authentication* was
classical Ed25519 only, so a cryptographically-relevant quantum computer (CRQC)
could forge identities. SessionInit/Ack now also carry an **ML-DSA-65** (FIPS
204, NIST level 3) signature over the same handshake bytes.

- Each node's ML-DSA key derives from a 32-byte seed **independent of its
  Ed25519 identity** — a CRQC breaking Ed25519 cannot also forge the PQ
  signature. `genconfig` emits a random `ml_dsa_seed`; existing configs without
  one fall back to an ephemeral key (warns; TOFU pin resets on restart).
- Verifiers **TOFU-pin** each identity's ML-DSA public key (per Ed25519 id;
  bounded at 8192 entries with eviction). Established and repeat sessions are
  thus post-quantum authenticated. `ml_dsa_pub` is inside the Ed25519-signed
  bytes, so a classical MITM cannot substitute it at first contact.
- The anti-amplification invariant is preserved (Ack and Init grow by the same
  ML-DSA terms). Flooded announces stay Ed25519-only — the +5.3 KB cost is
  per-session handshake only, keeping the lightweight per-node budget.

Residual gap (honestly): *first contact* still trusts the classical Ed25519
channel, and the underlay transport handshake (`transport.rs`/`quic.rs`) remains
Ed25519-only. So the "Quantum adversary" row in SECURITY.md stays ◐, not ✓.

### Breaking — wire format
- **SessionInit / SessionAck**: each now carries `ml_dsa_pub` (1952 B) and
  `ml_dsa_sig` (3309 B) after the ML-KEM field, before `sender_coord`.

---

## v0.11.0

> ⚠️ **Breaking, flag-day release.** The on-the-wire protocol changed
> incompatibly — **all nodes must upgrade together**. A v0.11 node and a v0.10
> node cannot interoperate (coord format v5; handshake +16 B). Mismatched peers
> fail loudly at parse time.

Makes hyperbolic greedy routing **load-bearing** — it was effectively a no-op
before (random key-hash angle + one-hop coordinates → greedy had no gradient and
never knew a multi-hop destination's coord). Cluster-measured: transit forwarded
via greedy went from **~0% → ~49.5%** (100-node WAN, rest via cuckoo fallback),
with no health regression (trust ~3.5/4, 0 panics).

### Breaking — wire format
- **Coordinate format v5 (tree-position embedding).** `CoordAnnounce.theta` is now
  derived from the node's tree position (parent's θ + a depth-shrinking per-node
  offset) instead of a random key-hash, so descendants cluster under their ancestor
  and greedy has a gradient toward a destination's subtree. Same 117-byte layout;
  version byte → 5; ρ stays depth-derived. θ anti-spoof relaxed to advisory (ρ still
  verified) — a θ-spoof sinkhole is caught by the existing trust-decay + active
  probing (same defence as cuckoo poisoning).
- **Coordinate dissemination at session setup.** `SessionInit`/`SessionAck` each
  carry the sender's 16-byte coord (advisory, **not** in the signed payload — the
  formally-verified handshake sign-bytes are unchanged), so a source learns a
  multi-hop destination's coord and stamps `dest_coord` → transit routes greedily.
  O(active sessions), no flooding. Anti-amplification invariant preserved.

### Added
- Convergence robustness + observability (groundwork): parent-switch hysteresis,
  a convergence-active control-cadence freshness floor, transient-hole poison
  suppression, and metrics `norn_tree_parent_changes_total`,
  `norn_cuckoo_no_route_total`, `norn_transit_greedy_total`,
  `norn_transit_cuckoo_total`.

### Known / unchanged
- **count-to-infinity stays tolerated.** The root-abdication guard is *not* landed:
  greedy does not unblock it (the first handshake bootstraps via cuckoo, before a
  destination's coord is known), and forcing it breaks single-path topologies. It is
  harmless on real clusters and greedy now carries ~50% of transit despite the
  inflated tree. See `docs/transit-greedy-design.md` / `docs/transit-cuckoo-convergence-design.md`.

## v0.10.2

> Backward-compatible patch. Wire protocol unchanged from v0.10.0/v0.10.1.

### Hardening
- **Transport locks recover from poisoning instead of cascading.** The TCP
  accept loop, the per-IP handshake rate-limiter (`PerIpGuard`), and the
  connected-peer map used raw `.lock().unwrap()` — a panic-while-holding any of
  those mutexes would poison the lock and cascade-panic every subsequent task
  (the rest of the codebase already used the poison-recovering `lock_or_recover`).
  Converted all production sites in `transport.rs`; a poison event now logs,
  bumps `norn_mutex_poison_total`, and continues on possibly-inconsistent state
  rather than taking the node down.

### Docs
- Corrected a stale `SessionManager.pq_keys` comment that described PQ-key
  rotation + prior-`dk` zeroize as a future TODO — both already exist
  (`PqKeys::rotate_if_due`, driven by maintenance; ml-kem `zeroize`-on-drop).

## v0.10.1

> Backward-compatible patch. The wire protocol is **unchanged** from v0.10.0 —
> v0.10.1 and v0.10.0 nodes interoperate freely; upgrade at your own pace.

### Performance
- **Exponential backoff for handshake-init retransmission.** v0.10.0 retransmits
  a lost `SessionInit` on a flat interval; under churn that flat-rate retry
  dominated egress. Backoff (1 s base, doubling, 30 s cap) keeps reliability
  while cutting the handshake retry cost. Measured on the 100-node WAN harness
  (50 ms ± 10, 2 % loss, mid-run kill+restore of 10 % of nodes):
  handshake `traffic` **439 MB → 187 MB (−57 %)**, total egress
  **10.0 → 7.6 MB/node (−24 %)**, with connectivity (4 peers/node), trust
  (≈3.5/peer) and memory (≈2.8 MiB/node) all preserved. The remaining egress is
  legitimate cuckoo gossip (the cost of a *connected* mesh), not retry waste.

### Added — observability
- **Per-message-type egress counters** — `norn_tx_bytes_by_type{type="…"}`
  (cuckoo / traffic / announce / coord / reputation / …) on `/metrics`, so node
  bandwidth can be attributed to gossip vs handshake/data vs control. This is the
  instrumentation behind the v0.9 → v0.10 bandwidth analysis above.

## v0.10.0

> ⚠️ **Breaking, flag-day release.** The on-the-wire protocol changed
> incompatibly. **All nodes in a mesh must be upgraded together** — a v0.10.0
> node and a v0.9.x node cannot interoperate. There is no v3↔v4 negotiation;
> mismatched peers fail loudly at the first parse.

### Breaking — wire format
- **Coordinate format v4 (hyperboloid model).** `CoordAnnounce` now carries a
  format-version byte and an unsaturating radial coordinate (`rho`, linear in
  tree depth) instead of the old Poincaré `r = tanh(depth·0.5)`, which saturated
  to 1.0 in f64 at depth ≳ 38 and suffered catastrophic cancellation near the
  boundary. Distances are computed on the hyperboloid (cancellation-free).
- **`Traffic` carries the destination coordinate (transit greedy, "Path A").**
  Senders stamp the destination's `HypCoord` so transit nodes can route greedily
  by hyperbolic distance (loop-free) instead of relying solely on cuckoo-filter
  reachability; cuckoo remains the local-minimum fallback. Adds a presence byte
  + 16 bytes to `Traffic`. (Privacy note: a relay learns the destination's
  coordinate *region*, not its identity; the opt-in Sphinx layer hides it.)

### Added
- **Opt-in Sphinx onion routing + capability negotiation** (`--features sphinx`).
  Zero cost when off: the module is `#[cfg]`-gated out of the default build.
- **Formal verification** of the PQ-hybrid handshake — ProVerif + Tamarin
  models proving mutual authentication and session-key secrecy (`spec/`,
  `docs/FORMAL.md`).
- **Handshake retransmission.** `SessionInit` is now re-sent (rate-limit-safe)
  until the session establishes, so a single Init lost to a transient routing
  gap during setup self-heals instead of wedging the session.

### Security & hardening
- Core hardening pass: hyperbolic-distance sign, session sequence-counter
  overflow, strict signature verification, O(1) onion replay dedup, and more.
- **HolePunch** `sign_bytes`/`encode` endpoint-length desync fixed (signature now
  always covers exactly the transmitted bytes).
- **Discovery-triggered dials are bounded** — an on-LAN attacker flooding fake
  pub_keys can no longer spawn unbounded persistent dial tasks.
- **PathNegative deprioritises a peer instead of hard-excluding it** — a single
  transient false-negative no longer black-holes the only path in a chain for
  the full 60 s TTL.
- **RUSTSEC-2026-0097** (`rand` unsoundness) resolved by upgrading to `rand`
  0.8.6 (the advisory's own patch), not suppressed.

### Fixed
- Crossing-dial tiebreak deadlock that could leave clients of a listen-only peer
  unable to connect.

### Internal
- `router.rs` decomposed into focused concern modules (`router/{handlers,
  conn, onion, coords, reputation, path_negative, diagnostics, …}`), no
  behaviour change.

### Known / tolerated
- The K=3 spanning-tree depth metric can inflate under churn (root-abdication
  "count-to-infinity"). It is **cosmetic** — routing is healthy (validated at
  100 nodes: flat ~2.5 MiB/node, median peer-trust 2.88/4, 0 loss through
  chaos). The convergence-robustness redesign that would let it be fixed cleanly
  is specced in `docs/transit-cuckoo-convergence-design.md` and deferred.

## v0.9.0 and earlier

See the git history and the `vX.Y.Z` tags.
