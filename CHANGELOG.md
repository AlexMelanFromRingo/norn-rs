# Changelog

All notable changes to norn-rs are documented here. Versions follow Cargo's
0.x semver: the **minor** number is bumped for breaking (wire/protocol) changes,
the **patch** number for backward-compatible fixes.

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
