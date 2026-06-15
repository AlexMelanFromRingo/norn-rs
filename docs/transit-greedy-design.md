# Transit greedy routing — destination coordinate in the Traffic header (Path A)

## Problem

Today greedy hyperbolic routing only happens at the **source**. `lookup(dst)`
reads the destination's `HypCoord` from `coord_table` (the source knows the
destination's `pub_key`) and forwards to the strictly-closer neighbour. But a
**transit** node only sees `traffic.routing_tag` (a BLAKE2b hash of the dst
pub key); `enc_header` is opaque to it. So `handle_traffic` forwards via
`lookup_by_tag_excluding` — **cuckoo-filter reachability only, no geometry**.

Consequence (verified, and matching the "routing reliability depended on the
count-to-infinity churn" finding): transit routing leans entirely on cuckoo
freshness. On a quiescent/correct tree the filters go cold, transient gaps
appear, packets bounce until `watermark >= MAX_FORWARD_HOPS` and trip a
`PathNegative` that poisons the tag for `PATH_NEG_TTL` (60 s). Cuckoo cannot
carry the whole transit load alone.

## Change (Path A)

Give transit nodes the destination coordinate directly, in the packet:

* `Traffic` gains `dest_coord: Option<HypCoord>` (wire: 1 presence byte, then
  16 bytes when present). Flag-day — same posture as the v4 coordinate bump.
* The source stamps `dest_coord = coord_table.get(dst)` when it knows it
  (it almost always does — it's routing to a known dst). `None` ⇒ legacy
  cuckoo-only transit (graceful fallback; also lets a privacy-conscious or
  coord-less sender opt out per packet).
* Transit `handle_traffic` routes **greedily on `dest_coord`** (pick the
  neighbour strictly closer to it), excluding the inbound peer. Greedy is
  loop-free by construction (each hop strictly decreases distance), so the
  micro-loop → TTL → PathNegative-poison cycle disappears.
* **Cuckoo stays as the fallback** for the local-minimum / last-meter case
  (no strictly-closer neighbour). `lookup_by_tag_excluding` is unchanged.
* Delivery is unchanged: a node still recognises a packet as its own by
  `routing_tag == routing_tag(self.pub_key)` and decrypts `enc_header`.

`greedy_next_hop(dst_coord, exclude)` is factored out of `lookup()` and reused
by both the source (`lookup`) and transit (`handle_traffic`).

## Why this stays within the project philosophy

* **No O(N) state.** Stateless — the coord rides in the packet. The flat
  ~2.5 MiB/node property is untouched. (This is why Path B — a per-node
  `tag → coord` gossip table — was rejected: O(N) per node, the "DHT-like"
  direction that defeats the whole point.)
* Greedy hyperbolic + cuckoo fallback **is** the project's routing model; this
  just lets transit participate in it instead of source-only.

## Privacy trade-off (the honest cost)

A transit node now learns the destination's `HypCoord` — its position in the
hyperbolic embedding, i.e. roughly *which region of the spanning tree* the
packet is heading to (comparable to seeing an IP prefix). It still cannot
recover the dst `pub_key` (encrypted in `enc_header`) or identity; `routing_tag`
already gave transit per-destination linkability, and `dest_coord` adds
geometric locality on top.

Mitigations: the coord is **optional** (omit ⇒ cuckoo-only, no leak), and the
opt-in **Sphinx onion** layer wraps the entire `Traffic` (including
`dest_coord`) for senders who need unlinkability. Path A's leak applies only to
base (non-onion) traffic, which already exposes `routing_tag` + `pkt_type`.

## Companion: tree convergence — TRIED, still shelved

Greedy is only as good as the embedding. The coordinates derive from the
spanning tree (`from_tree_depth`); the long-known **root-abdication**
count-to-infinity inflates depths and distorts coords. The hypothesis was that
Path A (transit no longer leaning on cuckoo) would finally make the abdication
guard (`fix_tree` ignores an announce whose root is our own identity echoed
back) safe to land.

**Result: it does not — tested and reverted.** With the guard *and* Path A, the
`four_node_linear_chain` integration test regressed and `five_node_star` went
to 8/10, whereas Path A alone is 12/12 and 20/20 under stress. Diagnosis: the
flakiness is a **convergence-window** gap, not a steady-state one. At cold
start the spanning tree (and thus the coordinates) has not converged yet, so
greedy has no good embedding to use *and* cuckoo is cold — the count-to-infinity
churn was what kept cuckoo warm through that window. Path A fixes steady-state
transit but not the startup window.

So Path A ships alone. count-to-infinity remains a tolerated, cosmetic
depth-inflation that the system actually relies on during convergence. A real
decoupling would need faster/seeded coord convergence or a brief startup warmup
that keeps reachability fresh until the embedding settles — a separate,
larger piece, out of scope here.

## Cluster validation + the deeper finding (100-node Docker harness)

Two full runs of `tests/cluster/run.sh` (100 nodes, 120 s, mid-run SIGKILL of
~10% + restore), one on master and one with the abdication guard:

| signal | master (count-to-∞) | + abdication guard |
|---|---|---|
| tree-0 depth (min/med/max) | 120 / 121 / 122 | **0 / 3 / 5** |
| panics (`mutex_poison`) | 0 | 0 |
| peer trust (probe success) | 2.88 / 4 | 2.88 / 4 |
| peer loss (med/max) | 0.000 / 0.261 | 0.000 / 0.261 |
| per-node memory | 2.84 MiB | 2.84 MiB |

So count-to-infinity is **real but genuinely tolerated** — routing is healthy at
100 nodes *either way* — and the abdication guard fixes it cleanly at scale with
**zero routing-health regression**. The flakiness is exclusively a property of
the tiny (4–5 node) integration topologies, not the real mesh.

**The deeper finding that reframes all of the above:** `CoordAnnounce` is
**one-hop only** (`handle_coord_announce` inserts `coord_table[from_key] =
coord`; nothing re-floods it). So `coord_table` only ever holds *self + direct
neighbours*. For any **multi-hop** destination the source does not know the
destination's coord, so:

* `lookup(dst)`'s hyperbolic-greedy branch is skipped (no `coord_table` entry)
  and falls through to cuckoo/XOR — i.e. **greedy is effectively source-only for
  *direct neighbours*; all real multi-hop routing is cuckoo (tree-aggregated
  reachability)**.
* **Path A is therefore mostly a no-op in production**: the source can only
  stamp `dest_coord` for a direct neighbour (which needs no multi-hop routing).
  Its mechanism is correct and harmless (and unit-tested), but for the common
  multi-hop case `dest_coord` is `None` → cuckoo, unchanged. The chain/star
  flake instrumentation confirmed it: failures are pure cuckoo "no route" +
  PathNegative during convergence, with `dest_coord` absent.

This means the count-to-infinity churn was **load-bearing for cuckoo freshness**:
it kept reachability perpetually re-gossiped, masking convergence-window gaps.
Removing it (abdication) exposes those gaps, and because greedy is vacuous there
is no geometric backstop. Surgical patches tried and measured:

* PathNegative as last-resort (deprioritise, never hard-exclude) — **kept**
  (eliminates a real 60 s single-path black-hole footgun), but did not fix the
  flake (chain 10/15).
* up-to-root transit fallback (forward toward a root when greedy+cuckoo miss) —
  marginal (chain 12/15), **reverted** (needs the abdication guard's acyclic
  parents, and abdication itself is what we're trying to make safe).

## Conclusion / the actual "full fix"

Robust multi-hop routing that does **not** depend on count-to-infinity churn
requires making **greedy actually work multi-hop**, which means the source must
learn the destination's coord. The lightweight way (NOT network-wide O(N) coord
flooding — that's the rejected DHT-like path) is to **exchange coords at session
setup** (O(active sessions), refreshed via the session), so Path A can stamp a
real `dest_coord`. Greedy then becomes the loop-free primary, cuckoo the
fallback, and the abdication guard becomes safe to land (verified harmless at
cluster scale). That is a design-first, multi-cycle change with a real
privacy/robustness/lightweight trade-off — an architectural decision, not a
surgical patch.

Until then: **count-to-infinity stays tolerated** (harmless per cluster data),
and the only change that ships from this investigation is the last-resort
PathNegative fix.

## Testing

* `packet.rs`: `Traffic` round-trip with `dest_coord` present and absent; a
  truncated coord is rejected.
* `greedy_next_hop`: picks the strictly-closer neighbour; returns `None` at a
  local minimum.
* Sim (`router::tests`): multi-hop greedy transit reaches the dst; `watermark`
  stays bounded (loop-free); recovery after node failure; behaviour with
  `dest_coord = None` (cuckoo path unchanged).
* Integration: the existing multi-node topology tests stay green.
