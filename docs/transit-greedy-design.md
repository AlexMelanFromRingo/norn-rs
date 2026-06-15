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

## Testing

* `packet.rs`: `Traffic` round-trip with `dest_coord` present and absent; a
  truncated coord is rejected.
* `greedy_next_hop`: picks the strictly-closer neighbour; returns `None` at a
  local minimum.
* Sim (`router::tests`): multi-hop greedy transit reaches the dst; `watermark`
  stays bounded (loop-free); recovery after node failure; behaviour with
  `dest_coord = None` (cuckoo path unchanged).
* Integration: the existing multi-node topology tests stay green.
