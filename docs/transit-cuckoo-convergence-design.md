# B-step 3 — Convergence-window robustness for cuckoo+tree routing

**Status:** design-first. No code changes proposed here are implemented yet.
**Goal:** make cuckoo+tree routing reliable on a *correct, converged* tree
(i.e. with the root-abdication guard landed) so that fixing count-to-infinity
no longer flakes low-path-diversity topologies — without adding O(N) state,
heavy flooding, or a privacy regression.

## 0. Where this sits (what is already established)

Confirmed by data/code this far (see `docs/transit-greedy-design.md`):

* **Routing is cuckoo+tree, not greedy.** `CoordAnnounce` is one-hop
  (`coords.rs::handle_coord_announce` inserts `coord_table[from_key]`; no
  re-flood), and `θ = angle_from_key(pub_key)` is a *random* angle, not a
  hierarchical greedy-embedding angle. So hyperbolic greedy is effectively
  source-only-for-direct-neighbours; all real multi-hop routing is cuckoo
  reachability aggregated over the K spanning trees.
* **count-to-infinity is real but tolerated.** 100-node cluster: depth 121 yet
  routing healthy (trust 2.88/4, loss 0, 0 panics, 2.84 MiB/node). The
  abdication guard (`fix_tree` ignoring an announce whose `root == self.pub_key`)
  fixes depth → 0/3/5 with **identical** routing health at scale.
* **The flake is exclusively low-path-diversity topologies.** With the
  abdication guard, the 100-node cluster stays healthy, but the 4-node chain
  (25% fail) and 5-node star (≈40–58% fail) flake.
* **Already shipped (`9ae6b40`):** PathNegative is now *last-resort
  deprioritisation*, not hard exclusion — removes the 60 s single-path
  black-hole. Necessary but **not sufficient** (chain still 10/15).
* **cuckoo gossips every tick** (`cuckoo_do_maintenance`, 1 Hz, not gated by the
  adaptive cadence) and `handle_cuckoo` replaces the peer filter on every
  message. So a node's *view of a neighbour's reachability* is at most 1 tick
  stale **once the tree is stable**.

The residual problem this spec addresses: the window where the tree is *not yet*
stable.

## 1. Diagnosis

### 1.1 Why low-path-diversity topologies flake (and the mesh does not)

cuckoo reachability is **aggregated along the tree**: each node sends
`merged = my_tag ∪ (children's filters)` UP to its parent and the union DOWN to
its children (`cuckoo_do_maintenance`, mod.rs). A node's ability to route to a
tag therefore depends on its **parent/child pointers being correct**.

While the tree is converging (or re-converging), parent pointers flip. During a
flip, the aggregation is transiently wrong: a node may briefly *not* have a tag
in any neighbour's filter — a **transient hole**. Holes close within a few ticks
once the tree settles (cuckoo is every-tick).

The amplification:

* **Mesh (100 nodes):** many node-disjoint paths to a destination. A transient
  hole on one path is routed around via another (`lookup_by_tag_excluding`
  already ranks all claimers). The hole is invisible end-to-end. → healthy.
* **Chain / star (the tests):** exactly **one** path to a 2-hop destination
  (chain: the sole upstream; star: the hub). A transient hole on that single
  path is **total** reachability loss for the destination until it closes. The
  test opens a session into that hole; `wait_for_session` retries for 10 s, and
  if the hole outlives the window the test fails.

So the bug is not "small topologies are special" — it is "**no alternative path
means zero tolerance for a transient hole**," and count-to-infinity's perpetual
churn used to keep the relevant tags continuously re-asserted so a clean hole
rarely opened. This is the verified failure signature: one transit `no route`
+ a PathNegative cascade at session-setup, `dest_coord` absent (greedy vacuous),
then silence.

### 1.2 What keeps the tree churning long enough to matter (candidate causes)

A 4-node chain has diameter 3; with the change-driven cadence (§2) it *should*
converge in ~3–4 ticks, well inside the 4 s warmup. The flake means convergence
sometimes does **not** settle (or re-opens) inside the window. Candidate causes,
ranked by current confidence:

1. **Cost-based parent flapping (HYPOTHESIS, medium-high).** `fix_tree` breaks
   root ties by `total_cost = ann.path_cost + peer.effective_cost()`.
   `effective_cost` is RTT/quality-derived. On in-memory `tokio::io::duplex`
   links RTT is ≈0 but *jittery* (task-scheduling noise), so two near-equal paths
   can oscillate which is "cheaper" → the parent pointer flaps every few ticks →
   the aggregation never settles → a hole that never closes inside the window.
   The mesh hides this (path diversity); a chain cannot.
2. **Adaptive-cadence propagation gaps (HYPOTHESIS, medium).** See §2 — a node
   that has backed off may be slow to re-assert a view a converging neighbour
   needs, *if* the triggering change is not captured by `control_digest`.
3. **Aggregation lag across a flip (CONFIRMED mechanism, low residual once 1+2
   are addressed).** Even with a stable tree, a *single* parent change takes
   ~depth ticks to re-propagate the aggregated union; on a chain that is a few
   ticks of hole. Tolerable if rare; fatal if 1/2 keep re-triggering it.

**Design-first imperative:** before committing a specific fix we must *confirm
which of 1/2/3 dominates* (see §5 instrumentation). The fixes below are designed
so the cheap, always-safe one (§4 transient-hole tolerance) lands first and
likely masks the symptom, while §2/§3 address the cause if instrumentation
shows they dominate.

## 2. Adaptive control-plane cadence (Roadmap #9)

### 2.1 How it works (mod.rs `maybe_broadcast_control`, `control_digest`)

Per tick: compute `control_digest` = per-tree `(root, root_seq, parent)` +
`own_depth` + `onion_eph_pub` + `peer_count`. If it changed since last time →
`control_interval = CONTROL_MIN_INTERVAL (1)` and **broadcast now**; else
`control_interval = min(control_interval+1, CONTROL_MAX_INTERVAL (8))` and
broadcast only when `tick - last_control_tick ≥ control_interval`. cuckoo
gossip and keepalives are independent and unaffected.

So announces are **change-driven**: any change to *my own* tree position snaps me
back to 1 Hz and I re-flood immediately. Steady state backs off to one announce
per 8 s (< `ANNOUNCE_EXPIRY` 30 s, so neighbours never expire me).

### 2.2 The starvation risk (precise)

The digest captures **my own** tree state, not "have I received and reflected
all of my neighbours' latest state." Two concrete gaps:

* **Digest blind spots.** A change that matters to a *downstream* node but does
  not alter my own `(root, root_seq, parent, depth, peer_count)` does **not**
  snap me to MIN. Tree-structure changes are mostly captured (parent/root/depth),
  so this is a narrow risk — but e.g. a `path_cost` change that does not flip my
  parent is *not* in the digest, yet it rides in the `Announce` (`send_announces`
  sends `path_cost`) and can change a *downstream* node's tie-break. If I have
  backed off to 8 s, that downstream node waits up to 8 s to see it. On a chain
  this directly extends a hole.
* **No freshness floor during a neighbourhood transition.** If any neighbour is
  still converging, I may already be "stable" (backed off) and thus slow to feed
  it the announce it needs. There is no notion of "someone near me is still
  moving, keep talking."

### 2.3 Proposed change — a convergence-active freshness floor

Keep the back-off for true steady state, but **guarantee minimum announce
freshness while the neighbourhood is unsettled**:

* Track a `last_topology_change_tick` that updates whenever **either** our own
  digest changes **or** we receive an `Announce`/tree update that changes any
  `peer.trees[*]` entry (root/parent/path_cost/depth). While
  `tick - last_topology_change_tick < CONVERGENCE_GRACE_TICKS` (proposed
  ~5–8 ticks), clamp `control_interval` to `CONTROL_MIN_INTERVAL`.
* Effect: as long as *anything nearby* is still moving, every node keeps
  announcing at 1 Hz; once the whole neighbourhood is quiet for the grace window,
  back-off resumes. Cost: a few extra announces per node per convergence event
  (bounded, O(degree), no new persistent state) — fully within the lightweight
  budget; steady-state chatter is unchanged.
* Also fold `path_cost` into `control_digest` (or a coarse bucket of it) so a
  cost change that affects downstream tie-breaks re-triggers a broadcast.

This is cheap insurance. Whether it is *sufficient* depends on whether cause §1.2.1
(cost flapping) dominates — which the freshness floor would *amplify into faster
flapping*, not fix. Hence §3.

## 3. Damping cost-based parent flapping (if §5 confirms it dominates)

If instrumentation shows the parent pointer flapping on near-equal costs:

* **Hysteresis on parent switch.** In `fix_tree`, only switch parent when the
  new candidate is better by a margin (e.g. `new_total_cost + SWITCH_MARGIN <
  current_total_cost`) OR the current parent became invalid/expired. This makes
  the chosen parent "sticky" against sub-margin cost noise. Same idea already
  used elsewhere (trust hysteresis). No new state; a few lines in `fix_tree`.
* **Smooth `effective_cost`.** If raw cost is jittery, route selection should use
  an EWMA-smoothed cost rather than the instantaneous sample, so scheduling noise
  cannot flip ranking. (Check whether `effective_cost` is already smoothed; if
  not, smoothing is the more principled fix and helps the mesh too.)

Either is O(1) per peer, lightweight, and improves stability generally (not just
the test).

## 4. Transient-hole tolerance (the always-safe symptom fix)

Independent of the cause, make a *single* transient hole non-fatal so a
no-alternative-path topology rides it out. Two options, smallest first:

### 4.1 Don't poison during a likely-transient hole (cheap, recommended first)

When `handle_traffic` finds no route, today it emits a PathNegative immediately.
The last-resort lookup change already prevents that from black-holing, but the
cascade still adds churn. Refine: **suppress PathNegative emission while the
local tree is convergence-active** (`tick - last_topology_change_tick <
CONVERGENCE_GRACE_TICKS`). During convergence a "no route" is presumed transient,
so we just drop-without-poisoning and let the sender's natural retry (sessions
already retry every 100 ms) catch the route once cuckoo fills in. After the grace
window, a "no route" is treated as a genuine dead-end (poison as today). Zero new
state; one guard.

### 4.2 Brief hold-and-retry queue (stronger, if 4.1 is not enough)

A small **bounded** per-node hold queue: when there is no route for a packet,
enqueue it (with a short deadline, ~1–2 s) instead of dropping; on each
maintenance tick, retry routing queued packets and forward any that now resolve;
drop on deadline. Bounds: `MAX_HELD_PACKETS` (small, e.g. 256) and the short TTL
keep it O(1)/lightweight and DoS-safe (a flood just fills and ages out the
queue). This converts a transient-hole *drop* into a sub-second *delay* — exactly
what session setup needs — without touching the routing algorithm.

4.1 is preferred (no buffering, no new memory); 4.2 is the fallback if holes are
longer-lived than the sender's own retry cadence.

## 5. Instrumentation first (confirm cause before committing §2/§3)

Add (test-cluster + a debug counter) and read off the chain/star repro:

* `tree_parent_changes_total` per node — confirms/【refutes §1.2.1 flapping.
* `cuckoo_no_route_total` and time-to-first-successful-route after session start
  — measures hole duration directly.
* `convergence_active_ticks` — how long the grace window is engaged.

Decision rule: if `tree_parent_changes_total` keeps climbing on a *settled* 4-node
chain → cause is flapping → §3 is required. If parent changes go to zero but
holes still appear → cause is cadence/aggregation lag → §2 + §4. In all cases
§4.1 lands first as the safety net.

## 6. Validation criteria

* **Integration (the gate):** `four_node_linear_chain` and
  `five_node_star_topology` ≥ **30/30** under stress (currently chain 10/15,
  star ~9/15 with abdication+last-resort). This is the bar for landing the
  abdication guard.
* **Cluster (no regression):** rerun `tests/cluster/run.sh` with the full stack
  (abdication + these changes). Tree-0 depth must stay shallow (≈0/3/5), and
  routing health must not regress: trust ≥ 2.8 median, loss ≈ 0, 0 panics,
  memory ≈ 2.84 MiB/node, control-broadcast count not materially higher in
  steady state (the freshness floor must not turn into perpetual 1 Hz chatter).
* **Poison defence intact:** the cuckoo-poisoning / trust-decay tests and the
  `lookup_by_tag` last-resort tests stay green; a malicious peer is still routed
  around when an alternative exists.
* **Unit:** new tests for the cadence freshness floor (stays MIN while a tree
  update is recent, backs off after the grace window) and, if added, parent-switch
  hysteresis (no switch under sub-margin cost noise).

## 7. Non-goals / constraints

* **No O(N) per-node state, no DHT, no network-wide coord/flood.** Everything
  here is O(degree) per tick and bounded.
* **No privacy change.** Routing stays on `routing_tag`; `dest_coord` (Path A) is
  untouched. (Making greedy *actually* work — hierarchical embedding + coord
  dissemination — is the rejected expensive Path A and explicitly out of scope.)
* **Preserve the documented poison/trust defence** — §4.1 only suppresses
  poisoning *during the convergence grace window*, not in steady state.
* **Steady-state cost unchanged** — the freshness floor must collapse back to the
  Roadmap #9 back-off once quiet; verify via `norn_control_broadcasts_total`.

## 8. Rollout

1. Land instrumentation (§5) + §4.1 (suppress-poison-during-convergence) +
   the abdication guard together on a branch.
2. Run the chain/star stress + cluster. Read the counters.
3. If the gate (§6) is met → done (count-to-infinity finally fixed). If not, add
   §2 (freshness floor); re-measure. If parent-flapping is confirmed dominant,
   add §3 (hysteresis/smoothing); re-measure.
4. Land §4.2 (hold queue) only if holes outlive the sender retry even after 2/3.

Each step is independently revertible and validated against both the integration
gate and the cluster no-regression bar.
