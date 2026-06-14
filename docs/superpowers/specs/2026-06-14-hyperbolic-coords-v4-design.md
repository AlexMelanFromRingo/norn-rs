# Design: v4 hyperbolic coordinates (hyperboloid model)

Status: approved (2026-06-14). Branch `feat/coords-v4-hyperboloid`.

## Problem

norn embeds nodes in the Poincaré disk: `HypCoord { r, theta }`, with
`r = tanh(depth · 0.5)` and distance `2·artanh(|u−v| / |1 − ū·v|)`. Two f64
failure modes near the disk boundary:

1. **Radial saturation.** `r = tanh(depth·0.5)` rounds to `1.0` in f64 at
   depth ≳ 38 (and hits the `1−1e-10` clamp at depth ~24). Deep nodes store the
   *same* `r`; the distinction is lost at storage/wire time — no distance-side
   trick recovers it. Max representable depth-from-centre ≈ 23.7 units.
2. **Catastrophic cancellation.** `1 − ū·v` evaluates `1 − (≈1)` for two
   far-from-centre nodes and loses most of the mantissa.

## Decision

**Option B — hyperboloid (Lorentz) model with a linear radial coordinate**,
shipped as a **flag-day v4** protocol bump (no v3↔v4 negotiation; norn is
pre-1.0 so a clean break is acceptable). Chosen over: keeping the wire frozen
(fixes only #2, leaves the depth ceiling); higher precision (f128 — same wire
problem plus a dependency); retuning DELTA (breaks interop, barely helps).

## Representation

`HypCoord { rho: f64, theta: f64 }` where `rho` is the **radial hyperbolic
distance** from the origin — linear in depth, never saturates.

* Relationship to the old field: `ρ = 2·artanh(r)`, and since `r = tanh(depth·0.5)`
  the embedding gives exactly `ρ = depth` (with `RADIAL_STEP = 2·DELTA = 1.0`).
* `from_tree_depth(depth)`: `rho = depth · RADIAL_STEP`, `theta` unchanged
  (BLAKE2b of pub key). Root (depth 0) → `rho = 0` (origin), as before.
* `rho` is clamped to `[0, RHO_MAX]` with `RHO_MAX = 350.0` so that
  `cosh(rho)·cosh(rho)` stays within f64 range (no overflow → no NaN). 350 ≫ any
  realistic mesh depth; the old ceiling was ~24.

## Distance (numerically stable)

Hyperbolic law of cosines, rewritten to remove the boundary cancellation:

```
cosh d = cosh(ρu − ρv) + 2 · sinh ρu · sinh ρv · sin²(Δθ/2)
d      = arccosh( max(1, cosh d) )
```

Derivation: `cosh ρu cosh ρv − sinh ρu sinh ρv cos Δθ`
`= (cosh ρu cosh ρv − sinh ρu sinh ρv) + sinh ρu sinh ρv (1 − cos Δθ)`
`= cosh(ρu − ρv) + 2 sinh ρu sinh ρv sin²(Δθ/2)`.

Why it is stable: `cosh(ρu−ρv)` is evaluated directly (the argument is small when
`ρu ≈ ρv`, the exact case the old formula mangled), and the second term is a sum
of non-negatives — there is **no** `huge − huge` subtraction. `max(1, …)` absorbs
sub-ulp rounding below 1 (identical points → exactly 0). `RHO_MAX` keeps the
`sinh·sinh` product finite.

## Wire format & versioning (flag-day v4)

`CoordAnnounce` gains an authenticated `version: u8` (= `COORD_FORMAT_V4 = 4`),
prepended to the signed bytes and the wire:

```
[version:1=4][coord:16 = rho:f64 LE ‖ theta:f64 LE][tree_depth:u32 LE][onion_eph_pub:32][sig:64]
```

`decode` rejects any `version != 4` (a v3 frame fails to parse / verify). The
anti-sinkhole check (`coord == from_tree_depth(tree_depth, key)`) is retained and
independently rejects any cross-version coordinate, so the change is fail-closed
on two counts. `coord` keeps its 16-byte size — only the radial **semantics**
change (rho, not r).

## Touched code

* `src/hyperbolic.rs` — `HypCoord{rho,theta}`; `RADIAL_STEP`, `RHO_MAX`;
  `distance()` rewrite; `from_tree_depth → rho`; `encode/decode` (rho, clamp);
  drop `to_cartesian` (only the old distance used it).
* `src/packet.rs` — `CoordAnnounce.version`, `COORD_FORMAT_V4`,
  `sign_bytes`/`encode_into`/`decode`.
* `src/router/coords.rs` — `broadcast_coord` sets `version`; `handle_coord_announce`
  uses `coord.rho.is_finite()`.
* `src/router/treemath.rs` — `coords_approx_equal` compares `rho`.

## Testing

* Unit (hyperbolic.rs): self-distance 0; symmetry; triangle inequality at large
  `ρ`; monotonic in `ρ`; **deep-node distinguishability** (depth 40 vs 45 now give
  *different* distances — the v3 regression); cross-check vs an independent
  `arccosh` reference at small *and* large `ρ`; `RHO_MAX` overflow guard (huge
  `ρ` → finite, no NaN/Inf); `from_tree_depth` `ρ = depth`; encode/decode
  roundtrip; v3-frame / wrong-version rejection.
* Workspace: `cargo test` (default) and `--features sphinx`; clippy 0.
* **Docker / extended node scenarios** (`tests/cluster/run.sh`, `test_rotation.sh`,
  `tests/netns/run.sh`): multi-node convergence, tree rotation, deep topologies —
  to confirm greedy routing still converges with the new metric end-to-end.

## Risks

* Breaking change (v3↔v4 do not interop) — accepted (flag day, pre-1.0).
* Missed `.r` call site — closed by the audit above + compiler (field renamed,
  so every reader must be updated) + tests.
* `arccosh` precision for near-coincident points — handled by the stable identity.
* `cosh/sinh` overflow at extreme depth — handled by `RHO_MAX`.
