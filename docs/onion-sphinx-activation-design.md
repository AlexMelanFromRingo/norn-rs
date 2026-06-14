# Design: capability negotiation — safely activate the Sphinx onion by default

Status: **design**. Branch `feature/onion-sphinx`. Follows
`onion-sphinx-design.md` (the format) — this is the rollout/activation half.

## 1. Problem

The Sphinx onion (`TYPE_ONION_SPHINX`, `src/sphinx.rs`) is implemented and wired
(inbound + opt-in outbound `write_to_onion_sphinx`), but **not used by default**:
a node that sends a `TYPE_ONION_SPHINX` cell to a peer running older code hits that
peer's `_ => unknown packet type` arm and the cell is silently dropped. So a sender
may only build a Sphinx cell when **every hop on the path** (all relays *and* the
destination) can process it. Nodes need a way to learn which others support it.

Constraint: the fix must roll out on a live, mixed-version mesh **without breaking
legacy nodes** and **without changing any signed announce wire format** (that would
break cross-version signature verification).

## 2. Approach

A new **additive, signed, flooded capability announce** (`TYPE_CAPABILITIES`),
modelled exactly on the existing `OnionKeyAnnounce`:

- Legacy nodes don't recognise the new type byte → they drop it via the existing
  `_ =>` arm. **Zero impact on them.** No existing message changes.
- Each node floods a signed `(origin, caps_bitfield, seq, valid_from_ms)`. Receivers
  verify, dedup by `(origin, seq)`, store `origin → caps`, and flood-forward.
- A sender builds a Sphinx cell only when its config allows it **and** every hop's
  identity is recorded with the `CAP_ONION_SPHINX` bit. Otherwise it uses the legacy
  onion. Graceful: before capabilities propagate, it falls back to legacy; as they
  arrive, capable paths upgrade automatically.

Capability advertised = "I can **receive/relay** Sphinx cells" (inbound is always
compiled in), independent of the node's own *send* preference (`onion_format`).

## 3. Wire format

`TYPE_CAPABILITIES = 0x11` (next free after `TYPE_ONION_SPHINX = 0x10`).

```
[origin:32][caps:u32 LE][seq:u64 LE][valid_from_ms:u64 LE][sig:64]   = 116 B
```
`sig` is Ed25519 by `origin` over `origin || caps || seq || valid_from_ms` (verified
with `verify_strict`, matching the rest of the protocol). `caps` is a bitfield:

```
CAP_ONION_SPHINX = 1 << 0   // can process TYPE_ONION_SPHINX
// bits 1.. reserved for future capabilities
```

## 4. State (RouterState)

```
peer_capabilities: HashMap<[u8;32], (u32 caps, u64 seq, Instant recorded)>
own_caps_seq: u64
```
- Bounded by `MAX_CAPABILITY_ENTRIES = 16_384` (mirrors `MAX_REMOTE_ONION_KEYS`),
  evicting a non-peer entry when full.
- Expired entries (`recorded` older than `CAPABILITY_VALIDITY`) are dropped in the
  existing periodic cleanup; senders treat unknown/expired as "no Sphinx".

## 5. Algorithms (mirror OnionKeyAnnounce)

**broadcast_capabilities** (periodic + once shortly after start):
```
own_caps_seq += 1
caps = CAP_ONION_SPHINX                       // we always accept Sphinx inbound
build CapabilityAnnounce{origin=self, caps, seq, valid_from_ms=now}, sign
self.peer_capabilities[self] = (caps, seq, now)   // so path checks see ourselves
flood encoded to all peers
```

**handle_capabilities** (on `TYPE_CAPABILITIES`):
```
reject if origin == self
verify_strict(sig) else drop
drop if age > CAPABILITY_VALIDITY or valid_from_ms too far future
dedup: forward only if seq strictly newer than stored for origin
record (origin → caps, seq, now), bounded-evict
flood-forward to all peers except sender
```

Broadcast cadence: every `CAPABILITY_BROADCAST_TICKS` (≈ 60 s) and on the first
tick, so newly-joined peers learn capabilities promptly. Caps are static, so this
is cheap; re-flood is bounded by the seq-dedup.

## 6. Sender selection

```
enum OnionFormat { Auto, Sphinx, Legacy }     // config; default Auto

fn path_supports_sphinx(relays, dst) -> bool:
    hop_count = relays.len() + 1
    if hop_count > sphinx::MAX_HOPS: return false
    for id in relays.identities ++ [dst]:
        match peer_capabilities.get(id):
            Some((caps, _, recorded)) if recorded fresh && caps & CAP_ONION_SPHINX != 0: ok
            _ : return false
    true
```

`PacketConn::write_to_onion` becomes the selector (it currently has **no callers**,
so this is low-risk and keeps the proven legacy body as the fallback):
```
fn write_to_onion(payload, dst, relays):
    let use_sphinx = match onion_format {
        Legacy => false,
        Sphinx => true,                       // force (errors if a hop can't)
        Auto   => path_supports_sphinx(relays, dst),
    };
    if use_sphinx { return write_to_onion_sphinx(payload, dst, relays); }
    ... existing legacy onion body unchanged ...
```
`onion_format` is plumbed like the other settings: `NodeConfig.onion_format` →
`PacketConn::set_onion_format` → `RouterState` field (default `Auto`).

## 7. Security notes

- The announce is signed, so an attacker can't forge "node X supports Sphinx". The
  worst a forged/incorrect cap does is make a sender build a Sphinx cell a hop
  drops — a self-inflicted reachability issue for traffic to that hop, not a leak;
  and forging requires X's key. `Auto` + the legacy fallback bound the blast radius.
- A node lying that it does **not** support Sphinx only downgrades its own traffic
  to the legacy onion (no worse than today). No downgrade attack on third parties
  (each hop's cap is signed by that hop).
- `caps` reveals a node runs Sphinx-capable code — negligible (it's the whole point;
  and the type byte `0x10` already reveals format use on the wire).

## 8. Test plan

1. `CapabilityAnnounce` encode/decode round-trip + truncation rejection +
   `sign_bytes` changes with every field (mirror the OnionKeyAnnounce tests).
2. `handle_capabilities`: valid announce recorded; bad sig / stale / self-origin
   rejected; strictly-newer dedup; bounded eviction.
3. `path_supports_sphinx`: all-capable → true; one missing/expired/legacy hop →
   false; hop count > MAX_HOPS → false.
4. Selection: `write_to_onion` picks Sphinx under `Auto` only when the path is
   capable; `Legacy` never; `Sphinx` always.
5. Config parse: `onion_format` defaults to `Auto`, accepts `sphinx`/`legacy`.

## 9. Implementation phases (each: TDD, commit, push)

1. `packet.rs`: `CapabilityAnnounce` + `TYPE_CAPABILITIES` + tests.
2. `router.rs`: state, `broadcast_capabilities`, `handle_capabilities`, dispatch
   arm, cleanup/eviction + tests.
3. `OnionFormat` config + plumbing (`set_onion_format`) + `path_supports_sphinx` +
   `write_to_onion` selection + tests.
4. Wire broadcast into the maintenance tick; REVIEW-FINDINGS + design updates.
