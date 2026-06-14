# Design: canonical Sphinx blinding (ristretto255) — analysis & recommendation

Status: **design / decision** (follow-up from `onion-sphinx-design.md` §9). Branch
`feature/onion-sphinx`.

## 1. What blinding would change

Canonical Sphinx carries **one** group element `alpha` that each hop re-blinds
(`alpha_{i+1} = alpha_i^{b_i}`, `b_i = H(alpha_i, s_i)`), instead of our current
**per-hop ephemeral X25519 keys** (a fresh `epk_i` per hop, the current one in the
clear cell header and the rest encrypted inside `beta`). Blinding needs a
prime-order group with scalar mult by arbitrary scalars, i.e. **ristretto255**
(curve25519-dalek), not X25519 (whose clamping breaks the blinding algebra).

Resulting header (for `MAX_HOPS=5`):

| | current (per-hop epk) | blinded (ristretto) |
|---|---|---|
| `PER_HOP` (β block) | flags1+tag16+**epk32**+mac16 = **65** | flags1+tag16+mac16 = **33** |
| `beta` = PER_HOP×5 | 325 | 165 |
| group element | epk 32 (clear, this hop) | alpha 32 (clear, re-blinded) |
| header total | tag16+epk32+gamma16+beta325 = **389** | tag16+alpha32+gamma16+beta165 = **229** |
| **payload** | **890** | **≈ 1050** (+160) |

## 2. The benefit is *only* size — not security

This is the key finding, and it changes the decision:

- **Unlinkability is already equivalent.** A single relay only ever sees its *own*
  hop's `epk` in clear (the next hops' epks are encrypted inside `beta`, surfaced
  one at a time). Each `epk_i` is an **independent** sender-chosen random, so two
  colluding relays at positions *i* and *i+2* see unrelated values — they cannot
  link the packet through the honest relay between them. Blinded `alpha_i` /
  `alpha_{i+2}` are likewise unlinkable (only the blinding factors, which the
  relays don't hold, relate them). **Both designs give unlinkable per-hop
  identifiers; blinding adds nothing here.**
- **Confidentiality, header integrity, replay, constant-size, payload integrity**
  are all identical (same per-hop ECDH → key schedule, same `gamma` MAC, same
  LIONESS payload, same fixed cell).

So blinding buys **≈160 B of payload (MTU)** and nothing else.

## 3. The cost is a network-wide migration

- **A second onion key type.** Relays advertise an **X25519** onion ephemeral
  today (`CoordAnnounce.onion_eph_pub`, `OnionKeyAnnounce`), and the **legacy
  onion** (`src/onion.rs`) uses it for its ECDH. Blinding needs a **ristretto255**
  onion key. X25519 and ristretto keys are not interchangeable, so during any
  rollout a node must advertise **both** — a new signed field (which can't go into
  the existing signed announces without breaking cross-version verification) or a
  **new additive announce type** (like the capability flood), plus storage and a
  second key in `OnionKeyChain` with its own rotation.
- **A Sphinx wire-format v2.** Removing the per-hop epks and adding `alpha`
  changes the cell layout and the build/process algorithms — it is **not additive**
  to the Sphinx format just shipped; it is a second format needing its own
  capability bit (`CAP_ONION_SPHINX_BLINDED`) and `process` path, coexisting with
  the current one during rollout.
- **New blinding crypto** (scalar mult, blinding-factor hashing, filler over the
  blinded transcript) — correct but more moving parts to verify.

Net: a multi-part protocol migration (new key infra + new announce + format v2 +
capability) touching both onion formats — for a 160-byte MTU gain.

## 4. Recommendation: **defer** (do not implement now)

The current per-hop-epk Sphinx already meets every security goal of #3 (constant
size, per-hop unlinkability, header integrity, replay, end-to-end payload
integrity with LIONESS non-localisability). Blinding is a **pure MTU
optimisation** whose migration cost and risk are out of proportion to ~160 B,
especially while norn's onion routing has no internal callers yet.

**Revisit if/when** any of these becomes true:
1. Onion payload MTU becomes a real constraint for a data plane that adopts onion
   routing (then the +160 B matters), **or**
2. `MAX_HOPS` is raised substantially (per-hop epks cost `32·(MAX_HOPS−1)` B; at
   large hop counts blinding's flat one-element header wins more), **or**
3. A decision is made to track canonical Sphinx exactly (e.g. for interop with an
   external Sphinx implementation or a formal-model reuse).

If revisited, implement as an **additive** `TYPE_ONION_SPHINX_BLINDED` with a
`CAP_ONION_SPHINX_BLINDED` capability and a ristretto onion key advertised via a
new additive announce — never by mutating the existing signed announces — so the
rollout stays non-breaking, exactly as the capability negotiation did.

## 5. Status of the §9 follow-ups

- ✅ fuzz target (`fuzz_sphinx`)
- ✅ ProVerif/formal note (`docs/FORMAL.md`)
- ✅ LIONESS payload (tagging non-localisability)
- ⏸️ ristretto blinding — **designed, deferred** (this document): size-only gain,
  migration cost not justified yet.
