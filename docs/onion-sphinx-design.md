# Design: fixed-size (Sphinx-style) onion format — closes the `aead_len` depth leak

Status: **design** (REVIEW-FINDINGS #3). Branch `feature/onion-sphinx`.

## 1. Problem

Today's onion (`src/onion.rs`) wraps each hop in its own AEAD layer and writes a
**cleartext `aead_len` varint** per layer (`OnionPacket::encode`). The wire cell is
zero-padded to `ONION_CELL_SIZE` (1280 B) and relays re-pad on forward, so the
*outer* size is constant — but `aead_len` shrinks ~one layer (~49 B) per hop. An
observer who can read consecutive hops' cells can therefore correlate
predecessor↔successor by the predictable length step, partially defeating the
fixed-cell anonymity. (Mitigated by QUIC link encryption; exposed on the raw-TCP
transport and to colluding relays sandwiching an honest one.)

Root cause: a nested-AEAD onion with per-layer length prefixes **cannot** be made
constant-size — an equal-sized inner layer can't fit inside an equal-sized outer.

## 2. Goals / non-goals

**Goals**
- Every onion cell is byte-for-byte indistinguishable in structure at every hop:
  no field reveals hop count, position, or remaining path length.
- Per-hop unlinkability: no identifier (epk, tag, MAC) is equal across two hops of
  the same packet.
- Per-hop integrity of the *routing header* (a relay detects tampering and drops).
- Replay protection (unchanged: per-hop seen-cache).
- Reuse the existing X25519 onion keys and announce machinery — **no key-type
  migration** (keeps the change tractable and low-risk).
- Coexist with the legacy onion during rollout via a distinct wire type byte.

**Non-goals (this iteration)**
- Canonical Sphinx single-element blinding (see §9 — deferred optimisation).
- LIONESS wide-block payload integrity (see §6 — payload integrity is already
  end-to-end via the session AEAD; documented tradeoff).
- Reply blocks / SURBs.

## 3. Approach

A **Sphinx-style fixed-size mix format**: a constant-length routing header whose
size is preserved at every hop by the Sphinx *filler* trick, plus a constant-length
payload peeled with a per-hop stream cipher. We keep **independent per-hop
ephemeral X25519 keys** (as the legacy onion already does) instead of canonical
Sphinx's blinded single element — this avoids a ristretto/key-type migration while
giving the same (in fact stronger) per-hop unlinkability, at the cost of carrying a
32-byte epk per hop inside the header. Header mechanics mirror Lightning BOLT-04
(a precise, test-vectored Sphinx instantiation).

## 4. Parameters & sizes

```
ONION_CELL_SIZE   = 1280                     (unchanged)
MAX_HOPS          = 5                         (relays incl. exit)
EPK_LEN           = 32                        (X25519 ephemeral pub)
TAG_LEN           = 16                        (routing_tag = BLAKE2b(dest_pub)[..16])
MAC_LEN           = 16                        (truncated BLAKE2b keyed MAC)
FLAGS_LEN         = 1
HOP_PAYLOAD       = FLAGS_LEN+TAG_LEN+EPK_LEN = 49   (per-hop routing for next hop)
PER_HOP           = HOP_PAYLOAD + MAC_LEN     = 65    (β block consumed per hop)
BETA_LEN          = PER_HOP * MAX_HOPS        = 325   (routing header, constant)
HEADER_LEN        = EPK_LEN + MAC_LEN + BETA_LEN = 373
PAYLOAD_LEN       = ONION_CELL_SIZE - 1 - TAG_LEN - HEADER_LEN = 890
```

Wire cell: `[TYPE_ONION_SPHINX:1][routing_tag:16][epk:32][gamma:16][beta:325][payload:890]`
= 1280.

The leading **cleartext `routing_tag`** is per-segment routing metadata: norn's
onion hops are not necessarily direct neighbours, so — exactly as the legacy onion
does with its outer tag — the mesh greedily routes the cell to the current onion hop
on this tag, and each peeling hop rewrites it to the next hop's tag. It is **not**
covered by the MAC (mutable hop-by-hop, like an IP header); the authenticated `beta`
carries the real routing. It changes every onion hop, so it leaks neither path
length nor position.

`MAX_HOPS=5` keeps an 890-byte payload (vs the legacy onion's ~1100 effective). This
is the inherent MTU cost of a constant-size onion; §9's blinding optimisation would
recover ~160 B by replacing the per-hop epks with one element.

## 5. Key schedule

Per hop, the shared secret is `s = X25519(eph_priv, hop_onion_pub)` (32 B). From `s`,
derive three independent sub-keys (BLAKE2b-256, domain-separated):

```
rho(s) = BLAKE2b256("norn-sphinx:rho:v1" || s)   # ChaCha20 key for beta stream
mu(s)  = BLAKE2b256("norn-sphinx:mu:v1"  || s)   # BLAKE2b key for gamma MAC
pi(s)  = BLAKE2b256("norn-sphinx:pi:v1"  || s)   # ChaCha20 key for payload stream
```

- **PRG**: ChaCha20 keystream, key = `rho(s)`, nonce = `0` (12 zero bytes). Safe:
  the key is unique per hop (fresh `s`), so the (key,nonce) pair never repeats.
- **MAC**: `gamma = BLAKE2bMac(key=mu(s), msg=beta)[..16]`.
- **Payload cipher**: ChaCha20 XOR, key = `pi(s)`, nonce = `0`.

## 6. Payload

A constant `PAYLOAD_LEN`-byte blob, onion-encrypted with a per-hop stream cipher.

- Innermost plaintext = `[orig_len:2 LE][Traffic packet bytes][zero pad → PAYLOAD_LEN]`.
  `orig_len` is encrypted (revealed only at the exit), so it leaks nothing en route.
- Sender, for `i = ν-1 .. 0`: `payload = ChaCha20_xor(pi(s_i), payload)`.
- Relay `i`: `payload = ChaCha20_xor(pi(s_i), payload)` (one peel). Same op both
  ways since XOR is involutive.

**Integrity tradeoff (documented):** the payload carries no per-hop MAC, so a relay
can flip payload bits (a tagging attack). norn's payload is the session-layer
`Traffic` packet, already AEAD-authenticated end-to-end (ChaCha20-Poly1305), so any
tampering is **detected and dropped at the destination**. The residual signal a
tagging attack yields (a dropped flow) is weaker than the depth leak we remove, and
is the same class of signal timing analysis already provides. Canonical Sphinx uses
LIONESS to make payload tampering non-localisable; adding LIONESS later is a
self-contained upgrade (see §9). The *routing header* IS per-hop MAC'd (§5), so a
relay cannot redirect or truncate the route undetected.

## 7. Algorithms

### 7.1 Sender — `build(path, traffic_bytes) -> Cell`

`path = [(tag_0, onion_pub_0) .. (tag_{ν-1}, onion_pub_{ν-1})]`, `1 ≤ ν ≤ MAX_HOPS`.
`tag_i` routes to hop `i`; the LAST hop is the exit (delivers the Traffic packet).

```
# 1. Per-hop ephemerals + shared secrets
for i in 0..ν: (e_i, E_i) = X25519_keygen(); s_i = X25519(e_i, onion_pub_i)
# 2. Filler (length (ν-1)*PER_HOP) — BOLT-04 mechanics
filler = []
for i in 0..ν-1:
    filler ||= zeros(PER_HOP)
    stream  = ChaCha20(rho(s_i), BETA_LEN + PER_HOP)
    filler ^= stream[BETA_LEN + PER_HOP - len(filler) ..]
# 3. Build beta back-to-front; `mac` carries gamma_{i+1}
beta = csprng(BETA_LEN)                 # random tail ⇒ unused slots indistinguishable
mac  = zeros(MAC_LEN)
for i in ν-1 .. 0:
    hop_payload = (i == ν-1) ? [EXIT, random(48)]
                             : [FWD, tag_{i+1}, E_{i+1}]          # 49 B
    block = hop_payload || mac                                    # PER_HOP
    beta  = (block || beta)[0 .. BETA_LEN]                        # right-shift by PER_HOP
    beta ^= ChaCha20(rho(s_i), BETA_LEN)
    if i == ν-1: beta[BETA_LEN-len(filler) ..] = filler           # plant filler
    mac = BLAKE2bMac(mu(s_i), beta)[..16]
# 4. Payload onion
payload = [len(traffic) as u16 LE] || traffic || zeros(→ PAYLOAD_LEN)
for i in ν-1 .. 0: payload = ChaCha20_xor(pi(s_i), payload)
# 5. Cell
return [TYPE_ONION_SPHINX] || E_0 || mac || beta || payload      # mac == gamma_0
```

### 7.2 Relay/exit — `process(cell, onion_keychain) -> Forward{tag,cell} | Deliver{traffic}`

```
(epk, gamma, beta, payload) = parse(cell)
s = keychain.dh(epk)                       # tries current/prev/identity x25519 priv
if BLAKE2bMac(mu(s), beta)[..16] != gamma: return Err            # tamper/not-for-us
B = (beta || zeros(PER_HOP)) XOR ChaCha20(rho(s), BETA_LEN + PER_HOP)
hop_payload = B[0 .. HOP_PAYLOAD]; next_mac = B[HOP_PAYLOAD .. PER_HOP]
beta'   = B[PER_HOP .. PER_HOP + BETA_LEN]
payload = ChaCha20_xor(pi(s), payload)
flags = hop_payload[0]
if flags == EXIT:
    orig_len = u16(payload[0..2]); return Deliver(payload[2 .. 2+orig_len])
else:
    next_tag = hop_payload[1..17]; next_epk = hop_payload[17..49]
    return Forward(next_tag, [TYPE_ONION_SPHINX]||next_epk||next_mac||beta'||payload)
```

The MAC over `beta` authenticates the whole remaining header to the holder of
`onion_priv`, so it doubles as the "is this layer addressed to me?" check (replaces
the legacy "try to AEAD-decrypt" probe). Constant-size at every hop: `process`
always emits a 1280-byte cell.

## 8. Integration

- New wire type `TYPE_ONION_SPHINX = 0x10` alongside `TYPE_ONION = 11`. `router`'s
  packet dispatch handles both during rollout; senders prefer Sphinx when all known
  relays advertise support (capability bit in `CoordAnnounce`, or simply attempt and
  fall back). Initial cut: gate behind a config flag `onion_format = "sphinx"`.
- `OnionKeyChain` (current/prev/identity X25519) is reused verbatim for `dh(epk)`.
- Relay forward path (`router.rs` ~2467): mirror the existing `Forward`/`Deliver`
  handling for the Sphinx cell; replay cache (`onion_seen[_set]`) keyed on
  `BLAKE2b(epk || beta[..16])` as today.
- `MAX_HOPS=5` ≤ existing `MAX_FORWARD_HOPS`; path builder caps relay count.

## 9. Security notes & deferred items

- **Fixes the leak:** every cell is `[type|epk32|gamma16|beta325|payload906]` with
  no length field and no per-hop-varying-size content. Position/where in the path is
  not observable.
- **Unlinkability:** `epk`, `gamma`, `beta`, and the payload are all freshly
  pseudo-random per hop; nothing is equal across hops (independent epks ⇒ no
  algebraic link, stronger than blinded Sphinx).
- **Header integrity:** per-hop BLAKE2b MAC over `beta`.
- **Deferred — blinding (canonical Sphinx):** replace per-hop epks with one
  re-blinded ristretto255 element to reclaim ~`(MAX_HOPS-1)*32` header bytes. Needs
  an onion-key-type migration; tracked as a follow-up.
- **Deferred — LIONESS payload:** full tagging-attack resistance; not required given
  end-to-end session AEAD.
- Extend `spec/norn.pv` with the new header once implemented.

## 10. Test plan

1. **KATs**: pin `rho/mu/pi` derivations and one full `build`→`process` cell to
   fixed vectors (guards accidental construction changes).
2. **Round-trip** for every `ν ∈ 1..=MAX_HOPS`: build, process at each hop in turn,
   assert the exit recovers the exact Traffic bytes.
3. **Constant size invariant**: every intermediate cell is exactly `ONION_CELL_SIZE`;
   `epk/gamma/beta/payload` lengths identical at every hop (property test).
4. **Tamper detection**: flipping any `beta`/`gamma`/`epk` byte ⇒ the targeted hop's
   MAC check fails (`Err`), never a panic.
5. **Wrong key**: a relay not on the path fails the MAC check cleanly.
6. **Indistinguishability**: a 1-hop and a 5-hop cell are byte-length-identical and
   field-length-identical (no observable difference).
7. **Fuzz** `process` on arbitrary 1280-byte input — never panics, only `Err`.

## 11. Implementation phases (each: TDD, commit, push)

1. ✅ `src/sphinx.rs` constants + key schedule (domain-separation test).
2. ✅ Filler + `build`/`process` header round-trip (machine-verified ν=1..5).
3. ✅ Payload onion; full `build`/`process`; all §10 tests (round-trip, constant
   size, empty/max traffic, tamper beta/gamma, wrong key, garbage-no-panic).
4. ✅ Wire cell with cleartext per-segment routing tag; `replay_digest`.
5. ✅ Router **inbound**: `handle_sphinx` (replay → MAC-auth + peel → forward/
   deliver), `dispatch` arm, `OnionKeyChain::sphinx_privs`, shared replay cache.
   Integration tests: announce↔process key consistency; 2-router relay→exit chain.
   ✅ Router **outbound**: `PacketConn::write_to_onion_sphinx` (additive, opt-in).
6. ⏳ **Remaining for activation:**
   - Capability negotiation: a bit in `CoordAnnounce`/`OnionKeyAnnounce` so a
     sender only builds Sphinx when every hop supports `TYPE_ONION_SPHINX`
     (sending to a legacy node today is silently dropped). Until then
     `write_to_onion_sphinx` is opt-in and unused by default.
   - Config flag (`onion_format = "sphinx"`) once negotiation exists, to auto-route
     `write_to_onion` → Sphinx when the path supports it.
   - Extend `spec/norn.pv` with the new header.
   - Optional: a `fuzz_targets/fuzz_sphinx_process` cargo-fuzz target (the
     `process_never_panics_on_garbage` unit test already covers panic-safety).
   - Optional follow-ups from §9 (ristretto blinding, LIONESS payload).
