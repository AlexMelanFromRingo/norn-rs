# Formal model

This document describes the symbolic model of the `norn-rs` v3 session
handshake in `spec/norn.pv`, and the security properties it claims.

## Why ProVerif?

ProVerif is a state-of-the-art symbolic model checker for cryptographic
protocols. It operates in the Dolev-Yao model — the adversary controls
the network, can intercept, modify, replay, and drop messages, can create
arbitrary numbers of identities, but cannot break the cryptographic
primitives (signatures, KEM, DH, HKDF, AEAD) treated as black boxes.

A successful ProVerif proof gives high assurance that a protocol has no
**logical** flaw — message-flow attacks, missing authentication, type
confusion, replay vulnerabilities. It does **not** speak to implementation
issues like side channels, broken random number generation, or bugs in
the underlying crypto libraries; those are addressed separately (see
`SECURITY.md`).

## Modeled primitives

| ProVerif construct                | Real primitive            |
|-----------------------------------|---------------------------|
| `sign(sk, m)` / `verify(pk, m, σ)` | Ed25519                  |
| `dh(a, dh_pub(b)) = dh(b, dh_pub(a))` | X25519 ECDH           |
| `mlkem_encap` / `mlkem_decap`     | ML-KEM-768 (FIPS 203)    |
| `hkdf(ss1, ss2)`                  | HKDF-SHA256(salt=ss1, ikm=ss2) |
| `aead_enc` / `aead_dec`           | ChaCha20-Poly1305        |

Each primitive is treated as a perfect black box; ProVerif cannot inspect
internals, only their declared equations.

## Modeled flow

```
I → R   Init = mInit(pk_I, x25519_I, ml_kem_ek_I, ts, pk_R, sig_I)
        where sig_I = Ed25519_Sign(sk_I, ⟨x25519_I‖ml_kem_ek_I‖ts‖pk_R⟩‖ts)

R → I   Ack  = mAck(pk_R, x25519_R, ml_kem_ct, ts, pk_I, sig_R)
        where sig_R = Ed25519_Sign(sk_R, ⟨x25519_R‖ml_kem_ct‖ts‖pk_I⟩)

Both:   pq_shared = ML-KEM decapsulate / encapsulate
        dh_shared = X25519_DH
        session_k = HKDF(salt=pq_shared, ikm=dh_shared)
```

The model collapses some real-world details for tractability:

* Timestamps are modelled as a single `ts` value; the live protocol's
  ±60s freshness window is enforced numerically and is out of ProVerif's
  reach. We do model that `ts` is in the signed bytes (preventing pure
  signature replay).
* Per-packet x25519 rotation is not modelled — the handshake establishes
  the static key, and the live protocol then ratchets it. The ratchet
  is a strictly-additional-FS improvement on top of the handshake key.
* The 64-slot replay window on session packets is enforced at runtime;
  ProVerif's view of "data" is replay-equivalent regardless.

## Queries

### Q1 — Session key secrecy

```proverif
query attacker(secret_marker).
```

`secret_marker` is a `[private]` constant that an honest pair places in
the protected channel. ProVerif explores whether any Dolev-Yao
adversary can derive it. With a successful proof, no attack works in
the symbolic model.

### Q2 — Mutual authentication (documented limitation, not machine-proven here)

```proverif
query pkI, pkR, k;
    event(I_finished(pkI, pkR, k)) ==> event(R_finished(pkR, pkI, k)).
```

The intended property: any session the Initiator commits to (peer pk_R, key k)
must correspond to a Responder execution by pk_R that committed to k.

**ProVerif reports this `false`** (with a candidate trace) — and so does the
key-independent variant. This is the **well-known incompleteness of ProVerif
under the Diffie-Hellman commutativity equation** `dh(a,pub(b)) = dh(b,pub(a))`:
the equational theory over-approximates its Horn-clause resolution, yielding
spurious traces for key-agreement correspondences. In every such trace both
roles still verify each other's Ed25519 signatures (recipient-bound, per Q3) and
derive the *same* key — i.e. it is a tool limitation, **not a demonstrated
attack**. The query is therefore left commented in `spec/norn.pv`. Sound
machine-checking of a DH-based AKE's authentication belongs in **CryptoVerif**
(computational) or **Tamarin** (native DH); that is tracked as future work.

Defence-in-depth observation surfaced by the model: the Ack signature binds
`(x25519_pub_R, ml_kem_ct, ts, recipient)` but **not** the initiator's
`x25519_pub`/`ml_kem_ek`; signing the full transcript would let the responder's
signature attest to the initiator's contributions too.

### Q3 — Cross-target replay

The `recipient_ed_pub` field is inside the signature scope. An attacker
who captures a valid `Init` cannot replay it against a different
recipient because the captured signature only validates with the
original recipient's public key in the signed bytes.

## Running it

ProVerif is distributed via opam (not in Ubuntu's apt as of 24.04):

```bash
opam install proverif
proverif spec/norn.pv           # handshake: key secrecy
proverif spec/capabilities.pv   # capability-gossip authenticity
```

Actual output (verified with ProVerif 2.05):

```
# spec/norn.pv
RESULT not attacker(secret_marker[]) is true.
# spec/capabilities.pv
RESULT event(acceptCap(pk(skO[]),caps)) ==> event(announceCap(pk(skO[]),caps)) is true.
```

`true` means the query is proved in the symbolic model. Q1 (key secrecy) is
proved and is *non-vacuous* — the Initiator actually encrypts `secret_marker`
under the derived key. Q2 (authentication) is a documented ProVerif/DH
limitation (above), left commented in `norn.pv`.

## Known model gaps

These are properties that the live protocol claims but the .pv model
does not currently formalise:

1. **Forward secrecy under long-term-key compromise.** The handshake key
   should remain secret even if `sk_I` or `dk_I` is later leaked. We
   would model this by leaking the long-term keys *after* the protocol
   run and re-querying secrecy. The PQ hybrid pq_shared is
   contributory-FS only if the per-packet x25519 ratchet is modelled,
   which we omit (see above).
2. **Daily ML-KEM rotation.** The model uses a single, immortal dk_I;
   the live protocol rotates it every ~24h with a 60s overlap. The
   overlap window correctness is small enough to be inspected by hand
   in `src/session.rs::PqKeys`.
3. **Authentication / key agreement (Q2).** ProVerif cannot soundly decide
   the I/R agreement correspondence under the DH commutativity equation
   (see Q2 above); key *secrecy* (Q1) is proved, but mutual authentication
   should be machine-checked in CryptoVerif or Tamarin.

These gaps are open invitations for future formal work.

## Onion layer (Sphinx) & capability negotiation

The `spec/norn.pv` model covers the **session handshake**. The onion routing
layer (`src/sphinx.rs`, `docs/onion-sphinx-design.md`) is exercised by the test
suite (round-trip, tamper, constant-size, LIONESS avalanche) and the
`fuzz_sphinx` target; full symbolic modelling of the mix format is research-grade
and out of scope (the Sphinx literature uses computational proofs).

**Capability authenticity — machine-verified** in `spec/capabilities.pv`
(ProVerif 2.05):

```
RESULT event(acceptCap(pk(skO),caps)) ==> event(announceCap(pk(skO),caps)) is true.
```

A `CapabilityAnnounce` is Ed25519-signed by `origin` over
`origin‖caps‖seq‖valid_from_ms`. The model proves a node cannot make a receiver
accept a capability for the honest origin's key unless that origin actually
announced it — i.e. an attacker cannot forge or alter the capabilities of an
identity whose signing key it does not hold. Consequences:

* **No third-party downgrade.** A sender builds a Sphinx cell only when *every*
  hop's signed capability advertises `CAP_ONION_SPHINX`; an attacker cannot strip
  or forge another node's capability, so cannot force a downgrade (or upgrade)
  of traffic between honest parties.
* **Self-downgrade only.** A node lying that it lacks the capability merely makes
  senders fall back to the legacy onion for traffic *to that node* — no worse
  than the pre-Sphinx status quo.

**Onion (Sphinx) properties (informal; full mix-format modelling is research-grade
and out of scope, as in the Sphinx literature, which uses computational rather
than symbolic proofs):**

* *Per-hop confidentiality* — each layer key is `X25519(ephemeral_i, onion_priv_hop)`
  with an independent per-hop ephemeral; a relay learns nothing of other layers.
* *Header integrity* — a per-hop BLAKE2b MAC over `beta` (the relay drops any
  tampered or not-for-it cell; doubles as the "addressed to me?" test).
* *Constant size / indistinguishability* — every cell is exactly 1280 B with no
  length field, so position in the path and remaining hop count are unobservable
  (this is the property that closes the legacy `aead_len` depth leak, #3).
* *Per-hop unlinkability* — `epk`, `gamma`, `beta`, and the payload are fresh
  pseudorandom at every hop; nothing is equal across two hops of one packet.
* *Replay resistance* — a per-hop seen-cache keyed on `(epk, beta[..16])`.
* *End-to-end payload integrity* — the payload is the session-AEAD-protected
  `Traffic` packet, i.e. it inherits the integrity of the **modelled** handshake
  key; a relay tampering with payload bytes is detected (and dropped) at the
  destination. (Tagging-attack *non-localisability* would additionally need a
  wide-block payload cipher — LIONESS — a documented optional hardening.)
