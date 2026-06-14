# Formal model

This document describes the symbolic models of the `norn-rs` v3 session handshake
and their machine-checked security properties. Two complementary tools are used,
because no single symbolic tool cleanly covers everything this protocol needs:

* **ProVerif** (`spec/norn.pv`, `spec/capabilities.pv`) — session-key secrecy and
  capability-gossip authenticity.
* **Tamarin** (`spec/norn.spthy`) — mutual authentication, injective key
  agreement, and perfect forward secrecy. These need native Diffie-Hellman
  reasoning that ProVerif cannot soundly provide for a DH-based AKE (see Q2).

Both operate in the Dolev-Yao model (the adversary controls the network; crypto
primitives are black boxes). The Tamarin run additionally **confirmed that the
Init/Ack signature domain separation is security-critical** — see "Tamarin model"
below.

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

### Q2 — Mutual authentication (machine-proven in Tamarin)

The intended property: any session the Initiator commits to (peer pk_R, key k)
must correspond to a Responder execution by pk_R that agrees on k, and the
Responder must likewise agree on who initiated.

ProVerif **cannot soundly decide this**. It reports the correspondence `false`
with a candidate trace — but so does even the key-independent variant, and in
every such trace both roles still verify each other's recipient-bound Ed25519
signatures and derive the *same* key. This is the well-known **incompleteness of
ProVerif under the Diffie-Hellman commutativity equation** `dh(a,pub(b)) =
dh(b,pub(a))`: the equational theory makes its Horn-clause resolution
over-approximate, producing spurious traces for key-agreement correspondences. So
the query is left commented in `spec/norn.pv`.

**Tamarin reasons about DH natively, and there mutual authentication is proved**
(`spec/norn.spthy`, "Tamarin model" section below). Both directions verify:
`I_injective_agreement` (the initiator authenticates the responder *and* agrees on
the session key, injectively — no replay) and `R_noninjective_agreement` (the
responder authenticates the initiator's signed initiation).

This also retires an earlier, ProVerif-era *speculation* that the Ack ought to
additionally sign the initiator's `x25519_pub`/`ml_kem_ek`: the Tamarin proof
shows it is **not** needed. Each party signs its **own** contributions plus the
peer identity (and a per-message domain-separation tag); the initiator's
contributions are already authenticated by the initiator's own signature in the
Init. That structure is sufficient for full mutual authentication and key
agreement.

### Q3 — Cross-target replay

The `recipient_ed_pub` field is inside the signature scope. An attacker
who captures a valid `Init` cannot replay it against a different
recipient because the captured signature only validates with the
original recipient's public key in the signed bytes.

## Tamarin model

`spec/norn.spthy` re-models the same Init+Ack handshake in Tamarin. Tamarin is a
multiset-rewriting prover whose `diffie-hellman` builtin carries the abelian-group
equational theory with a dedicated solver — so it decides the key-agreement
correspondences that defeat ProVerif (Q2). ML-KEM is modelled as the textbook KEM
abstraction (the responder draws a fresh shared secret and *encapsulates* it under
the initiator's long-term KEM public key, via the IND-CCA `asymmetric-encryption`
builtin). Each party holds an Ed25519 signing key and an ML-KEM key, both
**independently revealable** so "Ed25519 broken" and "ML-KEM broken" are separable.

| Lemma | Kind | Meaning |
|-------|------|---------|
| `executable` | exists-trace | a full honest run is reachable (model non-vacuous) |
| `I_injective_agreement` | all-traces | initiator authenticates responder **and** agrees on the session key, **injectively** (no replay) — unless an honest Ed25519 key leaked |
| `R_noninjective_agreement` | all-traces | responder authenticates the initiator's signed initiation — unless an honest Ed25519 key leaked |
| `key_secrecy_pq_hybrid` | all-traces | session key secret **even if the ML-KEM long-term key is revealed** (PQ hybrid: ephemeral X25519 still protects) |
| `key_secrecy_forward` | all-traces | **perfect forward secrecy**: the key is exposed only if an honest Ed25519 key leaked *before* that session |

All five **verify** (Tamarin 1.12.0 / maude 3.2; see "Running it").

### Finding: Init/Ack signature domain separation is load-bearing

Building this model surfaced a concrete result. The Init and Ack messages sign the
*same* field layout, `<pub, dh, ts, recipient, kem>`. With a **first draft that
omitted the leading magic byte** from the signed bytes, Tamarin found a **reflection
attack**: an `Init` signature is structurally a valid `Ack` signature, so an
adversary can reflect one for the other and break authentication. Adding the
per-message domain-separation tag (`'Init'` / `'Ack'`, modelling
`SESSION_INIT_MAGIC = 0x74` / `SESSION_ACK_MAGIC = 0x62`, which norn already prefixes
to `sign_data` in `build_init_sign_bytes` / `build_ack_sign_bytes`) makes the
attack disappear and all auth lemmas verify.

So norn's real protocol is **safe** — the magic byte, which also serves as the wire
demux tag, is doing double duty as a signature domain separator. Because that
double role is easy to miss in a refactor, it is now pinned with a `SECURITY`
comment in `src/session.rs` and asserted by this model (auth holds *with* the tags,
reflection attack *without*).

## Running it

### ProVerif

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
under the derived key.

### Tamarin

Tamarin needs `maude` (≥ 3.2) on `PATH`; the prover itself is a prebuilt binary
from the project's GitHub releases page:

```bash
apt-get install maude graphviz          # maude 3.2 ships in Ubuntu 24.04
# install the tamarin-prover 1.12.0 linux64 binary on PATH, then:
tamarin-prover --prove spec/norn.spthy  # all 5 lemmas, ~5s total
```

Actual output (verified with Tamarin 1.12.0, maude 3.2):

```
executable (exists-trace):             verified (16 steps)
I_injective_agreement (all-traces):    verified (48 steps)
R_noninjective_agreement (all-traces): verified (15 steps)
key_secrecy_pq_hybrid (all-traces):    verified (76 steps)
key_secrecy_forward (all-traces):      verified (76 steps)
```

## Known model gaps

Most of the original gaps are now closed by the Tamarin model. **Resolved:**

* **Forward secrecy** — proved in Tamarin (`key_secrecy_forward`): the session key
  stays secret even if *both* long-term keys leak *after* the run (and the ML-KEM
  key at any time). The ephemeral X25519 carries FS.
* **Authentication / key agreement (Q2)** — proved in Tamarin (`I_injective_agreement`,
  `R_noninjective_agreement`), which ProVerif could not soundly decide.

**Still out of (symbolic) scope:**

1. **Daily ML-KEM rotation.** Both models use a single, immortal `dk_I`; the live
   protocol rotates it every ~24h with a 60s overlap. The overlap-window
   correctness is small enough to inspect by hand in `src/session.rs::PqKeys`.
2. **Per-packet X25519 ratchet.** The models cover the handshake key; the live
   protocol then ratchets it per packet — a strictly-additional-FS improvement on
   top of the (already proved) handshake-level forward secrecy.
3. **Numeric freshness / replay windows.** The ±60s handshake timestamp window and
   the 64-slot session replay window are enforced numerically at runtime, out of
   symbolic scope. This is exactly why `R_noninjective_agreement` is *non*-injective:
   replaying one Init to one responder is defeated by the ts-window, not by the
   message format.

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
