# Anti-DPI mesh transport — design

*norn-rs · branch `feature/anti-dpi` · status: design, pre-implementation*

## Why this document

Bifrost users' contacts in Russia cannot connect at all: TSPU blocks the
plain-TCP mesh transport outright. This document specifies an **opt-in,
feature-gated** mesh transport that survives Russian DPI in 2026 —
without adding weight or complexity to the core lightweight protocol.

The threat model below is checked against 2026 reporting (see *Sources*).

## Goals / non-goals

**Goals**
- A mesh-link transport that passes Russian TSPU DPI as of 2026.
- Opt-in: Cargo feature `anti-dpi`, off by default — the default build
  is byte-for-byte unchanged.
- Mesh-symmetric: works peer↔peer and peer↔exit identically.
- No domain name required.

**Non-goals**
- Redefining norn-rs. It stays a general mesh-networking library; this
  is one more transport beside `tcp://` and `quic://`.
- Perfect anonymity / traffic-metadata protection.
- Defeating a *strict* national IP whitelist — no transport can; the
  mesh only maximises the odds that *a* path exists.

## Where this sits in the stack

The anti-DPI work adds **one transport adapter** — it is *not* a new
protocol. The layering, top to bottom:

    Bifrost            — the VPN / SOCKS5 application
    norn-rs mesh       — identity, peer sessions (NRN1), routing, mux
    transport adapter  — tcp:// | quic:// | wss://   (a byte-pipe)
    TCP/IP

norn-rs is transport-agnostic: `handshake_over_stream` is generic over
any `AsyncRead + AsyncWrite`, so a transport only has to yield a byte
stream. `wss://` is simply adapter #3 beside the existing `tcp://` and
`quic://`. The norn-rs protocol (NRN1 + frames) runs unchanged *inside*
the WebSocket; the WebSocket-over-TLS is a standard, ubiquitous wrapper
we borrow — not a protocol we invent. Yggdrasil's ironwood-based stack
works the same way and already ships `ws://` / `wss://` peerings.

## Threat model — Russian TSPU, 2026

TSPU = DPI boxes at every major ISP, centrally orchestrated by RKN.
Weapons, bluntest first:

1. **DNS / NSDI removal** — domains struck from the national DNS.
2. **IP / CIDR blocking — trending toward CIDR _whitelisting_** — only
   allow-listed destination subnets stay reachable. The hardest weapon.
3. **SNI blocking** — DPI reads the TLS SNI and blocks on it.
4. **Protocol-signature blocking** — fingerprints "the language a VPN
   speaks" (OpenVPN, WireGuard, Shadowsocks) and blocks it.
5. **"Fully-encrypted protocol" entropy heuristic** — flags streams
   that are high-entropy from byte 1 with no recognisable handshake.
   norn's current `obfs.rs` (uniform keystream) is exactly this — a
   detector magnet, not a defence.
6. **TLS JA3/JA4 ClientHello fingerprinting — ACTIVE & EXPLOITED.** On
   2026-04-01 TSPU added a `TELEGRAM_TLS` signature keyed on the
   JA3/JA4 of MTProto's Fake-TLS ClientHello and mass-blocked it. A
   distinctive TLS fingerprint is a *current* block vector.
7. **Active probing** — TSPU connects to a suspect endpoint and checks
   whether it answers like a proxy.
8. **Behavioural / statistical ML** — packet sizes, inter-packet
   timing, up/down ratio, session duration. VLESS+Reality was caught
   this way (~Feb 2026) *despite* a genuine TLS handshake.
9. **Throttling** — slow a flow to unusable speed without "blocking".

## Principle: be real, don't mimic

The NaiveProxy lesson: mimicry always leaves a gap to detect; *being*
the real protocol leaves none. So the transport is a **real TLS 1.3
session carrying a real WebSocket** — not a faked handshake.

## Architecture

New transport, URI scheme **`wss://`**, behind Cargo feature `anti-dpi`.
Module `src/wss.rs`, dispatched by scheme in `node.rs` exactly like
`quic://`.

- Every node runs a **real, minimal HTTPS server**.
- A mesh peer connects as a **real WebSocket client** (`wss://`). The
  WebSocket upgrade is gated by a secret derived from the peer key /
  PSK, carried in the request path or a header.
- A connection that does **not** present the secret is served a plain,
  boring, *consistent* web page — to any prober the node is an
  unremarkable web server (active-probing defence).
- Inside the established WebSocket: the existing **NRN1 handshake +
  norn frames**, unchanged. `handshake_over_stream` is already generic
  over `AsyncRead + AsyncWrite`, so a WebSocket stream plugs in with
  **zero core change** — the same trick `quic.rs` already uses.
- **TLS 1.3 only.** In TLS 1.3 the server Certificate message is
  encrypted, so a self-signed cert with no domain is invisible to a
  passive observer. Only the ClientHello (→ JA3/JA4) and ServerHello
  travel in clear.

## How each threat is met

| Threat | Mitigation |
|---|---|
| Entropy heuristic (#5) | Real TLS 1.3 handshake — recognisably TLS, not "unknown high-entropy". |
| Protocol signature (#4) | It *is* TLS + WebSocket — the two most common protocols on the wire. |
| TLS fingerprint (#6) | ClientHello / ServerHello shaped to a mainstream stack; the fingerprint is a **rotatable runtime parameter, never a baked-in constant** — because TSPU signatures *specific* fingerprints. |
| Active probing (#7) | The node serves a real, consistent web page to every non-mesh connection. |
| SNI (#3) | Blank SNI (normal for IP-addressed TLS) or a rotatable value. |
| Behavioural ML (#8) | Traffic shaping — Phase 2. |
| IP / CIDR block & whitelist (#2) | Mesh route diversity — see below. |
| DNS removal (#1) | N/A — peers connect by IP, not by name. |

## The IP-block answer: the mesh itself

Transport disguise cannot help once an IP is blocked, and a strict CIDR
whitelist defeats every VPN. The mesh is the answer **when a reachable
peer exists**:

- A censored node need not reach a foreign exit *directly*. It reaches
  **any** reachable peer — including a domestic one on an unblocked IP —
  and norn's existing multi-hop routing forwards onward.
- Multiple exit endpoints; no single fixed exit IP.
- **Bridge nodes** — entry peers absent from any public list, shared
  out-of-band (the Tor-bridge model).

Honest limit: against a fully-enforced national whitelist, success
depends on at least one reachable cooperating node. The mesh maximises
that probability; it cannot guarantee it.

## On WebSocket specifically

WebSocket is **not** blockable as a protocol — it underpins a large
fraction of the live web (chat, dashboards, trading, collaboration);
blocking it wholesale would break the Russian internet. Discord,
Telegram, Signal and Viber were blocked by **IP / SNI / DNS** service
blocking, and MTProto additionally by **TLS fingerprint** — not by
"WebSocket being banned". Here the WebSocket runs *inside* TLS, so a
passive DPI box never sees the WebSocket handshake at all — only a TLS
session. The lessons that *do* apply — IP/SNI agility and fingerprint
rotation — are first-class above.

## Phased plan

- **Phase 1** — the `wss://` transport: real TLS 1.3 + WebSocket,
  self-signed cert, probe-serves-a-page, a non-unique and *rotatable*
  TLS fingerprint. Feature-gated. Clears #4, #5, #6-naive, #7.
- **Phase 2** — traffic shaping: pad TLS-record sizes toward a web
  distribution, avoid a metronomic bulk stream. Addresses #8.
- **Phase 3** — deeper fingerprint hardening (browser-exact
  ClientHello) if field measurement shows it is needed.
- **Cross-cutting** — mesh route-diversity hardening: unlisted bridge
  nodes, multi-exit. Mostly leverages norn's existing routing.

## Deployment notes

- The exit should ideally listen on **:443** — TLS on an odd port is
  itself a mild tell and is easier to throttle. (The current Oracle box
  has :443 occupied by xray, so an anti-DPI exit wants its own :443 —
  a separate box, or coexistence.)
- **DuckDNS + Let's Encrypt** (both free) would give the *exit* — a
  stable server, unlike roaming peers — a real domain and CA-signed
  cert, closing the "SNI says X but the IP is not X's" cross-check gap
  for the Russia-facing link. Mesh peer↔peer links stay domain-free.
  Optional booster, not required.

## What this does NOT change

norn-rs stays a general mesh-networking library. `anti-dpi` is one more
opt-in transport, off by default, behind a feature flag — the core
lightweight protocol is untouched. Bifrost stays the VPN application
built on it. "VPN over mesh" is simply an accurate name for what
Bifrost already is.

## Sources

- Russia's internet censorship in 2026 — <https://en.zona.media/article/2026/04/07/russian_internet_censorship_2026>
- Russia using DNS + DPI, CIDR whitelisting — <https://www.techradar.com/vpn/vpn-privacy-security/russia-is-using-dns-and-dpi-to-block-youtube-telegram-and-whatsapp-while-pushing-state-controlled-max-as-alternative>
- TSPU `TELEGRAM_TLS` JA3/JA4 signature, MTProto Fake-TLS blocked 2026-04-01 — <https://github.com/DrKLO/Telegram/pull/1949>
- Censor's new CIDR-whitelist method — <https://github.com/net4people/bbs/issues/490>
