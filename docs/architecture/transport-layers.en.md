# Architecture: encrypted-transport layers

GoodNet's link family has stream-and-datagram cousins that overlap in
ways operators routinely confuse. This note maps the cousins:

- TLS over TCP for encrypted streams.
- DTLS over UDP for encrypted datagrams.
- QUIC over UDP for multiplexed encrypted streams with TLS 1.3 inside.
- WSS for TLS-tunnelled WebSocket framing.
- ICE for NAT traversal as a carrier orthogonal to all the above.

The goal is to make the scheme-vs-plugin mapping, the registration
shape, and the operator choice matrix explicit so a `peers.json` author
does not have to read every plugin to know which URI to write.

## Contents

- [1. Overview](#1-overview)
- [2. Plugin and scheme matrix](#2-plugin-and-scheme-matrix)
- [3. Registration relationships](#3-registration-relationships)
- [4. Choice matrix](#4-choice-matrix)
- [5. RFC implementation state](#5-rfc-implementation-state)
- [6. Why DTLS exists when QUIC also rides UDP](#6-why-dtls-exists-when-quic-also-rides-udp)
- [7. Why the TLS plugin handles both `tls://` and `dtls://`](#7-why-the-tls-plugin-handles-both-tls-and-dtls)
- [8. Cross-references](#8-cross-references)

---

## 1. Overview

GoodNet keeps stream and datagram transports as distinct plugins
instead of folding them into one polymorphic adapter. TCP-shaped
workloads pick `tls://` for encryption and `wss://` when the path has
to look like HTTPS. UDP-shaped workloads pick `dtls://` for
per-packet encryption and `quic://` when they need ordered streams,
flow control, and connection migration. ICE is a separate plugin that
nominates a NAT-traversed UDP pair (or TCP pair via RFC 6544) and
exposes it as a carrier to anything sitting above. None of these
plugins implement any of the others; their relationship is composer +
carrier, set up at runtime through the `gn.link.*` extension surface
described in `docs/contracts/link.en.md` §8.

---

## 2. Plugin and scheme matrix

| Scheme | Plugin | Transport | Encryption | Reliability | Streams | Use case |
|---|---|---|---|---|---|---|
| `tcp://` | `plugins/links/tcp` | TCP | none | yes | 1 | LAN, dev, debug, carrier for `tls://` and `ws://` |
| `udp://` | `plugins/links/udp` | UDP | none | no | n/a | game, RTP, carrier for `dtls://` and `quic://` |
| `ipc://` | `plugins/links/ipc` | UNIX domain socket | filesystem perms | yes | 1 | same-host plugin↔kernel and kernel↔kernel paths |
| `ws://` | `plugins/links/ws` | TCP + WebSocket framing | none | yes | 1 | HTTP-friendly transport over a TCP carrier |
| `tls://` | `plugins/links/tls` (`TLS_method` via `asio::ssl::context::tls_*`) | TCP + TLS 1.3 | TLS 1.3 | yes | 1 | encrypted streams, default for inter-node mesh |
| `dtls://` | `plugins/links/tls` composer (`DTLS_method`) | UDP + DTLS 1.3 | DTLS 1.3 | no | n/a | encrypted datagrams, WebRTC media, CoAP |
| `quic://` | `plugins/links/quic` (`OSSL_QUIC_server_method` / `OSSL_QUIC_client_method`) | UDP + QUIC + TLS 1.3 inside QUIC | TLS 1.3 (in QUIC handshake frames) | yes | many (one parent SSL + `SSL_new_stream`) | multiplexed encrypted streams, mobile reconnect |
| `wss://` | `plugins/links/ws` over a `tls://` carrier | TCP + TLS 1.3 + WebSocket framing | TLS 1.3 | yes | 1 | HTTPS-friendly encrypted transport, corporate-firewall traversal |
| `ice://` | `plugins/links/ice` | UDP candidates (TCP via RFC 6544) + ICE FSM | none on its own (composes) | depends on composer | depends on composer | NAT traversal carrier for any L2 above |

The cipher column lists what the plugin terminates. `wss://` does not
re-encrypt; it inherits TLS 1.3 from the `tls://` carrier and only adds
WebSocket framing. `ice://` does not terminate any cipher; QUIC or
DTLS riding on top do.

---

## 3. Registration relationships

The kernel's link registry maps **one scheme to one vtable**. The
plugin entry macro `GN_LINK_PLUGIN(Class, "scheme")` in
`sdk/cpp/link_plugin.hpp` is what places the row in the registry. Some
plugins also accept secondary URI prefixes through the composer
extension surface (`gn.link.<scheme>` per `link.en.md` §8) without
adding a second registry row.

The actual landings on a running node:

- `plugins/links/tls` registers exactly one scheme: `tls`
  (`plugin_entry.cpp` invokes `GN_LINK_PLUGIN(TlsLink, "tls")`). The
  `tls://` URI flows through the kernel-facing `listen` / `connect`
  thunks and uses an `asio::ssl::context::tls_server` /
  `asio::ssl::context::tls_client` SSL context, which is asio's
  wrapper around `TLS_method()`. The `dtls://` URI is handled by the
  same plugin object through its composer entries
  (`TlsLink::composer_listen` / `TlsLink::composer_connect` in
  `plugins/links/tls/tls.cpp`); on first call it lazy-builds a
  separate `SSL_CTX*` directly via `SSL_CTX_new(DTLS_method())`. The
  composer-side caller (a strategy, an upper-layer link, or a
  signaling bridge) is the one that recognises the `dtls://`
  prefix and dispatches to the TLS plugin's composer interface.
  One plugin object, one registry row, two URI shapes.

- `plugins/links/quic` registers exactly one scheme: `quic`. It does
  **not** delegate to `plugins/links/tls` — QUIC carries its own TLS
  1.3 handshake inside QUIC packet framing
  (`SSL_CTX_new(OSSL_QUIC_server_method())` and `OSSL_QUIC_client_method()`
  in `plugins/links/quic/quic.cpp`). The handshake bytes are
  encapsulated by QUIC Initial / Handshake packets and never appear
  as raw TLS records.

- `plugins/links/ws` registers exactly one scheme: `ws`. Both
  `ws://` and `wss://` are accepted by the same plugin's `listen` /
  `connect` entries; the parser in `WsLink::parse_uri` polarises on
  the `wss://` prefix and `ensure_carrier(secure=true)` looks up the
  `gn.link.tls` extension as its carrier instead of `gn.link.tcp`.
  There is no separate `wss` registry row; the WS plugin reuses one
  scheme registration and switches its carrier at parse time. The
  CHANGELOG entry "framing layer becomes a pure composer" describes
  this exact shape.

- `plugins/links/ice` registers exactly one scheme: `ice`. The plugin
  entry is hand-rolled (not `GN_LINK_PLUGIN`) because ICE also
  publishes two side-channel extensions —
  `gn.link.ice.signal` for offer/answer delivery and
  `gn.link.ice.path_mtu` for DPLPMTUD readouts — in addition to the
  standard `gn.link.ice` composer surface. Upper-layer plugins
  (`quic://<peer-pk-hex>`, `dtls://...`) query the
  `gn.link.ice` extension and use its `listen` / `connect` slots to
  ride a NAT-traversed pair.

The pattern: scheme registration is a kernel-facing claim that says
"this plugin owns URIs starting with `<scheme>://` on the public
`listen` / `connect` API". Composer extensions are a plugin-facing
contract that lets one plugin ride another without going through the
kernel registry. `tls://` is the only kernel-side TLS scheme; the
`dtls://` and `wss://` URI shapes live in plugin-facing parsers, not
in the registry.

---

## 4. Choice matrix

### 4.1 By latency target

| Target | Recommended | Rationale |
|---|---|---|
| `< 10 ms` round-trip | `quic://` (0-RTT resume) or `dtls://` | No TCP handshake, no head-of-line blocking |
| `< 100 ms` | `tls://` or `quic://` | TLS 1.3 1-RTT handshake fits comfortably |
| best-effort | `tcp://` or `tls://` | Setup cost amortised over a long-lived stream |

### 4.2 By reliability requirement

| Requirement | Recommended |
|---|---|
| Exactly-once stream delivery | `tcp://`, `tls://`, `quic://`, `wss://` |
| Best-effort datagram | `udp://`, `dtls://` |

QUIC streams are reliable; QUIC datagrams (`SSL_write_ex` datagram
mode) are not — but the GoodNet QUIC plugin does not currently expose
the datagram extension, so the operator-facing surface is
streams-only.

### 4.3 By NAT-traversal requirement

| Topology | Recommended |
|---|---|
| Behind NAT, peer-to-peer | `ice://` carrying `quic://`, `dtls://`, or `tls://` per fallback ladder |
| Direct internet routing | Any non-ICE transport |
| Symmetric NAT both sides | `ice://` with `ice.symmetric_port_prediction_enabled = true`; TURN relay if prediction fails |

See `docs/operator/ice-recipes.en.md` for per-deployment knob recipes.

### 4.4 By multiplexing requirement

| Concurrency need | Recommended |
|---|---|
| One application stream per connection | `tcp://`, `tls://`, `ws://`, `wss://` |
| Many concurrent streams sharing one congestion window | `quic://` |

QUIC is the only transport in the family with true in-protocol stream
multiplexing. The other transports require N connections for N
streams.

### 4.5 By firewall transparency

| Constraint | Recommended |
|---|---|
| UDP blocked end-to-end | `tls://` or `wss://` (both ride TCP/443 cleanly) |
| Only HTTPS allowed outbound | `wss://` (looks like a regular HTTPS upgrade) |
| HTTP-aware proxy in path | `wss://` (RFC 6455 upgrade is the canonical interop point) |

### 4.6 By interop

| Counterpart | Recommended |
|---|---|
| WebRTC media peer | `ice://` carrying `dtls://` (SRTP key exchange remains DTLS) |
| Browser WebSocket | `wss://` |
| IoT or CoAP endpoint | `dtls://` |
| Mobile client with reconnect / network change | `quic://` (connection migration carries the session across IP changes) |

---

## 5. RFC implementation state

The source of truth is `docs/_facts/rfc_coverage.yaml`. The table below
mirrors the entries relevant to transport selection; if it drifts,
trust the YAML.

| RFC | Title | Status | Implementation |
|---|---|---|---|
| [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) | TLS 1.3 | full | `plugins/links/tls` (OpenSSL backend, TLS 1.3 minimum pinned) |
| [RFC 9147](https://datatracker.ietf.org/doc/html/rfc9147) | DTLS 1.3 | not yet rowed in `rfc_coverage.yaml` | `plugins/links/tls` builds a DTLS SSL context lazily via `SSL_CTX_new(DTLS_method())` and reuses the TLS credential and verify-peer plumbing. The OpenSSL backend selects DTLS 1.3 when both peers negotiate it; no explicit DTLS-version pin exists today |
| [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000) | QUIC | partial | `plugins/links/quic` over OpenSSL-3.6 native `OSSL_QUIC_*_method`; works over plain UDP carrier. `quic://<64-hex>` route detection through `gn.link.ice` exists in `quic.cpp::resolve_carrier`; the end-to-end QUIC-over-ICE handshake regression is tracked in the ROADMAP |
| [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455) | WebSocket | full | `plugins/links/ws`; handshake, masking, ping/pong, close, §5.4 fragmentation reassembly (16 MiB merged cap, 64 KiB single-frame cap) |
| [RFC 7692](https://datatracker.ietf.org/doc/html/rfc7692) | permessage-deflate | not-implemented | `plugins/links/ws` strips the `Sec-WebSocket-Extensions` echo per RFC 7692 §5.1, so the extension never activates and frames stay uncompressed |
| [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445) | ICE | full | `plugins/links/ice`; full controlled/controlling FSM, triggered checks §7.3.1.4, regular nomination with `ice.aggressive_nomination` opt-in §8.1.1 |
| [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) | STUN | full | `plugins/links/ice` including 16-bit length-prefix framing for STUN-over-TCP / TLS |
| [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) | TURN | full | `plugins/links/ice`; ChannelBind / ChannelData fast path §11, allocation, permissions, Send-Indication fallback |
| [RFC 8899](https://datatracker.ietf.org/doc/html/rfc8899) | DPLPMTUD | full | `plugins/links/ice` (`path_mtu.{hpp,cpp}`); STUN binding-request padding probes |
| [RFC 8838](https://datatracker.ietf.org/doc/html/rfc8838) | Trickle ICE | partial | `plugins/links/ice`; end-of-candidates §10 signalled via `OFFER_EOC` / `ANSWER_EOC`. SDP integration is out of scope — the kernel uses a key-exchange-based offer/answer, not SDP |
| [RFC 8305](https://datatracker.ietf.org/doc/html/rfc8305) | Happy Eyeballs v2 | partial | `plugins/links/ice`; dual-family pre-fire in `begin_checks`. Full DNS-stage staggering is not applicable because ICE works with already-resolved candidates |
| [RFC 8085](https://datatracker.ietf.org/doc/html/rfc8085) | UDP Usage Guidelines | full | `plugins/links/ice`; pacing + consent-freshness compliant |
| [RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762) | Multicast DNS | partial | `plugins/links/ice` minimal A/AAAA responder + resolver for `<uuid>.local` host-candidate obfuscation; probe-then-announce omitted |
| draft-ietf-mmusic-mdns-ice-candidates | mDNS host candidates for ICE | partial | `plugins/links/ice` gated on `ice.mdns_obfuscate_host_candidates`; Linux-only host-IP enumeration today |

RFCs not in the YAML (RFC 6544 TCP candidates for ICE, RFC 6886 /
6887 NAT-PMP / PCP) are not implemented in the present plugin set and
are tracked separately in `docs/ROADMAP.en.md` and the `plugins/links/portmap` standalone repo. Treat the absence from the YAML as the canonical signal: if a transport claim is not in `rfc_coverage.yaml`, it is not shipping.

---

## 6. Why DTLS exists when QUIC also rides UDP

QUIC replaces TCP+TLS for stream-shaped workloads. DTLS replaces TLS
for datagram-shaped workloads. They sit on opposite sides of a
shape boundary, not on a redundancy boundary:

- **Pure datagram semantic.** WebRTC media (each RTP packet is
  independent of the next), CoAP-over-DTLS, OpenVPN, real-time game
  packets — these workloads do not need ordering, do not need
  retransmission, and do not benefit from a congestion window that
  collapses on a single loss. DTLS is the right shape.

- **QUIC is heavier than a one-shot datagram needs.** A QUIC
  connection carries congestion control, flow control, connection
  identifiers for migration, ack-eliciting frame logic, and a stream
  multiplexer. For "send one UDP packet, get one back" workflows that
  is gratuitous machinery.

- **DTLS preserves interop.** Anything that already speaks DTLS — and
  there are years of deployed WebRTC, CoAP, OpenVPN, and SCADA — keeps
  working without a QUIC adaptation layer.

Keeping both is the deliberate call. `dtls://` is not a fallback for
`quic://`; it is a separate transport shape that QUIC does not
subsume.

---

## 7. Why the TLS plugin handles both `tls://` and `dtls://`

`tls://` (TCP-carried) and `dtls://` (UDP-carried) share most of their
non-transport code:

- Certificate loading from PEM (`load_server_credentials`,
  `load_server_credentials_into`), including the same overridable
  `set_server_credentials` entry and the same key-zeroise rule on
  context teardown.
- Verify-peer policy. `links.tls.verify_peer = false` toggles the
  same `SSL_CTX_set_verify` call for both contexts. Default `true`
  uses the host's OpenSSL trust store.
- TLS 1.3 cipher suites. DTLS 1.3 reuses the TLS 1.3 cipher list, so
  the same OpenSSL configuration produces consistent peer selection
  on both transports.
- Worker pool, lifecycle, and shutdown ordering.

Splitting `tls://` and `dtls://` into two plugins would duplicate the
credential plumbing, the verify-peer toggle, and the worker pool while
keeping only the `SSL_CTX` family different (`TLS_method()` vs
`DTLS_method()`). The implementation keeps both behind one plugin
object:

- The kernel-facing `listen` / `connect` thunks accept `tls://` URIs
  only, since that is the scheme the plugin registers.
- The composer-facing `composer_listen` / `composer_connect` accept
  both `tls://` and `dtls://`. The DTLS-side SSL contexts
  (`server_ctx_dtls_`, `client_ctx_dtls_`) are constructed lazily on
  first `dtls://` call so a plain-TLS deployment never builds a DTLS
  context, and the chosen carrier (`gn.link.tcp` for TLS,
  `gn.link.udp` for DTLS) is captured at composer-listen / connect
  time.

One plugin, two SSL context families, two URI prefixes. The
composer-side caller — typically a strategy or an upper-layer
composing plugin — is the entity that decides which prefix to use.

---

## 8. Cross-references

- [link](../contracts/link.en.md) — link plugin contract; §6 covers
  scheme registration via `register_link`; §8 covers composer
  pattern and `gn.link.<scheme>` extension surface.
- [uri](../contracts/uri.en.md) — URI parser and authority/path
  splitting used by every link plugin's `parse_uri`.
- [multi-path](./multi-path.ru.md) — strategy-side policy for
  switching between transports advertised by `peers.json`.
- [ice-recipes](../operator/ice-recipes.en.md) — operator-facing
  `ice.*` knob combinations per deployment shape.
- [deployment](../operator/deployment.en.md) — `peers.json` URI form,
  TLS credential paths, and per-plugin namespaces in
  `links.tls.*` / `links.quic.*` / `ice.*`.
- [rfc_coverage.yaml](../_facts/rfc_coverage.yaml) — canonical RFC
  status table; the table in §5 above is a presentation of this YAML
  and the YAML wins on any conflict.
- `plugins/links/tls/README.md`, `plugins/links/quic/README.md`,
  `plugins/links/ws/README.md`, `plugins/links/ice/README.md` —
  per-plugin operator-facing docs in each plugin's own repo.
