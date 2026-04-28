# Roadmap

A statement of intent. Versions land when the goals are met, not on a
calendar — every release ships a tag and a CHANGELOG entry; nothing
ships before the contracts that govern it.

---

## v0.1.0 — Bring-up (current)

The kernel skeleton, the plugin C ABI, and the canonical security
crypto. Enough surface to write plugins against; not yet enough to
move bytes between two nodes.

| Area | Status |
|---|---|
| Kernel registries (connection / handler / transport / security / extension) | shipped |
| Plugin manager — `dlopen` + size-prefix vtable + service resolver | shipped |
| Identity — Ed25519 keypair, two-key derivation, attestation, NodeIdentity | shipped |
| Config loader — JSON, schema validation | shipped |
| Signal channel — typed pub/sub `SignalChannel<Event>` | shipped |
| GNET protocol v1 — mandatory mesh framing, static-linked into kernel | shipped |
| Null security provider — loopback pass-through | shipped |
| Noise crypto state machines — XX + IK on libsodium primitives | shipped |
| Kernel security pipeline — per-connection SecuritySession + Sessions registry, drives handshake_open through encrypt/decrypt | shipped |
| Noise plugin `.so` wrapper — `gn_security_provider_vtable` bound to the XX state machines, dlopen-tested with two-session handshake | shipped |
| Linking exception license model | shipped |
| CI/CD — ASan / UBSan / TSan / clang-tidy strict / nix flake check | shipped |

Tests: 319 passing across unit, integration, scenario, property suites.

---

## v0.2.0 — Two nodes talk

Goal: a real handshake between two processes over a real socket. Once
this lands, every later layer can rely on a working secured byte pipe.

| Area | Plan |
|---|---|
| URI parser foundation | shipped — `sdk/cpp/uri.hpp` (header-only, no libsodium) + `core/util/uri_query.hpp` (libsodium peer-pk decode); 33 unit + property tests; contract `docs/contracts/uri.md` |
| Kernel injection API | shipped — `host_api->inject_external_message` + `inject_frame` per `host-api.md` §8; per-source `RateLimiterMap` with `Clock`-injection token bucket per `clock.md` §2 |
| TCP transport plugin | shipped — Boost.Asio with strand-per-session writes (`transport.md` §4 single-writer), idempotent `shutdown_.exchange(true)`, IPv6 wildcard `IPV6_V6ONLY=false` for dual-stack listens; OBJECT lib for in-tree tests + `goodnet_transport_tcp.so` plugin entry |
| IPC transport plugin | AF_UNIX socket with length-prefix stream framing, declares `Loopback` trust |
| UDP transport plugin | datagram-mode with strand-bound receive path |
| Raw protocol plugin | opaque-payload protocol layer for foreign-protocol-payload (`null+raw` on Loopback per security-trust.md §4) |
| Heartbeat handler + `gn.heartbeat` extension | shipped — 88-byte PING/PONG payload with timestamp echo, per-peer RTT under injected clock per `clock.md` §2, observed-address reflection (STUN-on-the-wire) sourced from `host_api->get_endpoint`; extension `gn.heartbeat` v1.0.0 exports `get_stats` / `get_rtt` / `get_observed_address` |
| End-to-end loopback test | shipped — two kernels with their own NodeIdentity + TcpTransport + Noise provider drive a real Noise XX handshake over a 127.0.0.1 socket and reach Transport phase with matching channel-binding hashes; ASan/TSan clean |

---

## v0.3.0 — Reachability

Goal: nodes find each other and sustain a path even when neither side
has a public IP.

| Area | Plan |
|---|---|
| NAT pipeline | heartbeat keepalive, AutoNAT-style classification, relay candidates |
| Multi-path scheduler | TCP + ICE simultaneously, sub-50ms failover budget |
| Directed relay → direct upgrade | connection starts through a relay, upgrades to direct in ~7s once a path is found |
| AutoNAT classification | mapping behaviour detected over a small probe budget |

---

## v0.4.0 — Address routing

Goal: messages reach a peer by its public key alone, with bounded hop
count regardless of cluster size.

| Area | Plan |
|---|---|
| Kademlia-style DHT | XOR-distance routing table with k-buckets |
| Address-based forwarding | `find_node` and `route_to_pk` in handler space |
| Bucket sizing | targeting around 4.6 hops at one million nodes; 400 entries per routing table |

---

## v0.5.0 — Persistence

Goal: nodes that go offline keep their state and resume cleanly.

| Area | Plan |
|---|---|
| Storage handler | KV store with per-key TTL and signed updates |
| Sync handler | gossip-driven reconciliation between known peers |
| Offline queue | outbound envelopes survive a restart |

---

## v1.0.0 — Stable platform

Goal: a frozen kernel ABI, a documented operator surface, observability
hooks, and an audited security boundary.

- Frozen `host_api_t` size for v1.x
- MetricsExporter (Prometheus / OTLP) as a kernel-internal extension
- Auditable `--allow-null-untrusted` flag with documented threat model
- Operator manual in `docs/recipes/`
- Per-language SDK guides in `docs/impl/`

---

## Cross-cutting work

These run in parallel with the milestones above; no version gates them.

- **Documentation per language** — `docs/impl/cpp/`, `docs/impl/rust/`,
  `docs/impl/python/`. The contracts in `docs/contracts/` are
  language-neutral; per-language guides describe the idioms.
- **Plugin templates** — scaffolds in `templates/handler`,
  `templates/transport`, `templates/security`, `templates/protocol`.
- **Fuzz harness** — libFuzzer targets for the protocol layer and the
  Noise wire format.
- **Coverage gating** — lcov in CI with a percentage floor on each
  pull request.

---

## What is **not** on the roadmap

The following are explicit non-goals; the platform is built so these
remain plugin-side concerns and the kernel does not grow them:

- Kernel-level economics — token mechanics, relay payments, marketplace.
- Application protocols — file sync, chat, voice. They are handlers,
  not kernel code.
- Hardcoded trust roots — there is no certificate authority. Identity
  is Ed25519 to public keys.
- Centralised discovery service — the DHT is the discovery surface.
