# Changelog

All notable changes to this project. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

Two nodes can talk: real transports, an end-to-end secured byte
pipe, and the first handler. The kernel moves encrypted bytes
between two processes over a real socket and surfaces RTT through a
typed extension API.

### Added

- **URI parser** — header-only `sdk/cpp/uri.hpp` with `parse_uri`
  and `uri_query_value`, plus libsodium-backed
  `core/util/uri_query.hpp` for `?peer=<hex>` decode. Contract
  `docs/contracts/uri.md`.
- **Kernel injection API** — `host_api->inject_external_message`
  and `inject_frame` for bridge plugins to push foreign-system
  payloads into the mesh under their own identity. Per-source
  token-bucket rate limit (`core/util/token_bucket.hpp`) with
  explicit `Clock` injection per `clock.md` §2.
- **Kernel security pipeline** — per-connection `SecuritySession`
  plus `Sessions` registry that drive the handshake from
  `notify_connect` through encrypt / decrypt at the Transport
  phase. `kick_handshake` defers the initiator's first wire
  message until the transport has registered its socket. Trust
  promotes `Untrusted → Peer` once the handshake completes,
  gated through `gn_trust_can_upgrade` in `sdk/trust.h`.
- **Noise plugin** — `goodnet_security_noise` `.so` wrapping the
  XX + IK state machines, dlopen-tested through a two-session
  handshake.
- **TCP transport** — Boost.Asio strand-per-session writes per
  `transport.md` §4 single-writer, IPv6 dual-stack with
  `IPV6_V6ONLY=false` on `::` wildcard.
- **IPC transport** — Boost.Asio `local::stream_protocol` with
  the same strand shape as TCP; `chmod 0700` on the parent
  directory before bind closes the TR-C6 TOCTOU window.
- **UDP transport** — single-strand datagram path, MTU-gated send
  with all-or-nothing `send_batch` precheck, per-source
  `RateLimiterMap` on new-conn allocation, `notify_disconnect` on
  every released peer.
- **Heartbeat handler + `gn.heartbeat` extension** — PING/PONG
  payload with timestamp echo, per-peer RTT under injected clock,
  observed-address reflection (STUN-on-the-wire) sourced from
  `host_api->get_endpoint`. 88-byte big-endian wire layout with
  explicit `serialize_payload` / `parse_payload`.
- **End-to-end loopback test** — two kernels with their own
  `NodeIdentity` plus `TcpTransport` plus the Noise provider drive
  a real Noise XX handshake over a `127.0.0.1` socket and reach
  the Transport phase with matching channel-binding hashes.
- **`nix run .#install-hooks`** — opt-in pre-commit hook that runs
  strict `clang-tidy --warnings-as-errors=*` on staged C++ files,
  mirroring the CI lint gate locally.
- **Plugin quiescence anchor** — every registry entry (handler,
  transport, extension, security) carries a strong reference to
  the registering plugin's `std::shared_ptr` quiescence sentinel.
  Dispatch snapshots inherit the reference by value-copy; the
  plugin manager observes it through `weak_ptr` between
  `gn_plugin_unregister` / `gn_plugin_shutdown` and `dlclose`.
  An unmap that races with an in-flight dispatch is now
  structurally impossible — the snapshot keeps the .so mapped
  until the call returns. A bounded drain timeout falls through
  to `log warn + leak handle` rather than blocking shutdown.
- **`gn.transport.<scheme>` extension API** — every baseline
  transport publishes `gn_transport_api_t` from
  `sdk/extensions/transport.h` with steady slots
  (`get_stats`, `get_capabilities`, `send`, `send_batch`,
  `close`) functional and composer slots
  (`listen`, `connect`, `subscribe_data`, `unsubscribe_data`)
  returning `GN_ERR_NOT_IMPLEMENTED` until the first
  L2-over-L1 plugin (WSS, TLS) drives them. TCP / IPC / UDP
  expose monotonic byte / frame / connection counters; UDP
  surfaces its MTU through the capability descriptor.
- **`TRANSPORT_PLUGIN(Class, "scheme")` macro** — collapses
  per-transport `plugin_entry.cpp` boilerplate (five
  `gn_plugin_*` exports, kernel-facing vtable, extension
  vtable, descriptor) into a single one-line invocation in
  `sdk/cpp/transport_plugin.hpp`. Every C thunk is `noexcept`
  with a try/catch wrapper so a plugin exception never escapes
  the C ABI boundary.
- **`host_api->unregister_extension`** — paired with the
  existing `register_extension` so plugins can drop their
  extension registration on `gn_plugin_unregister` instead of
  leaking the entry. Auto-wired through the
  `TRANSPORT_PLUGIN` macro.

- **WebSocket transport** — `goodnet_transport_ws.so` registers
  `ws://` and the `gn.transport.ws` extension via the
  `TRANSPORT_PLUGIN` macro. RFC 6455 §5 binary framing with FIN
  / opcode / mask handling, RFC 6455 §1.3 upgrade handshake
  (inline SHA-1 + base64 — the algorithms the spec hard-codes,
  not a security primitive: identity / Noise lives above the
  transport). Self-contained TCP socket; full `wss://` support
  rides on top once the `gn.transport.tls` composer plugin
  ships.
- **Backpressure watermark events** — every baseline transport now
  publishes `GN_CONN_EVENT_BACKPRESSURE_SOFT` once a connection's
  write queue crosses `pending_queue_bytes_high`, and
  `GN_CONN_EVENT_BACKPRESSURE_CLEAR` when it drops below
  `pending_queue_bytes_low`. Per-Session `soft_signaled_` atomic
  enforces the rising / falling edge model from
  `backpressure.md` §3, so a queue oscillating inside the
  hysteresis band never floods the channel. The publisher slot
  is the new `host_api->notify_backpressure(conn, kind, bytes)`,
  guarded by the kind-based transport role gate so only
  transport plugins can emit. SDK_VERSION_MINOR → 1.6.
- **Backpressure hard cap** — TCP / IPC / WS / TLS transports now
  refuse fresh sends once the per-connection write queue holds
  more than `gn_limits_t::pending_queue_bytes_hard` bytes per
  `backpressure.md` §3. Each Session carries an atomic
  `bytes_buffered_` counter incremented on enqueue, drained on
  the matching `async_write` completion. `host_api->send` /
  `send_batch` return `GN_ERR_LIMIT_REACHED` past the cap; the
  producer back-pressures by retrying after the
  `BACKPRESSURE_CLEAR` event (§5.C.2 wires the watermark
  publishers). A `pending_queue_bytes_hard` of zero leaves
  enforcement off, matching the v1.0 baseline behaviour for
  out-of-process kernel embeddings that have not yet wired
  their limits.
- **Per-connection counters** — `ConnectionRegistry` now owns an
  `AtomicCounters` block alongside each record (bytes_in /
  bytes_out / frames_in / frames_out / pending_queue_bytes /
  last_rtt_us). `host_api->notify_inbound_bytes` folds into
  `add_inbound`, `host_api->send` into `add_outbound`,
  `notify_backpressure` into `set_pending_bytes`. `find_by_id`
  reads the atomics into the snapshot under the same shared
  shard lock, so `find_by_uri` / `find_by_pk` surface the same
  counters through every alternate index. Counters are allocated
  on `insert_with_index`, reaped on `erase_with_index`; calls on
  a missing id are silent no-ops to absorb teardown races.
- **Handshake-phase pending queue** — `host_api->send` no longer
  rejects application data while the connection's
  `SecuritySession` is in `Handshake`. Each framed plaintext is
  buffered on the session's pending queue (per
  `backpressure.md` §8), capped at
  `gn_limits_t::pending_handshake_bytes` (default 256 KiB,
  `GN_ERR_LIMIT_REACHED` past the cap). When `advance_handshake`
  transitions the session to `Transport` — on either the
  `kick_handshake` or `notify_inbound_bytes` path — the kernel
  encrypts every queued plaintext and pushes it through the
  resolved transport in arrival order. `SecuritySession::close`
  drops any leftover bytes; a connection that disconnects
  mid-handshake reports the loss through
  `GN_CONN_EVENT_DISCONNECTED`.
- **Connection-event observer** — `host_api->subscribe_conn_state`,
  `unsubscribe_conn_state`, `for_each_connection`. The kernel
  publishes a typed event for every observable change in
  connection lifecycle: `CONNECTED`, `DISCONNECTED`,
  `TRUST_UPGRADED` (Untrusted → Peer), and the reserved
  `BACKPRESSURE_SOFT` / `BACKPRESSURE_CLEAR` kinds for the
  send-queue layer. Subscriptions carry a weak observer of the
  caller's quiescence sentinel so a callback whose plugin
  unloaded is dropped silently. `for_each_connection` walks the
  registry under per-shard read locks. New
  `docs/contracts/conn-events.md` and `sdk/conn_events.h`.
  SDK_VERSION_MINOR bumped to 1.5.
- **Service executor** — `core/kernel/timer_registry`. The kernel
  owns a single-thread executor reserved for plugin service tasks.
  Three new `host_api` slots route to it: `set_timer` (one-shot
  callback after `delay_ms`), `cancel_timer` (idempotent), and
  `post_to_executor` (run-now task). Every scheduled entry holds
  a `weak_ptr<void>` of the calling plugin's quiescence sentinel
  (`plugin-lifetime.md` §4); a callback whose plugin already
  unloaded is dropped silently. `gn_limits_t::max_timers` and
  `max_pending_tasks` (default `4096`) cap the queue. New
  `docs/contracts/timer.md`. SDK_VERSION_MINOR bumped to 1.4.
- **TLS transport** — `goodnet_transport_tls.so` registers `tls://`
  and the `gn.transport.tls` extension. Asio-on-OpenSSL
  `ssl::stream<tcp::socket>` with TLS 1.2 minimum, sslv2/sslv3/
  tlsv1.0/tlsv1.1 disabled, no_compression. Server reads cert and
  key from kernel config (`transports.tls.cert_path` /
  `transports.tls.key_path`); client defaults to `verify_none`
  because the kernel's identity / Noise pipeline is the
  authentication gate (`security-trust.md` §3 single source).
  Capability descriptor adds `EncryptedPath`.

### Changed

- **Standalone Asio.** The networking dependency now ships as
  the `asio` package (Christopher Kohlhoff's standalone build,
  same library as Boost.Asio without the umbrella). The
  dependency closure drops Boost.System, Boost.Thread, and
  Boost.Atomic; the source compiles unchanged after a
  mechanical `boost::asio::` → `asio::` rename. Build is
  header-only end-to-end.

### Tests

475 across unit, integration, scenario, and property suites.
ASan / UBSan / TSan strict-clean.

## [0.1.0] — 2026-04-28

The bring-up release. The kernel core, the plugin C ABI, and the
canonical security crypto are in place. Real transports and the
security pipeline that drives the handshake land in v0.2.0; see
[`docs/ROADMAP.md`](docs/ROADMAP.md).

### Added

- **Kernel** — connection registry (16-shard, three indexes by id/uri/pk),
  handler / transport / security / extension registries, identity layer
  (Ed25519 keypair, two-key HKDF address derivation, attestation,
  NodeIdentity), plugin manager (`dlopen` + size-prefix vtable evolution
  + Kahn topo-sort service resolver), typed signal channel, JSON config
  loader with schema validation.
- **SDK** — C ABI plugin boundary (`gn_message_t`, `gn_endpoint_t`,
  `host_api_t`, vtable types for handler / transport / security /
  protocol), C++ convenience wrappers, ABI evolution rules
  (`abi-evolution.md`).
- **Crypto** — full Noise XX and IK state machines on libsodium
  primitives: X25519 (`crypto_scalarmult`), ChaCha20-Poly1305 IETF AEAD,
  BLAKE2b, RFC-2104 HMAC-BLAKE2b, Noise §4.3 HKDF. CipherState,
  SymmetricState, HandshakeState (XX + IK pattern progression),
  TransportState with §4 atomic rekey.
- **Reference plugins** — null security provider (loopback /
  debug pass-through), GNET protocol v1 (mandatory mesh framing,
  statically linked into the kernel).
- **Documentation** — eleven contracts in `docs/contracts/` covering the
  ABI surface end-to-end (host-api, plugin-lifetime, registry,
  protocol-layer, gnet-protocol, transport, handler-registration,
  noise-handshake, security-trust, abi-evolution, fsm-events, clock,
  limits).
- **Tests** — 304 passing: unit (configuration, identity, crypto
  primitives, handshake state, registries, plugin manager, service
  resolver, kernel router, signal channel), integration (host_api
  chain, send loopback), scenario (round-trip, disconnect), property
  (gnet wire, gnet protocol).
- **CI/CD** — five GitHub Actions jobs on every push and PR: nix flake
  check, build + test, AddressSanitizer + UBSan, ThreadSanitizer,
  strict clang-tidy on changed files.
- **Build** — Nix flake with `nix run .#build`, `nix run .#test`,
  `nix run .#test-asan`, `nix run .#test-tsan`.

### Licensing

The kernel (`core/` and the statically-linked `plugins/protocols/gnet/`)
is **GPL-2.0 with a Linking Exception**: plugins that interface only
through the stable C ABI may carry any license — MIT, BSD, Apache 2.0,
proprietary — and link statically or dynamically. SDK (`sdk/`) is MIT.
Bundled-tree convention: templates and common transports are MIT;
original implementations with no upstream analogue are Apache 2.0.

See [`LICENSE`](LICENSE) for the full text and rationale.
