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

- **`nix run .#demo` quickstart** — `examples/two_node` ships a
  single-process binary, `goodnet-demo`, that owns both ends of a
  conversation: two `Kernel` instances each with a fresh
  `NodeIdentity`, the noise security `.so` loaded through `dlopen`,
  the TCP transport listening on a 127.0.0.1 ephemeral port, and a
  message handler on Alice that prints what Bob sent. The
  `nix run .#demo` flake target configures with
  `GOODNET_BUILD_EXAMPLES=ON`, builds, and runs the binary; output
  is line-per-step so the user can read the handshake +
  round-trip without parsing logs.
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
- **Handshake-phase pending queue** — `host_api->send` buffers
  application data while the connection's `SecuritySession` is
  in `Handshake`. Each framed plaintext sits on the session's
  pending queue (per `backpressure.md` §8), capped at
  `gn_limits_t::pending_handshake_bytes` (default 256 KiB,
  `GN_ERR_LIMIT_REACHED` past the cap). The phase check, cap
  check, and queue insert all run under one mutex so a
  concurrent `advance_handshake` cannot let bytes slip into
  `pending_` after `take_pending` already drained. When
  `advance_handshake` transitions the session to `Transport` —
  on either the `kick_handshake` or `notify_inbound_bytes`
  path — the kernel resolves the transport vtable first, takes
  the queued plaintexts, encrypts each, and pushes the
  ciphertext in arrival order. A per-frame `encrypt_transport`
  failure or transport hard-cap rejection mid-drain disconnects
  the connection (the AEAD nonce has already advanced — partial
  completion is unrecoverable); the producer observes the loss
  as `GN_CONN_EVENT_DISCONNECTED`.
- **DNS resolver helper** — header-only `sdk/cpp/dns.hpp` with
  `gn::sdk::resolve_uri_host(io_context&, uri)`. Blocking
  `asio::ip::tcp::resolver` lookup on the calling thread for
  hostname inputs; IP literals and `ipc://` path-style URIs
  short-circuit. The TCP / UDP / WS / TLS transports now route
  every outbound `connect()` through the helper so the
  registry's URI index keys and the on-connect callback URI
  always carry an IP literal. Per `docs/contracts/dns.md` §1
  (new). Seven new unit tests cover IP-literal passthrough,
  IPv6 brackets, path-style URIs, query preservation,
  unparseable inputs, the `localhost` lookup, and `*.invalid`
  failure surfaces.
- **Path-optimiser plugin framework** —
  `sdk/extensions/optimizer.h` defines the `gn.optimizer.<name>`
  extension shape: a `recommend(conn)` slot that returns a
  `Replace` / `AddPath` / `Drop` recommendation for the kernel's
  `PathManager`, an `on_event(ev)` slot for connection-event
  subscriptions, and a `subscribed_events` bitmask. Reserved
  initial names (`transport-failover`, `relay-upgrade`, `ice`,
  `autonat`) lock the namespace so each plugin lands in a
  predictable slot. Per `docs/contracts/optimizer.md` (new).
  v1 ships the contract surface; the optimiser plugins
  themselves arrive on their own cadence.
- **Capability TLV codec** — `sdk/cpp/capability_tlv.hpp` ships
  a header-only encode / parse pair against the
  `[type:u16 BE][length:u16 BE][value]*` blob format described
  in `docs/contracts/capability-tlv.md` (new). Used by the
  post-Noise capability handshake — peers exchange the supported
  optimiser / transport / protocol names in a single GNET frame.
  Unknown record types are skipped on parse so the format stays
  wire-additive. Eight new unit tests cover empty round-trip,
  multi-record order, big-endian field layout, oversized-value
  rejection, truncated-header / truncated-value surfaces, and
  unknown-type tolerance.
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

- **FFI spec: subscriber failure modes (`signal-channel.md` §6).**
  `SignalChannel::subscribe` now rejects an empty `std::function`
  and returns the invalid-token sentinel; the subscriber list is
  unchanged. `SignalChannel::fire` wraps each handler invocation
  in `try/catch (...)` so a raising subscriber no longer starves
  the rest of the snapshot — the exception is captured and
  dropped. Plugin authors crossing the C ABI must catch
  internally; the kernel-side catch is a defensive net, not a
  contract that callbacks may raise. Tests cover the null-handler
  path and the multi-subscriber-with-thrower path.
- **FFI spec: kernel-side validation of plugin-provided vtables
  (`abi-evolution.md` §3a).** `TransportRegistry::register_transport`
  and `SecurityRegistry::register_provider` now reject vtables
  whose `api_size` is smaller than the minimum the kernel knows
  about; the rejection returns `GN_ERR_VERSION_MISMATCH` before
  any slot lookup. Handler vtable is fixed-shape at v1 and does
  not carry `api_size` (documented in §3a). Tests cover the
  zero-`api_size`, truncated, and exactly-minimum cases.
- **Registry-wide caps from `gn_limits_t` are now enforced
  (`limits.md` §4 + new §4a).** `ConnectionRegistry::insert_with_index`,
  `ExtensionRegistry::register_extension`, `PluginManager::load`, and
  `HandlerRegistry::register_handler` reject registrations that
  would push the live count past `max_connections`,
  `max_extensions`, `max_plugins`, and `max_handlers_per_msg_id`
  respectively. `Kernel::set_limits` wires the kernel-owned
  registries directly; `PluginManager` reads
  `kernel.limits().max_plugins` inside `load`. Cap of zero
  preserves the prior unlimited behaviour for backward
  compatibility; production configs always set non-zero values
  through the loaded `gn_limits_t`. The §4 paragraph that
  promised "every check-site reads from live `gn_limits_t`" no
  longer overpromises — the new §4a enumerates exactly which
  registries enforce which cap.
- **Registry contract honesty (`registry.md` §4).** The §4 paragraph
  that promised a deletion-generation increment on a
  `gn_endpoint_t` snapshot stream is replaced with a description
  of what the registry actually offers: `get_endpoint` returns the
  view by value, no cache-invalidation channel exists, consumers
  re-read or prune their cache on the `DISCONNECTED` event from
  `conn-events.md` §2a. The previous wording named a stream the
  kernel never exposed; the rewrite removes the lie.
- **Standalone Asio.** The networking dependency now ships as
  the `asio` package (Christopher Kohlhoff's standalone build,
  same library as Boost.Asio without the umbrella). The
  dependency closure drops Boost.System, Boost.Thread, and
  Boost.Atomic; the source compiles unchanged after a
  mechanical `boost::asio::` → `asio::` rename. Build is
  header-only end-to-end.
- **Connection registry — atomic snapshot variant
  (`registry.md` §4a).** `ConnectionRegistry` exposes a
  snapshot-and-erase primitive that captures the pre-erase
  record (the `gn_endpoint_t` view plus `§8` per-connection
  counters) and removes the entry from all three indexes
  inside one critical section. The snapshot owns its uri /
  pk bytes; kernel-side storage holds no reference past the
  call.
- **`notify_disconnect` — DISCONNECTED ordering and at-most-once
  semantics (`conn-events.md` §2a).** The thunk drops the
  security session, then runs the atomic snapshot+erase, then
  publishes one DISCONNECTED whose payload is the captured
  pre-removal record state. A call against an absent or
  already-removed id returns `GN_ERR_UNKNOWN_RECEIVER` and
  publishes nothing; concurrent calls converge on one publisher
  and the rest report unknown. Subscriber callbacks may
  re-enter `notify_disconnect` against the same conn — the
  re-entrant call observes the record gone and emits no second
  event. The `reason` parameter is reserved at v1.

### Tests

526 across unit, integration, scenario, and property suites.
ASan / UBSan / TSan / clang-tidy strict-clean. The
`ConnectionRegistry_SnapshotAndErase` suite covers the §4a
atomicity claim (cross-shard non-deadlock and
exactly-one-winner under same-id contention); the
`HostApiNotifyDisconnect` suite covers the §2a Returns table
(`GN_OK` / `GN_ERR_UNKNOWN_RECEIVER` / `GN_ERR_NULL_ARG` /
`GN_ERR_NOT_IMPLEMENTED`), the idempotent + concurrent
double-call cases, and the re-entrant-from-callback path.

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
