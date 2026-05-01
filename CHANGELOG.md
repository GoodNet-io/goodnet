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

- **Plugin logging vtable** — `host_api_t::log` is a size-prefixed
  substruct (`gn_log_api_t`) with two slots:
  `should_log(host_ctx, level)` for the hot-path level filter and
  `emit(host_ctx, level, file, line, msg)` for the fully-formatted
  buffer. Plugins format on their own stack — `sdk/convenience.h`
  exposes `gn_log_<level>(api, "fmt", args…)` macros (printf-style
  `snprintf`); `sdk/cpp/log.hpp` exposes `GN_LOGF_<level>(api,
  "{}", args…)` macros (C++23 `std::format_to_n`). Both capture
  `__FILE__`/`__LINE__` at the call site, short-circuit through
  `should_log` when the level is filtered out, and call `emit`
  with a NUL-terminated UTF-8 buffer (2048-byte cap). The kernel
  hands the buffer to its sink as a literal — no format specifier
  is interpreted on the kernel side, so a compromised plugin
  cannot smuggle `%n` writes or `%s`-without-arg dereferences
  across the C ABI. Substruct shape is gated through
  `GN_API_HAS_LOG` per `abi-evolution.md` §3a. Per
  `host-api.md` §11.
- **Kernel logger** — the named `"gn"` spdlog logger in
  `core/util/log.hpp` carries a console sink (always present)
  and an optional rotating file sink. Custom `%Q` flag renders
  the source-location prefix with four detail modes (Auto,
  FullPath, BasenameWithLine, BasenameOnly); the Auto default
  shows full path on TRACE/DEBUG and basename only on INFO+.
  Release builds (`NDEBUG`) cap the console sink at warn so a
  long-running daemon does not flood stderr with INFO chatter.
  CMake passes `-fmacro-prefix-map=${CMAKE_SOURCE_DIR}/=` so the
  rendered `__FILE__` carries repo-relative paths instead of the
  absolute build-tree location.
- **`log.*` config keys** — `level`, `file`, `max_size`,
  `max_files`, `source_detail_mode`, `project_root`,
  `strip_extension`, `console_pattern`, `file_pattern`. The
  kernel re-applies the block on every successful
  `reload_config` / `reload_config_merge` so operators flip
  detail mode, file path, or pattern without restarting.
  Schema in `config.md` §3; semantics in `host-api.md` §11.4.
- **Hot config reload** — `Kernel::reload_config(text)` and
  `reload_config_merge(overlay)` swap the live state atomically,
  propagate the new `gn_limits_t` to every kernel-owned registry
  through `set_limits`, then fire `on_config_reload` so subscribed
  plugins re-read their knobs. Plugins subscribe through
  `host_api->subscribe(GN_SUBSCRIBE_CONFIG_RELOAD, cb, ud, &id)` and
  `unsubscribe(id)`. The bundled UDP transport
  re-reads its `udp.new_conn_*` rate limiter on every reload as
  the canonical reference subscriber. A failed reload (parse or
  invariant violation) leaves the kernel state unchanged and does
  not fire the signal — every `on_config_reload` event corresponds
  to a successful state change.
- **Tuning profiles** — `server` / `embedded` / `desktop` baselines
  selected via the top-level `"profile": "..."` JSON field. The
  `limits` block overrides individual fields on top of the chosen
  baseline. Embedded shrinks every dimension (64 conns, 8 KiB
  frame, 256 timers); Desktop sits between Embedded and Server.
- **Layered config** — `Config::merge_json(overlay)` deep-merges
  per RFC 7396 so an embedding can compose
  defaults → site override → per-deploy override without
  reassembling the merged JSON itself. Atomicity carries through:
  a parse failure or invariant violation in any layer rolls back
  to the last good state.
- **Unified typed config read** — one `host_api->config_get(key,
  type, index, *out_value, *out_free)` slot covers every type and
  every shape the config tree carries: `INT64`, `BOOL`, `DOUBLE`,
  `STRING`, `ARRAY_SIZE` and indexed `INT64` / `STRING` array
  elements. The kernel rejects a type mismatch with
  `GN_ERR_INVALID_ENVELOPE` so a config drift (operator wrote a
  string where the plugin wanted an integer) surfaces at the call
  site instead of producing silent zero defaults further
  downstream. Pure-C convenience macros — `gn_config_get_string`,
  `gn_config_get_int64`, `gn_config_get_bool`, `gn_config_get_double`,
  `gn_config_get_array_size`, `gn_config_get_array_int64`,
  `gn_config_get_array_string` — expand to the LAYER-tagged call,
  so plugin code keeps the typed shape it had before. Per
  `host-api.md` §2 and `config.md` §3.
- **`Config::load_file(path)` + JSON5 comments** — the kernel itself
  remains library-linkable without a filesystem dependency, but the
  common single-binary deployment now has a one-call entry to read
  the bytes off disk. The JSON parser strips `//` and `/* */`
  comments at parse time so operators can annotate config with
  rationale without losing strict-JSON compatibility for existing
  files.
- **Inject rate limiter is configurable** — three new `gn_limits_t`
  fields (`inject_rate_per_source`, `inject_rate_burst`,
  `inject_rate_lru_cap`) replace the hard-coded constants the
  kernel previously held inside `kernel.hpp`. Operators tune the
  bridge plugin's per-source token bucket through the JSON config
  document, and `RateLimiterMap::reconfigure` propagates the new
  shape live without a kernel restart. Cross-field invariant
  rejects a burst below half the refill rate. `Config::load_json`
  now auto-validates: a parsed limits set that violates any
  invariant fails the load with `GN_ERR_LIMIT_REACHED` and rolls
  the kernel state back to the prior load. Per `limits.md` §2.

- **Counter surface for kernel and plugin metrics** —
  `host_api->emit_counter(name)` and `iterate_counters(visitor)`
  expose a flat map of named monotonic 64-bit counters. The
  router emits `route.outcome.*` for every dispatched envelope
  and the kernel surfaces `drop.*` for every `gn_drop_reason_t`;
  plugins extend the surface with their own
  `<subsystem>.<event>.<reason>` names. Wire format / scrape
  protocol live in an exporter plugin — the kernel never carries
  HTTP serving or Prometheus rendering code. New header
  `sdk/metrics.h`. Per `metrics.md` (new contract).
- **Plugin integrity manifest** — `PluginManager::set_manifest`
  installs a SHA-256 allowlist that gates every `dlopen`. An empty
  manifest is the developer-mode default (every plugin loads); a
  non-empty manifest puts the loader in production mode and rejects
  every plugin not pinned to a matching hash. Verification runs
  before `dlopen` so a tampered binary's static initialisers never
  reach the kernel. Manifest format: JSON
  `{"plugins":[{"path":...,"sha256":<64-hex>},...]}`. Streaming
  SHA-256 via libsodium, 64 KiB chunks. New error code
  `GN_ERR_INTEGRITY_FAILED`. Per `plugin-manifest.md`.
- **Cooperative cancellation for plugins** — every plugin owns a
  `PluginAnchor` carrying an in-flight counter and a
  `shutdown_requested` flag. Async dispatch sites (timer fire,
  posted task, connection-event subscriber) open each callback
  through a `GateGuard` that refuses entries published after
  rollback began, so a callback scheduled before shutdown but
  fired after is dropped without entering plugin code. Plugins
  poll the new `host_api->is_shutdown_requested(host_ctx)` slot
  from inside long-running async work and exit cooperatively
  before the kernel's drain timeout. Drain logs the in-flight
  count alongside the timeout warning, attributing leaked work to
  the misbehaving plugin. Per `plugin-lifetime.md` §4 + §8 and
  `host-api.md` §10.
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
  `link.md` §4 single-writer, IPv6 dual-stack with
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
  `NodeIdentity` plus `TcpLink` plus the Noise provider drive
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
- **`gn.link.<scheme>` extension API** — every baseline
  transport publishes `gn_link_api_t` from
  `sdk/extensions/link.h` with steady slots
  (`get_stats`, `get_capabilities`, `send`, `send_batch`,
  `close`) functional and composer slots
  (`listen`, `connect`, `subscribe_data`, `unsubscribe_data`)
  returning `GN_ERR_NOT_IMPLEMENTED` until the first
  L2-over-L1 plugin (WSS, TLS) drives them. TCP / IPC / UDP
  expose monotonic byte / frame / connection counters; UDP
  surfaces its MTU through the capability descriptor.
- **`LINK_PLUGIN(Class, "scheme")` macro** — collapses
  per-transport `plugin_entry.cpp` boilerplate (five
  `gn_plugin_*` exports, kernel-facing vtable, extension
  vtable, descriptor) into a single one-line invocation in
  `sdk/cpp/link_plugin.hpp`. Every C thunk is `noexcept`
  with a try/catch wrapper so a plugin exception never escapes
  the C ABI boundary.
- **`host_api->unregister_extension`** — paired with the
  existing `register_extension` so plugins can drop their
  extension registration on `gn_plugin_unregister` instead of
  leaking the entry. Auto-wired through the
  `LINK_PLUGIN` macro.

- **WebSocket transport** — `goodnet_link_ws.so` registers
  `ws://` and the `gn.link.ws` extension via the
  `LINK_PLUGIN` macro. RFC 6455 §5 binary framing with FIN
  / opcode / mask handling, RFC 6455 §1.3 upgrade handshake
  (inline SHA-1 + base64 — the algorithms the spec hard-codes,
  not a security primitive: identity / Noise lives above the
  transport). Self-contained TCP socket; full `wss://` support
  rides on top once the `gn.link.tls` composer plugin
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
- **Capability TLV codec** — `sdk/cpp/capability_tlv.hpp` ships
  a header-only encode / parse pair against the
  `[type:u16 BE][length:u16 BE][value]*` blob format described
  in `docs/contracts/capability-tlv.md` (new). Used by the
  post-Noise capability handshake — peers exchange the supported
  transport and protocol names in a single GNET frame.
  Unknown record types are skipped on parse so the format stays
  wire-additive. Eight new unit tests cover empty round-trip,
  multi-record order, big-endian field layout, oversized-value
  rejection, truncated-header / truncated-value surfaces, and
  unknown-type tolerance.
- **Connection-event observer** —
  `host_api->subscribe(GN_SUBSCRIBE_CONN_STATE, …)` /
  `unsubscribe(id)`, plus `for_each_connection`. The kernel
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
- **TLS transport** — `goodnet_link_tls.so` registers `tls://`
  and the `gn.link.tls` extension. Asio-on-OpenSSL
  `ssl::stream<tcp::socket>` with TLS 1.2 minimum, sslv2/sslv3/
  tlsv1.0/tlsv1.1 disabled, no_compression. Server reads cert and
  key from kernel config (`links.tls.cert_path` /
  `links.tls.key_path`); client defaults to `verify_none`
  because the kernel's identity / Noise pipeline is the
  authentication gate (`security-trust.md` §3 single source).
  Capability descriptor adds `EncryptedPath`.

### Changed

- **Naming: `transport` → `link` across the wire-byte layer.**
  The plugin family that owns wire-byte channels (TCP, UDP, IPC,
  WS, TLS) is named `link`; security providers (Noise) operate
  one envelope above. The rename touches the public C ABI
  (`gn_link_vtable_t`, `gn_link_id_t`, `gn_link_caps_t`,
  `gn_link_stats_t`, `GN_LINK_CAP_*`, `GN_PLUGIN_KIND_LINK`,
  `register_vtable(GN_REGISTER_LINK, …)` /
  `unregister_vtable(id)` on `host_api_t`), the SDK
  headers (`sdk/link.h`, `sdk/extensions/link.h`,
  `sdk/cpp/link.hpp`, `sdk/cpp/link_plugin.hpp`), the kernel
  registry (`LinkRegistry`, `LinkEntry`, `Kernel::links()`), the
  plugin tree (`plugins/links/{tcp,udp,ipc,ws,tls}/`), the
  `gn.transport.*` extension namespace (now `gn.link.*`), and the
  contract `docs/contracts/link.md`. The Noise plugin's
  Noise-protocol "transport phase" naming is preserved — that is
  the cipherstate term from the spec, not the wire-channel layer.
- **TLS and WS plugins reuse the canonical URI parser.** The
  authority parsing (host, port, IPv6 brackets, scheme stripping)
  in TLS and WS now flows through `gn::parse_uri` from
  `sdk/cpp/uri.hpp`, matching TCP/UDP/IPC. The TLS plugin no longer
  defaults the port to 443 when the URI omits it; an explicit port
  is required for connect, and listen accepts a literal `:0` for
  ephemeral allocation, matching the rest of the transport set.
  WS keeps its own path-suffix split (`/foo`) before handing the
  authority slice to the shared parser, since the WebSocket
  upgrade handshake needs the resource path.
- **TLS and WS plugins enable IPv6 dual-stack on wildcard
  listens.** A `tls://[::]:port` or `ws://[::]:port` listener
  now disables `IPV6_V6ONLY` on the underlying acceptor, so a
  v4-mapped client reaches the same socket. TCP and UDP already
  did this; the gap meant TLS and WS bound only the v6 family
  on a wildcard, dropping every v4 client. `set_option` is
  best-effort: a kernel that lacks the option (pre-Linux-3.x)
  leaves the listener v6-only and logs the refusal at debug.
- **URI parse and DNS-resolve failures uniformly return
  `GN_ERR_INVALID_ENVELOPE`.** TCP, UDP, IPC, TLS plugins now
  agree on the diagnostic for malformed URIs, unresolvable
  hostnames, and connect-side `port == 0`. Previously TCP/UDP/IPC
  returned `GN_ERR_NULL_ARG` for the same conditions while
  TLS/WS already returned `GN_ERR_INVALID_ENVELOPE`; the split
  meant a wrapper layer had to inspect the call site to know
  which fault class fired.
- **Result-code split for lookup misses
  (`sdk/types.h::gn_result_t`).** `GN_ERR_NOT_FOUND` (-14) covers
  registry id misses, config key absences, transport session
  misses, and inject-target misses across the kernel and the
  plugin tree. `GN_ERR_OUT_OF_RANGE` (-15) covers array indices
  past the array length on `config_get_array_*`.
  `GN_ERR_UNKNOWN_RECEIVER` (-4) is reserved for the
  message-routing path: a `receiver_pk` that does not match any
  local identity and has no relay loaded. The split lets a plugin
  author distinguish "key not configured" from "envelope cannot
  reach its receiver" without inspecting the call site.
- **TCP_NODELAY across stream transports.** TCP, TLS, and WS
  sessions disable Nagle on the underlying socket immediately
  after the accept and connect callbacks fire. Small framed
  messages — heartbeats, pongs, sub-MTU app envelopes — leave
  the kernel without waiting on the 200 ms coalescing timer, so
  the LAN baseline reaches the wire as the host wrote it. The
  set_option call is best-effort: a kernel that refuses the
  option leaves the connection on the default scheduler instead
  of failing the accept.
- **Per-peer device-key pinning across sessions
  (`registry.md` §8a).** ConnectionRegistry exposes
  `pin_device_pk` / `get_pinned_device_pk` /
  `clear_pinned_device_pk`. The map keys on `peer_pk` and outlives
  connection records, so a peer that disconnects and reconnects
  meets the same pin. The attestation dispatcher writes the pin on
  the first successful attestation and rejects a subsequent
  attestation that carries a different `device_pk` for the same
  peer with `GN_DROP_ATTESTATION_IDENTITY_CHANGE`. Five regression
  tests pin the API edges; an integration regression on the
  cross-session disconnect path is wired through the dispatcher.
- **PluginManager `set_manifest_required(true)` knob
  (`plugin-manifest.md` §7).** The flag turns the empty-manifest
  case into a hard error: `load` returns
  `GN_ERR_INTEGRITY_FAILED` with a diagnostic that names "manifest
  required but empty" followed by the rejected path. The dev-mode
  flow keeps the flag clear and empty-manifest loads keep working.
  The flag is bootstrap-only — the host calls
  `set_manifest_required` and `set_manifest` from the bootstrap
  thread before `load`. Two regression tests pin both edges.
- **TLS plugin: client peer-cert verification on by default.** A
  fresh `TlsLink` client verifies the peer cert against
  OpenSSL's default trust store. Operators running TLS as link
  encryption beneath Noise authentication opt out through
  `links.tls.verify_peer = false` on the kernel config; the
  transport reads the flag in `set_host_api` and flips the verify
  mode accordingly. The regression suite asserts the handshake
  fails when the client opts in (the default) and the peer
  presents a self-signed cert that chains to nothing trusted.
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
  (`abi-evolution.md` §3a).** `LinkRegistry::register_link`
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
- **Noise handshake: Ed25519↔X25519 conversion explicit
  (`noise-handshake.md` §8).** §8 now states that the address is
  an Ed25519 public key and the Noise suite's `25519` denotes
  X25519 for Diffie-Hellman; each side's static key crosses
  curves at session initialisation through the standard
  birational map (libsodium
  `crypto_sign_ed25519_pk_to_curve25519` /
  `crypto_sign_ed25519_sk_to_curve25519`), and the conversion
  lives inside the security provider. The kernel and handlers
  see only the Ed25519 representation. `identity.md` §7
  cross-reference updated to point at the curve-conversion
  paragraph rather than the file as a whole.
- **Capability TLV: `protocol-set` and `protocol-list` types
  (`capability-tlv.md` §2).** Type `0x0001` `protocol-set` is a
  bitmap of supported `gn.protocol.<name>` slugs in declaration
  order; type `0x0002` `protocol-list` carries the canonical
  UTF-8 newline-separated ordering. Generic TLV codec
  (`sdk/cpp/capability_tlv.hpp`) is unchanged; the
  category-specific encoders ride on top of it.
- **TLS plugin: minimum protocol version bumped to 1.3.** Both
  server and client SSL contexts in `plugins/links/tls/`
  now disable TLSv1.2 explicitly in addition to TLSv1.0 and
  TLSv1.1. A peer that only speaks pre-1.3 fails the handshake
  at hello rather than silently negotiating an obsolete suite.
  OpenSSL still picks TLS 1.3 cipher suites automatically; the
  minimum is enforced by exclusion. Existing loopback test
  passes — both ends negotiate 1.3.
- **Attestation gate for `Untrusted → Peer` upgrade
  (`attestation.md`, `security-trust.md` §3,
  `handler-registration.md` §2a).** Trust no longer promotes
  automatically when a Noise session reaches Transport phase.
  The kernel-internal `AttestationDispatcher` exchanges a
  232-byte payload on system msg_id `0x11` over the secured
  channel — 136-byte attestation cert (per `identity.md` §4) +
  32-byte session `handshake_hash` binding + 64-byte Ed25519
  signature pinning the cert to this session. Both peers must
  send their own and verify the other's before
  `connections.upgrade_trust` runs and
  `GN_CONN_EVENT_TRUST_UPGRADED` fires. A peer that completes
  Noise but fails to provide a valid attestation stays at
  `Untrusted`. Loopback / IntraNode connections skip the
  exchange (their trust class is final at `notify_connect`).
  The `notify_inbound_bytes` thunk intercepts `0x11` envelopes
  after the protocol layer's `deframe` step and routes them to
  the dispatcher — plugin handlers never see attestation
  traffic, and `HandlerRegistry::register_handler` rejects the
  reserved id with `GN_ERR_INVALID_ENVELOPE`. Per-step verify
  failures (size / replay / parse / signature / expiry /
  identity-change) drop the envelope, log the named reason,
  and disconnect the connection. A duplicate attestation with
  the same `device_pk` is silently dropped without disconnect
  (live re-attestation is out of scope at v1). Per-conn
  dispatcher state clears on `notify_disconnect` directly from
  the kernel thunk. The "exactly once" upgrade guarantee comes
  from the registry's `upgrade_trust` policy gate — concurrent
  callers race through the gate and the loser exits silently.
- **TLS transport wipes the override server private key per
  `noise-handshake.md` §5b.** The override storage migrates from
  `std::string` to a byte vector that the destructor and the
  reassignment path zeroise explicitly. The bytes are also wiped
  immediately after `OpenSSL` copies them into the SSL context
  during `listen()`; subsequent reassignments hit a freshly
  cleared buffer. Public material — the cert PEM — is exempt from
  the wipe rule. The regression suite asserts the observable
  flips from non-zero to zero across the listen call.
- **WebSocket transport gates every control-frame path through
  the per-connection hard cap (`backpressure.md` §3.1).** Pong
  replies to peer-initiated pings, graceful-close echoes, and
  host-initiated close frames share the same budget that
  `host_api->send` already respects. A peer flooding pings cannot
  push the local write queue past the cap — the transport
  disconnects when the next pong reply would overflow, treating
  the flood as abuse rather than amplifying the buffer. Close
  echoes and host-initiated close frames drop silently when the
  cap is already saturated; the socket teardown carries the
  closure. The regression suite simulates a 64-ping flood under a
  256-byte cap and asserts the server publishes `notify_disconnect`.
- **Noise handshake clears every secret buffer on Split
  (`noise-handshake.md` §5 clause 4).** The handshake state's
  `Split` step zeroises the long-term static private key, the
  ephemeral key pair, the peer ephemeral key, and the symmetric
  chaining key in the moment the transport ciphers are produced.
  The wipe is exception-safe: if the underlying split primitive
  throws, every secret is cleared before the exception propagates.
  Move construction and move assignment on both `HandshakeState`
  and `SymmetricState` clear the moved-from source, so a caller
  that moves a live handshake into another container leaves the
  source with empty secret buffers. The destructor stays as a
  defence-in-depth backstop; in the steady-state path it sees
  buffers already cleared.

### Tests

742 across unit, integration, scenario, and property suites.
ASan / UBSan / TSan / clang-tidy strict-clean. The
`ConnectionRegistry_SnapshotAndErase` suite covers the §4a
atomicity claim (cross-shard non-deadlock and
exactly-one-winner under same-id contention); the
`HostApiNotifyDisconnect` suite covers the §2a Returns table
(`GN_OK` / `GN_ERR_UNKNOWN_RECEIVER` / `GN_ERR_NULL_ARG` /
`GN_ERR_NOT_IMPLEMENTED`), the idempotent + concurrent
double-call cases, and the re-entrant-from-callback path.
The `AttestationDispatcher_Verify` suite pins the
`compose_payload` layout and exercises every per-step
rejection path of `verify_payload` (`BadSize`,
`BindingMismatch`, tampered cert, tampered signature, expired
cert); the `AttestationDispatcher_Mutual` suite covers the
upgrade-fires-once contract under both flags, the no-upgrade
paths under each flag alone, the `Loopback`-class no-upgrade
case, and the `on_disconnect` state-clear claim. The
`HandlerRegistry_Args.RejectsReservedAttestationMsgId` test
covers `handler-registration.md` §2a's plugin-side rejection.

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
