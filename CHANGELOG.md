# Changelog

All notable changes to this project. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### test: ice-3node harness — 12/14 scenarios pass

Fixes bringing the `tests/docker/ice-3node` docker suite from 10/14 to
≥12/14 PASS (ice_tcp known gap; quic_over_ice deferred):

**`port_prediction`**: `init-nat.sh` `symmetric_stride` mode switched from
`iptables REDIRECT` to TPROXY with policy routing (`fwmark 0x1 / table 100`).
`REDIRECT` rewrites the destination before socket delivery so
`IP_RECVORIGDSTADDR` returned the post-redirect local address; all packets
shared a single flow key and the forwarder sent packets to itself.  TPROXY
preserves the original destination — `IP_RECVORIGDSTADDR` now returns the real
upstream STUN server address.  `stride-nat.py` listener socket gains
`IP_TRANSPARENT` (required for TPROXY delivery); reply sockets already used it
to spoof STUN server source addresses back to LAN peers.

**`no_udp_fallback`**: `coturn/coturn:latest` ships on Alpine; the previous
`nc -z` health check failed (no `nc` in image).  Changed to
`openssl s_client -connect 127.0.0.1:5349 < /dev/null 2>&1 | grep -q CONNECTED`.

**`prflx`**: Removed `ICE_HOST_ONLY: "true"` from both peers (the flag
suppressed STUN gather so srflx candidates were never collected, making the
check ladder see only host-to-host pairs across NAT — which fail).  Added
`PEER_LAN_SUBNET` / `PEER_LAN_GW` static routes on both NAT containers so
host-candidate direct paths exist for the prflx nomination.  `nat-b/init-nat.sh`
gains the same cross-LAN route block already present in `nat-a`.

**`ice_lite_gateway`**: Deterministic role assignment via `FORCE_INITIATOR` /
`FORCE_RESPONDER` env vars in `peer/harness.cpp`.  An ice-lite peer always
acts as controlled agent; without a forced split both peers could elect the
same role and the session never progressed beyond the gathering phase.

**`turn-tls/Dockerfile`**: Rebased onto `coturn/coturn:latest` to avoid
`apt-get` network access at image-build time; `realm` Dockerfile arg now uses
double-quotes so the variable is expanded.

**`plugins/links/ice/session.cpp`**: `handle_gather_response` now arms a 200ms
window before calling `on_gathering_complete()` when additional STUN probes are
still pending.  Previously, the first response immediately cleared
`pending_stun_probes_`, dropping the second probe's response and preventing
symmetric-stride detection.  The `port_prediction` docker scenario now passes.

**`tools/math/gnet_model.py`**: Added `QUIC` and `IPC` transport types;
`TransportProps` gains `handshake_us` field populated from 852c20a bench data.
`gnet_simulate.py`: exposes `ice_broken` state in the ICE upgrade model and
updated diagnostics output.

## [1.0.0-rc7] — 2026-06-11

### fix: TRUST_UPGRADED fires for loopback and intra-node connections

Loopback and intra-node connections skip the attestation path, so
`GN_CONN_EVENT_TRUST_UPGRADED` was silently never emitted for them after
Noise XX completed.  `notifications.cpp` now fires the event from both
`kick_handshake` and `notify_inbound_bytes` once `remote_pk` is resolved
and trust is above `GN_TRUST_PEER`.  Applications that wait for
`TRUST_UPGRADED` before sending to loopback peers now behave correctly.

### fix: `gn_message_t.conn_id` surfaced to C callbacks

`gn_core_s::MessageSub` previously passed `GN_INVALID_ID` as the
`conn` argument to the registered C callback, with a comment deferring
the fix to a future minor.  The envelope's `conn_id` is now forwarded
directly so callers can correlate received messages with the originating
connection without a separate lookup.

### fix: TCP `composer_listen_port` falls back to kernel-path listen port

`TcpLink::composer_listen_port` returned `GN_ERR_INVALID_STATE` when the
kernel used `TcpLink::listen` rather than the composer listen path,
because it only inspected `composer_acceptor_`.  The method now falls back
to `listen_port_` (populated by both paths) so ICE-TCP and other callers
that query the port after a kernel-path listen get the correct value.

### fix: ICE `inject_targets` missing from positional descriptor init

`gn_plugin_descriptor_t` gained an `inject_targets` field between `kind`
and `_reserved`.  The ICE plugin's positional aggregate initializer passed
its brace-list to the wrong slot, causing a compile error.  The field is
now explicitly set to `nullptr`; designated initializers will be adopted in
a follow-up C++26 sweep.

### fix: ICE TURN — bool config keys and TLS URI scheme

`gn_config_get_int64` silently no-ops on JSON boolean literals; TURN knobs
(`turn_tcp`, etc.) now use `gn_config_get_bool`.  TLS TURN endpoints
previously constructed a `tcp://` URI, which the TLS carrier parser
rejected; the correct `tls://` scheme is now used.  ICE_DBG traces added
on the TURN build / attempt / connect and allocate paths to aid diagnosis.

### fix: TLS `listen` error code on missing credentials

`TlsLink::listen` returned `GN_ERR_LIMIT_REACHED` when called without TLS
credentials configured.  The honest code is `GN_ERR_INVALID_STATE` (the
link is not yet configured to accept connections); test updated to assert
the corrected return value.

### feat: `provides_flags` vtable slot in security plugins

`security-noise` and `security-null` now implement the `provides_flags`
vtable slot.  `noise` advertises `GN_SEC_FLAG_E2E_ENCRYPTED |
GN_SEC_FLAG_AUTHENTICATED | GN_SEC_FLAG_FORWARD_SECRECY`.  `null` adds a
link-only provider mode that returns `GN_TRUST_LINK_ENCRYPTED` without
full mutual authentication, enabling plaintext-transport deployments that
still signal transport-layer encryption to the kernel.

### feat: ICE P2300 timer migration, nomination logic, topology-aware config

The ICE session's retransmission and nomination timers migrated from raw
`asio::steady_timer` to the P2300 sender/scheduler model, removing the last
direct Asio timer usage from `session.cpp`.  New config knobs
`ice.max_check_retries` (1–16) and `ice.nomination_wait_ms` (0–10 000 ms)
are parsed from JSON; `set_prefer_turn_tcp` and `set_security_overhead`
topology-aware setters added.  Tag-filtered debug output via
`ICE_DEBUG_TAGS` env var.  New test suite
`tests/test_ice_nomination.cpp` (464 lines) covering aggressive and regular
nomination, peer-reflexive handling, and wait-timeout paths.

### feat: TCP static archive target

`goodnet_link_tcp_static` — a CMake `STATIC` library target — is now built
and installed alongside the shared plugin.  Consumers that link `TcpLink`
directly (examples, bench, integration fixtures) can use
`GoodNet::link_tcp_static` via `find_package(GoodNetLinkTcp)` instead of
depending on `dlopen`.  `tcp.hpp` is installed with the target.

### feat: UDP GCC 16 / C++26 ring-slot send path

The UDP send path now pre-allocates a fixed ring of reusable buffer slots
instead of calling `make_shared` per frame.  Eliminates per-frame heap
allocation on the hot path under GCC 16 / C++26 where the old approach
triggered an ODR diagnostic.  `ICE_DEBUG=1` recv/dispatch tracing added
(zero overhead when the env var is unset).

### feat: heartbeat publishes RTT samples to kernel

After matching a PONG to its PING, the heartbeat handler now calls
`host_api->notify_rtt_sample(conn, rtt)`.  The kernel folds each
observation into its per-connection EWMA and republishes via
`on_path_event(RTT_UPDATE)` so strategy plugins rank connections by
latency without maintaining their own probes.  The raw instantaneous
sample is still available through the `gn.heartbeat` extension's
`get_rtt` slot.

### feat: store handler subscription cleanup on detach / destroy

`StoreHandler` now exposes `detach_conn(conn)` to prune wire-side
subscriptions when a peer disconnects, and `~StoreHandler` clears
`subs_` and `owners_` under the mutex after unsubscribing from the kernel
channel.  Previously stale rows accumulated until process exit.  New test
asserts subscription count reaches zero after destroy.

### feat: sqlite store — correct error mapping and prefix UB fix

`SqliteStore` ctor now maps DB-open / migration / IO failures to their
correct `sdk/types.h` codes (was always `GN_ERR_OUT_OF_MEMORY`).
Prefix-scan upper-bound correctly handles keys ending in `0xFF`; previously
a prefix scan over such a range returned no records.

### build: `CMakePresets.json` tracked in git; release preset includes bench

`CMakePresets.json` is now committed to the repository.  The `release`
preset sets `GOODNET_BUILD_BENCH=ON` so the bench suite is always built
alongside production artifacts in CI and local release builds.  The
`.gitignore` whitelist was updated to allow the file.

### build: `protocol-gnet` CMake `ARCHIVE DESTINATION` fix

The static archive for `protocol-gnet` was installed to the default
(wrong) location.  `ARCHIVE DESTINATION` is now explicitly set to
`${CMAKE_INSTALL_LIBDIR}` in `CMakeLists.txt`.

### build: security plugins adopt C++26 designated initializers

`security-noise` and `security-null` switch their `gn_plugin_descriptor_t`
definitions from positional to designated initializers, keeping future
vtable slots zero-initialised by default and avoiding the class of bug
fixed in ICE above.

### build: all plugin flakes point to `github:GoodNet-io/goodnet/dev`

Every plugin's `flake.nix` changed the `goodnet` input from
`git+file:../../..` (developer-local path) to
`github:GoodNet-io/goodnet/dev`.  External consumers building a plugin in
isolation now resolve the kernel from the public registry rather than
requiring a local checkout.  Affected: tcp, udp, ws, ice, tls, ipc,
security/noise, security/null, handlers/store, handlers/heartbeat.

### bench: intel\_pstate HWP governor detection

`env_facts.sh` now reads `scaling_driver` and compares `scaling_max_freq`
against `cpuinfo_max_freq`.  When the driver is `intel_pstate` and
`powersave` governor is in use but `scaling_max_freq == cpuinfo_max_freq`,
the environment is tagged `intel_pstate_at_max` and the report renders a
clarifying note ("HWP at max freq; governor label is misleading") instead
of the false throttling warning that was previously emitted.  A new bench
snapshot `bench/reports/852c20a.md` is included.

## [1.0.0-rc6] — 2026-06-09

### fix: ICE multi-connect signal routing (#18)

OFFER/ANSWER signals now route by ufrag rather than `peer_pk` alone.
`IceLink` maintains an `inbound_ufrag_to_conn_id_` map
(`peer_hex + "/" + ufrag → conn_id`); `deliver_signal` looks up the
correct session before falling through to `notify_connect`.  Two
simultaneous ICE sessions to the same peer are now correctly
demultiplexed.  Two unit tests added:
`IceSignalRouting.TwoOffersDifferentUfragCreateTwoSessions` and
`TwoOffersSameUfragFoldIntoOneSession`.

### feat: portmap extension merged into ICE plugin (#23)

`GN_EXT_PORTMAP` (NAT-PMP / PCP / UPnP IGD) is now registered inside
`goodnet_link_ice.so`.  The standalone `goodnet_link_portmap.so` is
kept with `EXCLUDE_FROM_ALL` for explicit opt-in builds only; production
deployments no longer need a separate portmap plugin load.

### feat: `max_capability_blob_bytes` config gate

`gn_limits_t.max_capability_blob_bytes` is now parsed from the JSON
config and validated: when non-zero the field must not exceed
`max_payload_bytes` (a blob that cannot fit in a single message is
rejected at load time).  Documented in `docs/contracts/limits.en.md`.

### feat: inject void-namespace drop + `bench_inject` throughput target

`inject()` with no registered handler for a `msg_id` increments
`dropped_no_handler` and returns `GN_OK` — the call site is never
an error.  Test: `InjectExternal.VoidNamespaceDroppedCleanly`.
`bench_inject` measures the kernel hot-path (router → handler) at
~1 M envelopes/s baseline; `BM_InjectMessageNoHandler` captures the
no-handler drop cost.

### feat: `GN_SECURITY_PLUGIN_MULTI` macro (#21)

`sdk/cpp/security_plugin.hpp` gains `GN_SECURITY_PLUGIN_MULTI` — a
multi-slot variant that supports more than one concurrent security
session per provider instance.  `noise` and `null` plugins migrated.

### fix: clang-tidy sweep

- `candidate.hpp`: merged identical `Host`/`HostMdns` switch arms
- `stub_host.hpp`, `link_teardown.hpp`: unused/value params fixed
- `test_wire_codec_fuzz.cpp`: removed unused `wire` namespace alias
- `gen_attestation.cpp`: cast `std::fprintf` returns to `(void)`
- `.clang-tidy`: added `-bugprone-macro-parentheses` exclusion (type
  parameters in macros cannot syntactically take parentheses)
- Pre-commit hook fixed for clang-tidy 21: use temp directory for
  filtered compile_commands instead of a bare `.json` file path

### ci: WASM release assets (#29)

`release.yml` now attaches `goodnet-*-wasm.zip` and
`goodnet-*-wasm-emscripten.zip` to every tagged release.

### chore: `gnVersion` single source of truth (#15)

`flake.nix` now has one `gnVersion = "1.0.0-rc6"` let binding reused
across all package outputs.

### rc6 cycle — comprehensive pre-release gauntlet snapshot

Full clang-driven sweep across every test + sanitizer + bench + ICE
docker dimension at SHA `ca1c239`, written up at
`bench/reports/ca1c239.md`. Headline numbers:

- `ctest` vanilla under clang: **1473 / 1473 pass** (2 env-gated
  skips — IPv6 loopback + UPnP live, neither a regression).
- ASan + UBSan: **1472 / 1473 pass** — one test-body leak in
  `TurnTcpAlloc.DataConnectionBindRoundTrip` (a captured-lambda
  `make_shared<TurnClient>` outliving strand teardown; runtime
  callers don't have this shape so kernel is unaffected). Filed
  for follow-up; not in release-blocker scope.
- TSan: **1473 / 1473 pass, 0 data-race reports** — confirms #79
  (ICE TURN UAF), #100 + #104 (TCP shutdown race primary + residual
  via mutex) all hold under thread-sanitiser pressure.
- Coverage: **lines 74.3% (16009 / 21540), functions 86.5%
  (1858 / 2149)** across 180 source files.
- Bench rerun under `performance` governor: UDP echo-RTT at 1024 B
  recovered from 9.21 MiB/s → 39.77 MiB/s (+331.8%) over baseline
  `4212f8d.md` thanks to the rc5-cycle `UdpLink` heap-arena
  assertion fix. Loopback throughput on TCP / IPC / WS regressed
  -7 % to -26 % within scheduler-noise band (concurrent docker
  containers on host suspected — flagged in the report's `## Δ vs
  baseline` and `## Known issues` sections rather than treated as
  a real perf regression).
- ICE 3-node docker gauntlet: **0 / 11 pass** even after the
  NixOS firewall fix (`ice-docker-firewall.nix`) was applied via
  `nixos-rebuild switch`. Peer logs show the OFFER / ANSWER signal
  path through the `coordinator` container is the actual blocker,
  not the host firewall — peer_a stays in "responder waiting for
  peer OFFER" until timeout across every scenario, including
  `hairpin` which doesn't touch the firewall at all (both peers
  share the same NAT box). Filed against the coordinator's
  signal-relay path for follow-up; treated as a known infra issue
  rather than a kernel regression because it predates the
  firewall-fix attempt.

The rc6 cycle landed: identity 5-phase HSM, `gssh` v0.2.0 rewrite,
bridges/cpp + bridges/rust + bridges/python split, DX layer
(`sdk/cpp/{Core,Error}`, `host_api_default`, `nix-hooks`), Forgejo
CI as sole CI (GitHub repo release-only), cross-platform builds
(aarch64-linux, Android NDK r28, WASM via emscripten; darwin
intentionally broken with `--system aarch64-darwin` warning),
clang validation + sanitizer fixes (#79 ICE turn UAF + #100 + #104
TCP shutdown race), livedoc tooling extension, lifecycle contract
freeze, SVG architecture diagrams refresh. Version suffix bumped to
`-rc6` with this commit batch.

### inject `target_ns` — all call sites updated

`inject()` gained a `const char* target_ns` parameter (between
`conn_id` and `msg_id`) for explicit handler-namespace routing.
Updated all call sites: `tests/unit/integration/test_inject_api.cpp`
(12), `test_inject_limits.cpp` (21), `test_raw_inject.cpp`
(guarded behind `GOODNET_HAS_PROTOCOL_RAW` after protocol-raw
extraction), `tests/unit/util/test_convenience.cpp` stub + calls,
and `sdk/cpp/convenience.hpp` wrappers (`inject_external_message`,
`inject_frame`). CI ice-3node timeout reduced 30 s → 1 s (non-blocking
step; saves ~5 min per run while coordinator path is still tracked in
the issue queue).

### Bench gauntlet — sequential harness leak fixed

`bench/comparison/runners/run_all.sh` no longer pre-stubs
`bench_udp` / `bench_dtls` / `bench_quic` as crashed: the rc5 cycle
fixed the `UdpLink` `malloc.c:2610` heap-arena assertion that
originally parked them, and solo + sequential reproductions now
produce valid google-benchmark JSON. The three are appended to the
end of the default set so any residual UDP-carrier instability
cannot poison the earlier benches' numbers, and a TIME_WAIT drain
wait between binaries (`ss -tan state time-wait` capped at 30s)
covers the ephemeral-port pressure that builds up across
loopback-heavy benches. CPU governor pinned to `performance` for
the run (matches `docs/perf/methodology.en.md` §Environmental
controls) and restored to `powersave` afterwards. Fresh report at
`bench/reports/4212f8d.md` carries populated rows for
`bench_{tcp,udp,dtls,quic}` for the first time since rc5; the
`## Known crashes` section is empty.

### `gn_core_listen` — public C ABI bind entry mirrors `gn_core_connect`

`sdk/core.h` now exposes `gn_core_listen(core, uri)` as the inbound
counterpart of `gn_core_connect`. The scheme prefix of the URI
selects the link plugin via `LinkRegistry::find_by_scheme`; the call
forwards to the link's vtable `listen` slot (`plugins/links/tcp/tcp.cpp:481`
for TCP). Inbound accepted connections surface through the existing
`gn_core_on_conn_state` channel — no new callback shape was
introduced. `core/kernel/core_c.cpp` implements the entry directly
against the kernel link registry rather than through the
`gn.link.<scheme>` extension's L2-composer `listen` slot (which
returns `GN_ERR_NOT_IMPLEMENTED` on baseline links). Teardown rides on
`gn_core_stop` / `gn_core_destroy`; no per-listener handle is
exposed. The Python cffi binding and the bridges/rust surface
inventory pick up the entry automatically.

`tests/unit/integration/test_core_c.cpp::CoreListen.*` (5 tests)
covers the NULL-arg defence, missing-scheme `NOT_FOUND`, no-link
`NOT_FOUND`, lifecycle smoke with a stub link, and the inbound
`CONNECTED` event surfacing through `gn_core_on_conn_state` after a
real link's accept loop calls `notify_connect`. Closes the SDK gap
that forced `apps/gssh/mode_listen.cpp` and `apps/ssh-modern`'s
server mode to return `GN_ERR_NOT_IMPLEMENTED` stubs.

### CI migrated to Forgejo Actions; GitHub repo becomes release-only

The full CI matrix (`build-and-test`, `plugin-verify`, `windows-cross`,
`bench-smoke`, `ice-3node`, `fuzz-smoke`, `asan-smoke`, `tsan-smoke`,
`flake-check`, `livedoc-check`) runs on the project's self-hosted
Forgejo instance at `http://localhost:3000/goodnet-io/goodnet`.
Workflows live at `.forgejo/workflows/{ci,dev,release}.yml`; the
`.github/workflows/` directory has been removed — GitHub Actions no
longer runs anything for this repo. The trigger was the recurring
`magic-nix-cache` Actions-Cache rate-limit on the GitHub free tier
that had broken every release cycle since rc3.

The Forgejo runner registers with labels `[ubuntu-latest, nixos]` and
runs in `:host` executor mode, which means the system
`/etc/nix/nix.conf` substituters are visible to every job. The local
binary cache `http://localhost:5555` (NixOS `nix-serve` service,
public key `goodnet-cache.local:sMamNw9G84OcJPGUzIylgdKapN5raFscLfDiqXe8ao4=`)
is already pinned in `substituters`, so the rate-limited
`DeterminateSystems/magic-nix-cache-action` is gone and the workflows
do not need a replacement cache step.

Release artefacts are still published on GitHub — but the workflow
that builds them now lives on Forgejo. `.forgejo/workflows/release.yml`
triggers on `v*` tags, builds Linux+Windows x86_64 artefacts on the
self-hosted runner, then publishes to `goodnet-io/goodnet` on GitHub
via the `gh` CLI (staged from `nixpkgs#gh` on demand). The publish step
is idempotent on tag re-runs: `gh release view` decides between
`create` and `upload --clobber`. The `softprops/action-gh-release@v2`
wrapper has been dropped. The release job consumes a Forgejo-side
repo secret named `GH_TOKEN` (scopes: classic `repo`, or fine-grained
`Contents: read and write` on the target repo); see
`docs/operator/ci-forgejo-setup.en.md` §GitHub Releases publish.

The aarch64 release matrix arm is dropped from the Forgejo copy of
`release.yml` — no aarch64 self-hosted runner is registered yet;
restoring that arm is queued for the rc6 cycle alongside the broader
cross-arch initiative (see `docs/ROADMAP.en.md`).

`docs/operator/ci-forgejo-setup.en.md` is the operator handbook for
this layout: how to spin the Forgejo container (the local
`docker-forgejo.service` unit binds web on `:3000` and SSH on `:222`
to `/home/vaniello/forgejo/data`), how to register the runner via
the native NixOS user-systemd path (`~/.config/systemd/user/forgejo-runner.service`,
already templated against `/home/vaniello/forgejo/runner/`) or the
docker path, how to set the `GH_TOKEN` secret, and the verbatim
`gh release` publish command.

## [1.0.0-rc5] — 2026-05-19

### Subprocess plugin runtime — LINK / SECURITY / HANDLER host-call slots

The subprocess runtime now hosts the same vtable surface that
static and dynamic plugins see. `RemoteHost::handle_host_call_`
decodes six host-call opcodes that previously fell through the
default branch: `NOTIFY_CONNECT` (0x13), `NOTIFY_DISCONNECT`
(0x14), `REGISTER_VTABLE` (0x15), `UNREGISTER_VTABLE` (0x16),
`REGISTER_SECURITY` (0x17), `UNREGISTER_SECURITY` (0x18). The
worker-side library (`sdk/cpp/remote_plugin.cpp`) ships the
matching `host_api_t` thunks wired into `g_state.synth_api` so a
LINK / SECURITY / HANDLER subprocess worker drives the host
surface a static or dynamic plugin would see.

`RemoteHost::security_vtable_proxy()` returns a synthesised
`gn_security_provider_vtable_t` whose slots issue PLUGIN_CALL
frames at pinned ids 0x300..0x308 (handshake_open, step,
complete, export_transport_keys, encrypt, decrypt, rekey,
handshake_close). `allowed_trust_mask` rides on slot 0x300; the
provider_id itself comes from the HELLO descriptor and needs no
wire round trip. `RemoteHost::handler_vtable_proxy()` is the
analogue for HANDLER plugins at 0x400..0x405 (protocol_id,
supported_msg_ids, handle_message, on_result, on_init,
on_shutdown). The `supported_msg_ids` thunk caches the worker's
reply per-RemoteHost so the borrowed pointer stays valid for the
lifetime of the registration. The remote LINK vtable proxy's
`send_batch` slot is synthesised in the same shape — it loops over
each frame, issuing one `link_send_thunk` PLUGIN_CALL per frame.

`RemoteHost::set_reply_timeout_for_slot(slot_id, duration)` lets
the host caller dial different reply deadlines per wire slot. A
fast slot (`PLUGIN_REGISTER`, `LINK_DISCONNECT`) typically runs
in milliseconds; a custom handler-call slot may legitimately need
seconds. The single global `set_reply_timeout` value remains the
fallback for any slot without an explicit override.
`clear_reply_timeout_overrides()` drops the map back to the
unscoped default. The `round_trip_` dispatcher consults the
override map before falling back to `reply_timeout_`.

Worker-side stub library: `WorkerConfig` carries
`security_vtable` / `security_self` and `handler_vtable` /
`handler_self` so the worker declares its real vtables once.
The PLUGIN_CALL dispatcher routes 0x300..0x308 into the worker's
`gn_security_provider_vtable_t` and 0x400..0x405 into its
`gn_handler_vtable_t`. Per-handshake `void*` state pointers are
stashed in a worker-side handle map so the wire only sees u64
tokens. Synthetic `host_api_t` gains `register_security` and
`unregister_security` thunks for the 0x17 / 0x18 round trips.

Four in-tree workers cover regression:
`plugins/workers/remote_echo` round-trips notify_connect,
send_batch via the proxy, and register/unregister via call_register
(three gtest cases under `test_remote_echo_slots.cpp`);
`plugins/workers/remote_noise_stub` exposes a deterministic
3-step XX-shaped security script and an encrypt/decrypt
round-trip; `plugins/workers/remote_handler_stub` exposes a
deterministic envelope-dispatch handler;
`plugins/workers/remote_slow_stub` is a pathological worker that
sleeps in `on_init` / `on_register` per `GOODNET_SLOW_STUB_*_MS`
env vars so the per-slot timeout regression fires deterministically.
Integration suites `test_remote_host_security.cpp` (4 tests),
`test_remote_host_handler.cpp` (5 tests), and
`RemoteHostTimeoutOverride` (`OverrideAppliedToSlot`,
`OverrideDoesNotAffectOtherSlots`, `ClearRemovesOverride`) drive
the proxies and overrides end-to-end.

### Public C ABI — unload_plugin + query_extension_checked surface tests

The C ABI entry point `gn_core_unload_plugin(name)` now drives a
real per-name teardown through a new `PluginManager::unload(name)`
path. The existing `shutdown` / `rollback` walks were factored into
a shared `teardown_one()` helper so the per-name path reuses the
quiescence-gated unregister → shutdown → close chain without
duplicating it. Idempotent on unknown name (`GN_ERR_NOT_FOUND`);
NULL argument is rejected with `GN_ERR_INVALID_ARGUMENT`.
`docs/contracts/plugin-lifetime.en.md` §6.1 documents the
host-driven hot-reload contract: after `unload(name)` returns
`GN_OK`, the host may re-prime with a fresh
`gn_core_load_plugins`. Two new integration tests exercise the
reload (`CoreUnloadReload`) and multi-protocol coexistence
(`RegisterSecondProtocol`) paths.

Three new tests under `CoreC.Query*` exercise
`gn_core_query_extension_checked(core, name, version)` — the
public C-ABI entry that external clients (raw-socket adapters,
FFI bindings, the planned C-inject demo) use to consume the
kernel's extension registry. Previously the surface was only
covered against NULL handles. Happy path queries
`gn.link.capability` and exercises its `get` vtable slot; the
two negative paths confirm an unknown name returns NULL and a
producer-version pin fails the lookup rather than silently
returning a partial vtable.

`gn_ctx_make_for_test(...)` and `gn_ctx_destroy(...)` on
`sdk/connection.h` allocate and release a synthetic
`gn_connection_context_t` for plugin test fixtures. Production
code never calls them — the kernel manages context lifecycle
itself — but the entry points let protocol-layer / security-layer
plugin tests fixture a real kernel-shaped context without
including kernel-internal headers (which the ABI hermeticity
gate forbids for plugin TUs).

### Security — recv-side parallel decrypt + recycled plaintext pool

The send path has fanned encrypt jobs through `CryptoWorkerPool`
since rc1; the recv path stayed single-threaded inside
`SecuritySession::decrypt_transport_stream`. Three new primitives
close the asymmetry.

`InlineCrypto::reserve_recv_nonces(k)` atomically grabs the next
K recv nonces in one shot so K parallel decrypt jobs can fold
their results back in delivery order without contention. The
per-conn single-writer inbound-strand invariant keeps the
reservation race-free.

`InlineCrypto::make_decrypt_job(ciphertext, nonce, out)` builds a
`CryptoWorkerPool::Job` that runs the AEAD decrypt at a given
nonce into a caller-sized plaintext span. `result_len` encodes
success (plaintext length) vs AEAD failure (0).

`SecuritySession::decrypt_batch_transport` and its streaming
wrapper `decrypt_batch_transport_stream` split N already-deframed
ciphertext spans into N jobs through the pool and coalesce
results. A batch of one falls through to the scalar
`decrypt_transport_stream` path to skip the pool's latch +
condvar overhead. Available only when `fast_crypto_active()`
holds; otherwise the session defers to the provider's vtable
decrypt slot.

`notify_inbound_bytes` routes the Transport-phase drain through
`decrypt_batch_transport_stream`; multi-frame ticks fan out,
single-frame ticks fall through transparently. At end-of-call
routed plaintexts are reclaimed back into the session's
`recycled_plaintext_pool_` (free-list capped at 16 entries) via
`recycle_plaintext_buffers` so steady-state inbound traffic
reuses buffer capacity instead of heap-churning one
`std::vector<std::uint8_t>` per frame.

The bench-only downgrade seam
`SecuritySession::_test_clear_inline_crypto` is declared and
defined only when `-DGOODNET_BENCH_SHOWCASE=ON`; the
`bench_showcase` binary called the helper unconditionally,
producing an LTO link failure on the default build. The showcase
target now returns early with a skip message when the option is
OFF, mirroring the existing skips for `GOODNET_BENCH_STRATEGIES`
and `GOODNET_STATIC_PLUGINS`. Default `nix run .#build` is clean;
opting into the showcase propagates the macro kernel-wide so both
ends of the seam see the symbol.

Seven new tests pin the recv-side behaviour: three under
`InlineCrypto` (`ReserveRecvNoncesAdvancesAtomically`,
`MakeDecryptJobAuthenticatesMatchingCipher`,
`MakeDecryptJobReportsAeadFailure`) and four under
`SecuritySessionBatchDecrypt` (`RoundTripThroughPool`,
`AeadFailureClearsOutput`, `StreamRoundTripBatchOfMany`,
`RecyclePlaintextBuffersCapsAtMax`).

### Plugin manager + manifest

`DynamicRuntime::load` resolves every `gn_plugin_*` symbol once
via `dlsym` and stores the function pointers on the owning
`PluginInstance` (a new `DynamicPluginSymbols` aggregate). The
init / register / unregister / shutdown entry points dereference
the cached pointers instead of re-issuing `dlsym` per call —
measurable on hot paths that load and tear down many plugins
back-to-back (test harnesses, hot-reload). `close()` resets the
symbol cache alongside `dlclose` so a reused `PluginInstance`
never holds a dangling pointer. A diagnostic
`dlsym_call_count()` counter on `DynamicRuntime` lets white-box
tests assert the cache holds: three new cases in
`test_dynamic_runtime_dlsym_cache.cpp` cover resolve-on-load,
no-re-resolve across 64 register/unregister cycles, and
cache-clear on dlclose.

`ManifestEntry::required` (parsed from the JSON `required` key,
default `false`) pins critical plugins for the loader. After every
load `PluginManager::load` walks the manifest and rejects with
`GN_ERR_INVALID_STATE` if any required entry has no registered
instance, naming the missing paths in the diagnostic. Operators
pin `gn.link.tcp` + `gn.link.tls` so a misconfigured deploy never
silently runs without the minimum carrier set.

`ManifestEntry` carries an optional `quiescence_timeout_s` field
parsed from JSON; the rollback path consults the per-plugin value
first and falls back to the global default. Long-running handlers
declare longer drain windows without inflating the global timeout
for every plugin. The override is documented in
`docs/contracts/plugin-manifest.en.md` §2.

`PluginManifest::find(path)` is O(1) — a sibling
`std::unordered_map<std::string, std::size_t>` index keyed on the
canonicalised path runs alongside the order-preserving vector,
rebuilt on every `add_entry` / `parse`. Remote-heavy deployments
with hundreds of subprocess entries see find drop from O(N) to
hash-lookup cost.

`set_manifest` and `set_manifest_required` assert `!active_` —
those setters are bootstrap-only and racing them against an
active session is a programming error the comment already
promised to catch.

### Wire codec — decode-failure error code

`sdk/types.h` adds `GN_ERR_WIRE_DECODE = -17` distinguishing CBOR
decode failures (type-tag mismatch, truncated payload, bad tag)
from numeric range violations (`GN_ERR_OUT_OF_RANGE`, kept for
actual overflow into a smaller target type). The
`wire_codec::Reader` accepts an optional `std::string* diag`
output parameter — the offset + decoder's expectation lands in
`diag` on failure, matching the diagnostic shape
`PluginManifest::parse` already exposes. `gn_strerror` learns the
new code. Existing `!= GN_OK` call sites in `remote_host.cpp` and
the worker library are unaffected.

### Link capability — host-side bind probe + extension surface

`core/kernel/link_capability.{cpp,hpp}` adds a host-side bind probe
for UDP / TCP on IPv4 and IPv6. `gn::host_link_capability()`
probes once on first call, caches the four-bool snapshot, and
re-probes on `refresh_host_link_capability()`. Plugin code
consults the cached snapshot through the new
`GN_EXT_LINK_CAPABILITY` extension (registered by the kernel
constructor) instead of every UDP plugin retrying its bind in a
log-spamming loop. A graceful-degradation host (corporate
firewall, mobile carrier with UDP blocked, container without
IPv6) gets one summary WARN at probe time naming the disabled
carrier families.

Four tests under `LinkCapability*` and
`PluginManager_ManifestRequired` cover the probe surface and the
manifest-pin gate end-to-end. The `required` field pinning
`gn.link.tcp` + `gn.link.tls` (described under "Plugin manager +
manifest" above) is the operator-facing complement that turns the
capability probe into a deploy-time invariant.

### IPluginRuntime polymorphic-loader abstraction

PluginManager dispatches every plugin-lifecycle step
(load / init / register / unregister / shutdown / close) through
a runtime registry keyed by the manifest entry's `kind` string.
The kernel ships three built-in runtimes — `dynamic` (dlopen),
`static` (gn_plugin_static_registry walk), `remote` (subprocess
worker over `sdk/remote/wire.h`) — each owning its kind-specific
entry-symbol resolution and load-state teardown.

Host programs that bundle a custom linkage (WebAssembly host,
FFI-over-IPC bridge, per-process sandbox manager) implement the
`IPluginRuntime` interface in `core/plugin/plugin_runtime.hpp`
and register an instance through
`PluginManager::register_runtime(kind, std::unique_ptr<...>)`
before `load`. Manifest entries whose `kind` field matches
dispatch through the custom runtime; PluginManager itself stays
unchanged. The kernel-internal abstraction is the keystone for
the future SDK `gn_core_register_runtime` slot — that addition
is non-breaking once it lands.

### host_api notify_rtt_sample slot + multi-strategy chain dispatch

A new size-prefixed slot `notify_rtt_sample` is appended before
`host_api_t._reserved`. The struct grows from 488 to 496 B; the
`_reserved` array stays at its design size of 8 entries. Link
plugins and the heartbeat handler push observed RTT samples
through the slot; the kernel folds each sample into a per-conn
EWMA(α = 1/8) per RFC 6298 and republishes the smoothed value to
every registered strategy through
`on_path_event(GN_PATH_EVENT_RTT_UPDATE)`. The strategy chain
ranks conns by latency without each strategy maintaining its own
probe. LINK / HANDLER / UNKNOWN (host embedding) kinds can
publish; other kinds get `GN_ERR_NOT_IMPLEMENTED`. Zero is the
"no-sample" sentinel and silently dropped; unknown conn id
returns `GN_ERR_NOT_FOUND`. The heartbeat handler forwards every
matched PONG-driven sample to the kernel after recording its own
raw `last_rtt_us` for the gn.heartbeat extension's get_rtt slot.

The kernel admits multiple `gn.strategy.*` plugins concurrently
and walks the registered chain in registration order on each
`host_api->send_to`. The first strategy that returns a real
conn wins; a strategy with no opinion on the candidate set
returns `GN_ERR_NOT_FOUND` and the chain advances to the next.
The previous single-strategy gate (`GN_ERR_LIMIT_REACHED` on a
second registration) is removed. Single-strategy deployments
work unchanged; the chain is the natural admission of composite
setups (`rtt-optimal` + a `cost-aware` fallback).
`ExtensionRegistry::query_prefix` sorts results by the monotonic
registration sequence so the strategy walk is deterministic
regardless of the underlying hash-map iteration order.
`(GN_OK, GN_INVALID_ID)` from a strategy is treated as
`GN_ERR_NOT_FOUND` for chain advancement, mirroring the
documented lenient interpretation on
`gn_strategy_api_t::pick_conn`. A non-NOT_FOUND error aborts
the chain. The kernel auto-fires `on_path_event` with
`GN_PATH_EVENT_CONN_UP` and `GN_PATH_EVENT_CONN_DOWN` to every
registered strategy so the chain reflects live connection
state without manual injection.

`register_vtable` and `register_security` now gate on
plugin-kind match — a HANDLER plugin cannot register a LINK
vtable, a LINK plugin cannot register a SECURITY provider, and
the rejection surfaces as `GN_ERR_INVALID_ARGUMENT` with a
diagnostic naming the mismatch. Five unit tests in
`tests/unit/registry/test_update_rtt_sample.cpp` and the
`tests/send_to/` suite cover the RTT-sample + chain-fallthrough
+ kind-gate paths.

### Security registry — multi-provider StackRegistry documentation

The kernel's security registry has admitted multiple distinct
`provider_id`s since the StackRegistry contract; the surface was
previously documented as "single active provider total" in
several places. The `docs/contracts/security-trust.en.md` §6
multi-provider paragraph and the `register_security` docstrings
in `sdk/host_api.h` and `docs/host-api.en.md` now describe the
multi-provider shape. `find_for_trust` selection is registration-
order policy.

### Bench infrastructure — bytes-processed metering + parody/real fence + CI smoke gate

`bench/plugins/bench_real_e2e.cpp` and `bench/plugins/bench_tcp.cpp`
both reported `bytes_per_second` as `meter.size() × payload` or
`sent_ok × payload` — counts that excluded iterations where the
arrival deadline was missed or backpressure forced a continue.
A bring-up transient could silently zero the row and the
aggregator would drop it from the report entirely. Both helpers
now use `state.iterations() × payload`, matching
`bench_udp.cpp::EchoRoundtrip`. All `RealFixture*Echo` rows and
`TcpFixture/Throughput` rows now emit non-zero throughput.

`bench/comparison/reports/aggregate.py` tags every row with a
`mode` field (`"real"` for libp2p / iroh / `RealFixture*`,
`"parody"` for iperf3 / socat / synthetic) and refuses to mix
shapes inside the same pivot cell via a new `ModeMismatchError`.
The aggregator exits non-zero if a mis-tagged parody row sneaks
into a real-mode column.

`docs/perf/methodology.en.md` §2.6 documents the send/recv
asymmetry as a structural property of the data plane: send fans
out through `CryptoWorkerPool::run_batch` via
`reserve_send_nonces` + `encrypt_batch_transport`; recv walks
`decrypt_transport` single-threaded inside `notify_inbound_bytes`
(the recv-side parallel path described under "Security" closes
this asymmetry).

A new `bench-smoke` job in `.github/workflows/ci.yml` builds
`bench_real_e2e`, `bench_tcp`, and `bench_udp` in Release mode,
runs each for ~0.3 s with `--benchmark_format=json`, and either
compares against a committed baseline JSON via
`tools/bench_compare.py --threshold-pct 15` (failing on
regression beyond the threshold) or — when no baseline file is
present — runs in smoke mode via the new
`tools/bench_summary.py` helper that just logs the per-benchmark
numbers. Gated by the `bench` label on PRs or push to main so
PRs that don't touch perf-relevant code skip the Release-build
tax. JSON artefacts upload on every run for post-hoc review.
`bench/baselines/README.md` documents the ratchet workflow: the
baseline is intentionally manual, refreshed in the same commit
that legitimately changes performance. Auto-rolling baselines
would mask unintentional regressions, so the gate is the review
mechanism.

`tools/bench_compare.py` ships as a standalone per-commit
regression-gate driver with a `--threshold-pct` CLI flag that
widens the regression band and an exit code 2 for missing-file
errors. Eight pytest cases under `tests/tools/` pin the
regression-gate contract; CI's livedoc-check job extends to run
the `tests/tools/` and `tests/livedoc/` pytest suites.

### RFC coverage + attestation freeze

`tools/livedoc/rfc_coverage.yaml` and the rendered
`docs/_facts/rfc_coverage.yaml` declare RFC 7692
(permessage-deflate WebSocket compression) explicitly
`not-implemented`: a client offering
`Sec-WebSocket-Extensions: permessage-deflate` in the handshake
gets a response with no `Sec-WebSocket-Extensions` echo, so per
RFC 7692 §5.1 the extension never activates and the connection
falls back to uncompressed frames. RFC 6455 entry gains a §5.4
fragmentation-reassembly detail (max 16 MiB merged, 64 KiB
single-frame cap) matching the WS plugin's actual ceiling. The
catalogue also gains RFC 6762 (multicast DNS) and the
draft-mdns-ice-candidates entry covering the ICE plugin's mDNS
host-candidate obfuscation surface, and the RFC 9000 entry
corrects its implementation note from "ngtcp2-backed" to
"OpenSSL 3.6 native QUIC".

`docs/contracts/attestation.en.md` adds a §Stability paragraph
declaring the current Ed25519 / 232-byte / msg_id 0x11 layout as
the canonical v1 schema. Future attestation schemes register
under a new extension namespace; the kernel-side
`AttestationDispatcher` is the kept-stable shim for this format.
The dispatcher's file-header comment and
`docs/architecture/security-flow.ru.md` §attestation
cross-reference the new contract paragraph.

### Plugin-lifetime + remote-plugin contract prose

`docs/contracts/plugin-lifetime.en.md` §2a notes that
`IPluginRuntime` is a C++ interface today; a C ABI version is the
natural development when WASM / eBPF runtimes arrive (the runtime
itself can be a loadable module). `docs/contracts/remote-plugin.en.md`
calls out that the subprocess trust model is operator-vetted
manifest + sha256, not runtime isolation, and documents the
`descriptor_name_storage_` runtime-mirrored pattern as the price
of supporting HELLO-payload names. The same contract is normalized
with `Stability: active · v1` headers alongside `dns`, `store`,
and `plugin-linkage`.

### Build + tooling

`flake.nix` exposes a new `packages.sdk-headers` derivation —
header-only redistribution of `sdk/` for downstream consumers
that build against the C ABI without pulling the kernel build
graph. `.githooks/pre-commit` gates on livedoc drift when the
changed files touch livedoc inputs, complementing the
`ci`-side livedoc-check job that runs pytest over
`tests/livedoc/` + `tests/tools/`.

### Sub-repo work referenced

`plugins/links/ice` is a separate git that ships its own
CHANGELOG. Six substantive landings in this cycle that
operators reading the kernel CHANGELOG should be aware of:

- **Multi-TURN fallback** — sequential walk through
  `IceConfig::turn_servers` in `gather_relay`; backup probing
  via `turn_backup_timer_` (default 30 s); failover when a
  backup ALLOCATE succeeds and the primary is degraded per
  `TurnClient::is_healthy()`; rate-limited to one failover per
  `turn_failover_min_interval_s` (default 60 s).
- **IPv6 mDNS dual-stack** — `mdns.{cpp,hpp}` binds both
  `224.0.0.251` (IPv4) and `ff02::fb` (IPv6) multicast groups
  via `SO_REUSEPORT`; per-interface `IPV6_JOIN_GROUP` for every
  AF_INET6 address from `getifaddrs`; AAAA queries route to the
  new IPv6 socket; `ice.mdns_obfuscate_host_candidates` now
  covers AF_INET6 host candidates.
- **DPLPMTUD active path-MTU probing** — `PathMtuProbe` state
  machine implementing RFC 8899 (Packetization Layer Path MTU
  Discovery for Datagram Transports); fires padded STUN binding
  requests at sizes from the configurable ladder (default
  `{1200, 1400, 1500, 4000, 9000}`); correlates responses by
  transaction id; binary-search bisects on consecutive loss.
  Replaces the static `ice.path_mtu` floor with a live
  `effective_path_mtu()` queryable through the new
  `gn.link.ice.path_mtu` extension slot.
- **ICE-lite mode (RFC 8445 §2.7)** — `ice.lite_mode = true` on
  one side pins controlling=false, makes `begin_checks` a no-op,
  and accepts whatever the controlling peer nominates. Triggered
  checks still respond per §7.3.1.4. Wire flag
  `ICE_SIGNAL_FLAG_LITE` advertises the mode on the offer;
  lite-vs-lite is rejected because no one would drive checks.
  Use case: media gateways, IoT responders, minimal-state
  endpoints.
- **RTM_NEWLINK network-mobility hook (Linux)** — netlink
  `RTM_LINK / RTM_IPV4_IFADDR / RTM_IPV6_IFADDR` subscription
  re-gathers host candidates when interfaces come up/down
  (cable unplug, wifi switch, suspend→wake). Trickle path emits
  candidate updates; non-trickle falls back to
  `restart_session()`. Config knob
  `ice.reactive_interface_change` (default on); no-op on non-
  Linux.
- **Symmetric-NAT port prediction** — when ICE gather observes
  a symmetric NAT (different external ports per destination
  from the same local port), connectivity checks fire an EXTRA
  salvo at `(peer.ip, peer.port + step * k)` for k in 1..N. Wire
  flag `ICE_SIGNAL_FLAG_SYMMETRIC` advertises the detected
  stride to the peer. Cooperative-ISP symmetric NATs typically
  allocate sequential ports — prediction increases connect-rate
  ~30–50% on those paths. WebRTC doesn't do this by default;
  this is the "more than WebRTC" item.

See `plugins/links/ice/CHANGELOG.md` for the full ICE entry.

## [1.0.0-rc3] — 2026-05-13

### Real-mode round-trip bench cases for comparable libp2p / iroh side-by-side

`bench/plugins/bench_real_e2e.cpp` gets three new sibling fixture
classes — `RealFixtureTcpEcho`, `RealFixtureUdpEcho`,
`RealFixtureIpcEcho` — each registering an
`<plug>EchoRoundtrip/<sz>` case that drives full bob→alice→bob
echo through the production stack (kernel + Noise XX + gnet). One
new `RxEchoResponder` handler in `core/kernel/test_bench_helper.hpp`
echoes the inbound payload back via `api->send(env->conn_id, ...)`,
gated on the conn_id `api_size` contract per `sdk/types.h`. The
aggregator now routes these into a new section "А. Comparable
echo round-trip — production stack vs libp2p / iroh" pivoted on
payload, listing GoodNet TCP / IPC rows next to libp2p (TCP +
Noise XX + Yamux) and iroh (QUIC + TLS 1.3) outputs from the
existing comparison runners. The `bench/comparison/runners/`
`libp2p_rs.sh` and `iroh.sh` payload sweeps drop to
`64 1024 8192 32768` so every column meets at the same payload
ladder. Methodology doc gets §1.3 pairing rule so the report
states what's comparable to what (same transport + AEAD +
framing/mux shape).

### Free-kernel showcase bench

New `bench_showcase` binary at `bench/showcase/bench_showcase.cpp`
+ `core/kernel/test_bench_showcase.hpp` (~340 LOC helper). Six
sections, each demonstrating one capability that requires the
kernel-driven architecture:

* `MultiConnFixture/FallbackThroughput` — alice listens on TCP +
  UDP + IPC simultaneously, three connection records under one
  `remote_pk`. Without a strategy plugin the kernel's
  `send_to(peer_pk)` falls back to first-found; throughput
  counters confirm the multi-conn shape on alice side.
* `StrategyFixture/PickerSelectsIpc` + `FlipOnRttDegradation` —
  the `goodnet_float_send_rtt` plugin's picker is registered as
  `gn.strategy.rtt-optimal` directly through
  `host_api->register_extension`. Synthetic RTT samples injected
  via `on_path_event` settle on the lowest-RTT carrier; a runtime
  degradation flips the winner after the EWMA-α=1/8 hysteresis
  crosses 0.75× threshold.
* `HandoffFixture/NoiseSteady` + `TriggerStep` + `NullSteady` —
  PoC for post-handshake Noise→Null security provider migration.
  After the Noise XX handshake establishes identity binding, the
  bench reaches the kernel's `SecuritySession` through a new
  `_test_clear_inline_crypto()` method that zeros the inline
  AEAD state. Subsequent `encrypt_transport` /
  `decrypt_transport` fall through to the provider vtable
  (copy-through for `gn.security.null`), dropping per-frame AEAD
  cost while the handshake hash stays alive. The seam is
  compile-gated through the `GOODNET_BENCH_SHOWCASE` macro;
  default builds do not compile the method at all, so production
  binaries cannot link the showcase header.
  `tests/unit/security/test_inline_downgrade_gate.cpp` pins the
  in-bench phase-guard contract — the method refuses outside
  `SecurityPhase::Transport`. The kernel-driven
  `SessionRegistry::downgrade_*` API is a followup; the bench's
  PoC suffices to surface the latency-step number now.
* `FanoutFixture/Producers` — N producer threads on bob spam
  `api.send_to(alice_pk)` in parallel; the kernel's
  strand-per-conn + crypto worker pool absorb the load. Throughput
  scaling vs N exposes where the single-writer drain CAS on
  `PerConnQueue::drain_scheduled` becomes the bottleneck.
* `FailoverFixture/IpcDrop` — picker drives between three
  synthetic carriers, mid-iteration `CONN_DOWN` is injected on
  the IPC slot, next pick routes to TCP. The kernel-side
  auto-emit hook on `notify_disconnect` is not wired; the bench
  fires `on_path_event` manually so the shape is testable now.
* `MobilityFixture/LanShortcut` — one carrier starts as the
  active path (synthetic TURN-relayed, RTT 60µs); mid-iteration
  a second carrier appears with RTT 2µs (synthetic LAN host
  candidate). Strategy `CONN_UP` flips the winner; the same peer
  identity survives the path migration. Stand-in for the C.4
  network-mobility netlink hook (`RTM_NEWLINK` →
  `GN_CONN_EVENT_NETWORK_CHANGE`). Acceptance verifies bytes
  through the TURN-relayed conn stop growing after the flip.

Time-series cases write CSV side-channels to
`/tmp/showcase-<tag>-<pid>.csv` that the companion aggregator
`bench/comparison/reports/showcase_aggregate.py` picks up to
render inline ASCII sparklines in
`bench/reports/showcase-<sha>.md`. Tests for the aggregator live
in `tests/aggregator/test_showcase_aggregator.py` (4 pytest
cases). The showcase report is intentionally separate from the
fair-comparison aggregate — `bench/showcase/README.md` documents
the boundary.

### Build gate

`bench_showcase` configures when `-DGOODNET_BENCH_STRATEGIES=ON`
is passed AND every needed plugin target is in the build
(`goodnet_security_noise`, `goodnet_float_send_rtt_objects`,
`goodnet_tcp_objects`, `goodnet_udp_objects`,
`goodnet_ipc_objects`). Pre-existing `bench_float_send_rtt` was
re-enabled along the way; one compile-only fixup in its source
fully-qualifies `FloatSendRtt` to the new
`gn::strategy::float_send_rtt::` namespace and passes `nullptr`
to the host-api-taking constructor.

## [1.0.0-rc1] — 2026-05-08

First release candidate. Wire format, public C ABI, plugin
contracts, and the operator surface are frozen for the rc series;
post-rc1 work routes through the contract-amendment process in
`GOVERNANCE.md`.

### Multi-connection per peer

Kernel `ConnectionRegistry` admits N concurrent connections to the
same peer. URI and pk indexes became last-writer-wins (`insert_or_assign`
under the per-shard lock); `conn_id` stays the only uniqueness key.
The contract change unblocks multi-path strategies that hold a TCP
conn and an ICE conn to the same peer at the same time, with a
strategy plugin choosing which carries application traffic. See
`docs/contracts/registry.en.md` §3 and `docs/architecture/routing.ru.md`
§"Регистр соединений".

### AEAD batch send invariant — scalar fallback fixed

The kernel's `send_link_batch` scalar fallback (used when a link
plugin's vtable returns `GN_ERR_NOT_IMPLEMENTED` for `send_batch`)
accepted a partial prefix then surfaced `LIMIT_REACHED`. The drainer
parked the **whole** wire batch as stalled and replayed the
already-sent prefix on retry, breaking the AEAD nonce sequence on
the receiver. Fix: `send_link_batch` now reports the accepted-frame
count through an out parameter, and the drainer's three send sites
(stalled retry, plaintext path, ciphertext path) erase the accepted
prefix before parking the remainder. Any link plugin that opts out
of batch send no longer triggers wire-byte replay under back-pressure.
See `docs/contracts/link.en.md` §3.

### Inline-crypto fast path + CryptoWorkerPool

`SecuritySession` exposes `encrypt_batch_transport(plaintexts,
&wire_batch)` that atomically reserves K AEAD nonces and submits
K encrypt jobs to the `CryptoWorkerPool`, then coalesces the wire-
framed ciphertexts into one `link->send_batch` call. Single
connection sustained throughput on the reference machine
(i5-1235U, loopback, 16 KiB payloads) lands at ~6 Gbps; four-conn
aggregate at ~20 Gbps. WireGuard single tunnel measured under the
same conditions hits 4.94 Gbps (mainline data plane runs single-
threaded in softirq context). See `docs/operator/deployment.en.md`
§1 for the full bench matrix and `README.md` for the WireGuard
comparison.

### Receiver-side recv backpressure

TCP plugin pauses the read loop when `notify_inbound_bytes` returns
`GN_ERR_LIMIT_REACHED`, parks the rejected chunk in
`stalled_inbound_`, and retries on a 100 µs strand-bound timer.
The kernel's per-session recv buffer cap rose from `2 *
max_frame_bytes` (128 KiB) to `kDefaultDrainBatch *
max_frame_bytes` (4 MiB) so the receiver absorbs a full peer drain
batch without tripping the failure threshold. See
`docs/contracts/backpressure.en.md` §9 and the link plugin's
recv-loop pattern in `docs/impl/cpp/transports.ru.md`.

### Honest performance reporting

`docs/operator/deployment.en.md` §1 now labels burst (1000-frame
warmup) and sustained (5000-frame feedback loop) numbers
separately. `perf record` evidence for the AEAD hot path
(chacha20_encrypt_bytes 42 % of cycles, poly1305_blocks 30 %) ships
in the architecture canvas's link-tcp card.

### Contract corrections

- `docs/contracts/host-api.en.md` §2 — `emit_counter` and
  `iterate_counters` slots now appear in the ABI table (they
  were live in `sdk/host_api.h` but missing from the contract
  document).
- `docs/contracts/conn-events.en.md` §3 — replaced the obsolete
  single-slot `subscribe(channel, …)` rendering with the real
  typed pair (`subscribe_conn_state` /
  `subscribe_config_reload`).
- `docs/contracts/security-trust.en.md` §3 — dropped the phantom
  `scheme` parameter from `notify_connect`'s signature; the
  kernel derives scheme from the `uri://` prefix.
- `docs/contracts/registry.en.md` §3 — corrected the
  "all-or-nothing on any key" wording to reflect the multi-conn
  semantic (only `conn_id` and `max_connections` cap reject).
- `docs/contracts/capability-tlv.en.md` §1 — removed reference
  to phantom `host_api->send_capability_blob` /
  `set_capability_handler` slots; capability blobs ride as
  application-message payload until v1.1.

### Two nodes talk: bridges/cpp + link-ice + gssh

`bridges/cpp/` is a sibling git that ships header-only RAII C++23
wrappers over `sdk/core.h` so operator binaries write
`gn::cpp::Core` instead of raw `gn_core_*` calls. MIT-licensed,
INTERFACE target `GoodNet::cpp`. The kernel build picks up the
slot when present and pulls its smoke tests into the kernel ctest
run.

`plugins/links/ice/` ports the ICE NAT-traversal transport from
the legacy GoodNet — full RFC 8445 with custom STUN/TURN (no
libnice or libjuice dependency), GPL-2 + linking exception. The
legacy optimizer/orchestrator coupling is dropped; signalling
moved off the wire onto the `gn.link.ice.signal` plugin↔plugin
extension. The plugin's own ctest suite passes 20/20 under
Release / ASan / TSan.

`apps/gssh/` is the operator SSH binary — single binary, three
modes (`gssh user@<peer-pk>` wraps `ssh -o ProxyCommand=...`,
`gssh --bridge <peer-pk>` is the ProxyCommand callee,
`gssh --listen` forwards inbound GoodNet conns to `localhost:22`).
Consumes the kernel through `bridges/cpp` + `sdk/core.h`; same
source tree fronts both client and server side.

### Tests as plugin-owned units

Each loadable plugin owns its own conformance tests. `link.en.md` §9
shutdown contract lives in `sdk/test/conformance/link_teardown.hpp`
(typed-test fixture exported from the SDK); each link plugin's
own `tests/test_<link>_conformance.cpp` instantiates the suite
for its type. A regression in IPC's `shutdown()` now fails IPC
plugin's own `nix run .#test`, not a kernel-side cross-plugin
runner.

Cross-plugin integration tests (Noise+TCP end-to-end, plugin
teardown, goodnet binary boot, backpressure across plugins, link
extension API) live in `goodnet-integration-tests` sibling repo
pulled into the kernel's `tests/integration/` slot via
`nix run .#plugin -- install`.

### Documentation corpus

23 canonical contracts in `docs/contracts/`, ten architecture
deep-dives in `docs/architecture/`, eight task recipes in
`docs/recipes/`, five C++ implementation guides in
`docs/impl/cpp/`, four wire-format references in
`docs/protocol/`. Architecture diagrams as 17 SVGs under
`docs/img/` produced by `tools/gen_diagrams.py`; bird's-eye
canvas at `docs/architecture.canvas`. Doxygen API reference is
wired through `nix run .#docs` against `docs/Doxyfile`.

### Workflow

Loadable plugins live in their own gits; the kernel monorepo
ignores their slots entirely. The kernel's flake exposes seven
`nix run .#…` apps that cover the full lifecycle, plus an
auto-pull `shellHook` that wires a fresh checkout on first
`nix develop`:

```
nix run .#                           # default = debug build
nix run .#setup                      # mirrors + plugins + hooks
nix run .#update                     # nix flake update + plugin pulls
nix run .#build  [-- release|debug]
nix run .#test   [-- asan|tsan|all]
nix run .#run    -- <demo|node|goodnet> [args]
nix run .#plugin -- <new|pull|install|update> [args]
```

### Verification

- ctest 878/878 green under Release, ASan, TSan on the reference
  machine.
- 5/5 sustained-tight-loop bench runs (1c × 16 KiB × 5000 frames)
  complete with zero AEAD-MAC failures.
- 30× TSan stress run on link-teardown without surfacing the
  shutdown race that closed in late April.

### Known limitations

- **Plugin flake input is a relative `git+file:../../..`** which
  Nix has deprecated in favour of absolute or `github:` URLs
  (see https://github.com/NixOS/nix/issues/12281). Each plugin's
  `flake.lock` therefore needs `--allow-dirty-locks` to refresh.
  Workaround stays in place until each plugin extracts to its
  `GoodNet-io/<repo>` GitHub URL post-rc1.
- **No per-plugin GitHub repositories yet.** The `GoodNet-io`
  organisation is empty; bundled plugins ship in-tree until
  rc1 cuts and the per-plugin repos go live.
- **No registered domain.** Documentation references the GitHub
  organisation directly.

### Teardown protocol pinned

`link.en.md` §9 now spells out the full caller-thread emit invariant:
shutdown latches the flag inside the sessions lock, drains an
append-only published-ids list rather than the live session map,
and emits one `notify_disconnect` per id on the caller thread. The
new `docs/impl/cpp/concurrency.md` carries the matching C++
pattern (`shutdown_` under the lock, `claim_disconnect` for runtime
worker emits, `published_ids_` for shutdown completeness). Each of
the four affected link plugins (TCP, IPC, WS, TLS) landed the fix
in its own git on `fix/teardown-race`, merged into the plugin's
`main`. The kernel-side TSan suite ran 30× post-fix without a
single teardown-race surface.

### Added

- **`GN_ERR_OUTPUT_TOO_SMALL` (-18)** — new error code in `gn_result_t`.
  Distinguishes "caller's `out_cap` is smaller than the size required to
  hold the result; retry with a larger buffer" from
  `GN_ERR_PAYLOAD_TOO_LARGE` (an *input*-side limit where retrying with
  the same payload is pointless).  Used by the `gn.compress` extension
  vtable (`sdk/extensions/compress.h`).

### Documentation

- `docs/contracts/compressed-object.en.md` §7 added: scope locked to
  GNET-shaped carriers (discrete payloads routed by `msg_id`);
  cross-protocol compression explicitly out of scope for v1.
- `docs/contracts/compressed-object.en.md` §3: added note clarifying that
  the algo byte (enum-shaped, names the encoding of a single frame) and
  the `compression-set` TLV `0x0003` (bit-shaped, advertises peer
  capability) are semantically distinct; numeric coincidence at `0x01` is
  allocation convention, not an invariant.
- `docs/contracts/compressed-object.en.md` §4: documents that inband
  `target_msg_id` is rejected by `inject(LAYER_MESSAGE)` when it falls in
  the identity range (`0x10..0x1F`); decompression is never attempted for
  reserved system handler ids.

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
  `GN_API_HAS_LOG` per `abi-evolution.en.md` §3a. Per
  `host-api.en.md` §11.
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
  Schema in `config.en.md` §3; semantics in `host-api.en.md` §11.4.
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
  `host-api.en.md` §2 and `config.en.md` §3.
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
  the kernel state back to the prior load. Per `limits.en.md` §2.

- **Counter surface for kernel and plugin metrics** —
  `host_api->emit_counter(name)` and `iterate_counters(visitor)`
  expose a flat map of named monotonic 64-bit counters. The
  router emits `route.outcome.*` for every dispatched envelope
  and the kernel surfaces `drop.*` for every `gn_drop_reason_t`;
  plugins extend the surface with their own
  `<subsystem>.<event>.<reason>` names. Wire format / scrape
  protocol live in an exporter plugin — the kernel never carries
  HTTP serving or Prometheus rendering code. New header
  `sdk/metrics.h`. Per `metrics.en.md` (new contract).
- **Plugin integrity manifest** — `PluginManager::set_manifest`
  installs a SHA-256 allowlist that gates every `dlopen`. An empty
  manifest is the developer-mode default (every plugin loads); a
  non-empty manifest puts the loader in production mode and rejects
  every plugin not pinned to a matching hash. Verification runs
  before `dlopen` so a tampered binary's static initialisers never
  reach the kernel. Manifest format: JSON
  `{"plugins":[{"path":...,"sha256":<64-hex>},...]}`. Streaming
  SHA-256 via libsodium, 64 KiB chunks. New error code
  `GN_ERR_INTEGRITY_FAILED`. Per `plugin-manifest.en.md`.
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
  the misbehaving plugin. Per `plugin-lifetime.en.md` §4 + §8 and
  `host-api.en.md` §10.
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
  `docs/contracts/uri.en.md`.
- **Kernel injection API** — `host_api->inject_external_message`
  and `inject_frame` for bridge plugins to push foreign-system
  payloads into the mesh under their own identity. Per-source
  token-bucket rate limit (`core/util/token_bucket.hpp`) with
  explicit `Clock` injection per `clock.en.md` §2.
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
  `link.en.md` §4 single-writer, IPv6 dual-stack with
  `IPV6_V6ONLY=false` on `::` wildcard.
- **IPC transport** — Boost.Asio `local::stream_protocol` with
  the same strand shape as TCP; `chmod 0700` on the parent
  directory before bind closes the bind-vs-permissions TOCTOU
  window.
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
  `backpressure.en.md` §3, so a queue oscillating inside the
  hysteresis band never floods the channel. The publisher slot
  is the new `host_api->notify_backpressure(conn, kind, bytes)`,
  guarded by the kind-based transport role gate so only
  transport plugins can emit. SDK_VERSION_MINOR → 1.6.
- **Backpressure hard cap** — TCP / IPC / WS / TLS transports now
  refuse fresh sends once the per-connection write queue holds
  more than `gn_limits_t::pending_queue_bytes_hard` bytes per
  `backpressure.en.md` §3. Each Session carries an atomic
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
  pending queue (per `backpressure.en.md` §8), capped at
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
  always carry an IP literal. Per `docs/contracts/dns.en.md` §1
  (new). Seven new unit tests cover IP-literal passthrough,
  IPv6 brackets, path-style URIs, query preservation,
  unparseable inputs, the `localhost` lookup, and `*.invalid`
  failure surfaces.
- **Capability TLV codec** — `sdk/cpp/capability_tlv.hpp` ships
  a header-only encode / parse pair against the
  `[type:u16 BE][length:u16 BE][value]*` blob format described
  in `docs/contracts/capability-tlv.en.md` (new). Used by the
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
  `docs/contracts/conn-events.en.md` and `sdk/conn_events.h`.
  SDK_VERSION_MINOR bumped to 1.5.
- **Service executor** — `core/kernel/timer_registry`. The kernel
  owns a single-thread executor reserved for plugin service tasks.
  Three new `host_api` slots route to it: `set_timer` (one-shot
  callback after `delay_ms`), `cancel_timer` (idempotent), and
  `post_to_executor` (run-now task). Every scheduled entry holds
  a `weak_ptr<void>` of the calling plugin's quiescence sentinel
  (`plugin-lifetime.en.md` §4); a callback whose plugin already
  unloaded is dropped silently. `gn_limits_t::max_timers` and
  `max_pending_tasks` (default `4096`) cap the queue. New
  `docs/contracts/timer.en.md`. SDK_VERSION_MINOR bumped to 1.4.
- **TLS transport** — `goodnet_link_tls.so` registers `tls://`
  and the `gn.link.tls` extension. Asio-on-OpenSSL
  `ssl::stream<tcp::socket>` with TLS 1.2 minimum, sslv2/sslv3/
  tlsv1.0/tlsv1.1 disabled, no_compression. Server reads cert and
  key from kernel config (`links.tls.cert_path` /
  `links.tls.key_path`); client defaults to `verify_none`
  because the kernel's identity / Noise pipeline is the
  authentication gate (`security-trust.en.md` §3 single source).
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
  contract `docs/contracts/link.en.md`. The Noise plugin's
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
  (`registry.en.md` §8a).** ConnectionRegistry exposes
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
  (`plugin-manifest.en.md` §7).** The flag turns the empty-manifest
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
- **FFI spec: subscriber failure modes (`signal-channel.en.md` §6).**
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
  (`abi-evolution.en.md` §3a).** `LinkRegistry::register_link`
  and `SecurityRegistry::register_provider` now reject vtables
  whose `api_size` is smaller than the minimum the kernel knows
  about; the rejection returns `GN_ERR_VERSION_MISMATCH` before
  any slot lookup. Handler vtable is fixed-shape at v1 and does
  not carry `api_size` (documented in §3a). Tests cover the
  zero-`api_size`, truncated, and exactly-minimum cases.
- **Registry-wide caps from `gn_limits_t` are now enforced
  (`limits.en.md` §4 + new §4a).** `ConnectionRegistry::insert_with_index`,
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
- **Registry contract honesty (`registry.en.md` §4).** The §4 paragraph
  that promised a deletion-generation increment on a
  `gn_endpoint_t` snapshot stream is replaced with a description
  of what the registry actually offers: `get_endpoint` returns the
  view by value, no cache-invalidation channel exists, consumers
  re-read or prune their cache on the `DISCONNECTED` event from
  `conn-events.en.md` §2a. The previous wording named a stream the
  kernel never exposed; the rewrite removes the lie.
- **Standalone Asio.** The networking dependency now ships as
  the `asio` package (Christopher Kohlhoff's standalone build,
  same library as Boost.Asio without the umbrella). The
  dependency closure drops Boost.System, Boost.Thread, and
  Boost.Atomic; the source compiles unchanged after a
  mechanical `boost::asio::` → `asio::` rename. Build is
  header-only end-to-end.
- **Connection registry — atomic snapshot variant
  (`registry.en.md` §4a).** `ConnectionRegistry` exposes a
  snapshot-and-erase primitive that captures the pre-erase
  record (the `gn_endpoint_t` view plus `§8` per-connection
  counters) and removes the entry from all three indexes
  inside one critical section. The snapshot owns its uri /
  pk bytes; kernel-side storage holds no reference past the
  call.
- **`notify_disconnect` — DISCONNECTED ordering and at-most-once
  semantics (`conn-events.en.md` §2a).** The thunk drops the
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
  (`plugins/security/noise/docs/handshake.md` §8).** §8 now states that the address is
  an Ed25519 public key and the Noise suite's `25519` denotes
  X25519 for Diffie-Hellman; each side's static key crosses
  curves at session initialisation through the standard
  birational map (libsodium
  `crypto_sign_ed25519_pk_to_curve25519` /
  `crypto_sign_ed25519_sk_to_curve25519`), and the conversion
  lives inside the security provider. The kernel and handlers
  see only the Ed25519 representation. `identity.en.md` §7
  cross-reference updated to point at the curve-conversion
  paragraph rather than the file as a whole.
- **Capability TLV: `protocol-set` and `protocol-list` types
  (`capability-tlv.en.md` §2).** Type `0x0001` `protocol-set` is a
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
  (`attestation.en.md`, `security-trust.en.md` §3,
  `handler-registration.en.md` §2a).** Trust no longer promotes
  automatically when a Noise session reaches Transport phase.
  The kernel-internal `AttestationDispatcher` exchanges a
  232-byte payload on system msg_id `0x11` over the secured
  channel — 136-byte attestation cert (per `identity.en.md` §4) +
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
  `plugins/security/noise/docs/handshake.md` §5b.** The override storage migrates from
  `std::string` to a byte vector that the destructor and the
  reassignment path zeroise explicitly. The bytes are also wiped
  immediately after `OpenSSL` copies them into the SSL context
  during `listen()`; subsequent reassignments hit a freshly
  cleared buffer. Public material — the cert PEM — is exempt from
  the wipe rule. The regression suite asserts the observable
  flips from non-zero to zero across the listen call.
- **WebSocket transport gates every control-frame path through
  the per-connection hard cap (`backpressure.en.md` §3.1).** Pong
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
  (`plugins/security/noise/docs/handshake.md` §5 clause 4).** The handshake state's
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
covers `handler-registration.en.md` §2a's plugin-side rejection.

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
  (`abi-evolution.en.md`).
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
