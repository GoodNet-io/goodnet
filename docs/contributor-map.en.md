# GoodNet Contributor Map

How to orient yourself in this codebase and find work that matches
your experience level. The kernel is a C++23 library; everything
outside it is a plugin, bridge, or operator tool.

---

## Before you start

```sh
git clone https://github.com/GoodNet-io/goodnet.git
cd goodnet
nix run .#setup          # mirrors + plugins + hooks
nix run .#build          # debug build → build/
nix run .#test           # 1510 tests, ~30 s
```

Read first: [`docs/contracts/host-api.en.md`](contracts/host-api.en.md) — the
kernel surface. [`docs/operator/quickstart.en.md`](operator/quickstart.en.md)
— end-to-end node setup.

The rule: contracts in `docs/contracts/` change first, code catches up.
Every PR must pass `nix run .#test` and `nix build` before push.

---

## Entry-level track

Tasks that need no deep kernel knowledge. Good first contributions:

| Task | Issue | What to do |
|------|-------|------------|
| Add `on_topology_sealed` to link-tcp | [#23](https://github.com/GoodNet-io/goodnet/issues/23) | Define `on_topology_sealed(const gn_topology_t*)` on the plugin class — `GN_LINK_PLUGIN` wires it automatically |
| Add `on_topology_sealed` to link-ws | [#23](https://github.com/GoodNet-io/goodnet/issues/23) | Same as above |
| Add `on_topology_sealed` to link-ipc | [#23](https://github.com/GoodNet-io/goodnet/issues/23) | Same |
| Add `on_topology_sealed` to link-tls | [#23](https://github.com/GoodNet-io/goodnet/issues/23) | Same |
| NodeIdentity --expiry 0 signature bug | [#24](https://github.com/GoodNet-io/goodnet/issues/24) | Fix in `identity.cpp:222–235` |
| WsLink ping frame > 125 bytes | [#25](https://github.com/GoodNet-io/goodnet/issues/25) | Cap ping payload at 125 bytes per RFC 6455 §5.5 |

**How:** Each plugin lives in `plugins/<kind>/<name>/` with its own git and
CMakeLists. The `GN_LINK_PLUGIN` macro (sdk/cpp/link_plugin.hpp) detects
`on_topology_sealed` via C++ concept — define the method, the vtable
slot fills automatically.

---

## Plugin maintainer track

Each plugin is a separate repository. Work on a plugin means: read its
standalone flake, build with `nix develop`, run its own test suite.

### Link plugins

| Plugin | State | Open work |
|--------|-------|-----------|
| link-tcp | ✅ stable | Add `on_topology_sealed` (#23); P2300 send PoC (#20) |
| link-udp | ✅ stable | io_uring compile-flag path (#19); P2300 send (#20) |
| link-ws | ✅ stable | Add `on_topology_sealed` (#23); PingFlood TSan (#25) |
| link-ipc | ✅ stable | Add `on_topology_sealed` (#23) |
| link-tls | ✅ stable | Add `on_topology_sealed` (#23) |
| link-ice | ⚠️ broken | Multi-connect signal routing (#18) — see below |
| link-quic | 🚧 in progress | ICE carrier topology propagation |
| link-ws-inject | ✅ stable | ws_inject smoke test after derived-pk refactor (#5) |
| link-raw-inject | ✅ stable | — |
| link-portmap | ✅ stable | — |

### Security plugins

| Plugin | State | Open work |
|--------|-------|-----------|
| security-noise | ✅ stable | Reorder buffer for datagram links (#7) |
| security-null | ✅ stable | — |
| security-pkcs11 | ✅ stable | — |

### Handler plugins

| Plugin | State | Open work |
|--------|-------|-----------|
| handler-heartbeat | ✅ stable | — |
| handler-store | ✅ stable | — |
| handler-dns | ✅ stable | — |
| handler-web-api-proxy | ✅ stable | — |

### Bridges

| Bridge | State | Open work |
|--------|-------|-----------|
| bridges-cpp | ✅ stable | — |
| bridges-rust | 🚧 partial | Expose `register_runtime` + vtable traits (#30) |
| bridges-python | 🚧 partial | Callback substrate + `register_runtime` (#30) |
| bridges-js | ✅ stable | — |

---

## Kernel contributor track

The kernel lives in `core/` and `sdk/`. The source of truth is
`core/kernel/kernel.hpp` — every registry and bus is owned there.

**Rules:**
- Contract in `docs/contracts/` changes before any C++ change
- `nix run .#test -- asan` and `nix run .#test -- tsan` must be green
- `nix build` must pass before any push (the pre-push hook runs this)
- ABI evolution: use `GN_API_HAS` guards, bump `api_size`, never shrink

**High-value kernel work:**

| Work | Issue | Complexity |
|------|-------|------------|
| `on_topology_reloaded` vtable field | [#27](https://github.com/GoodNet-io/goodnet/issues/27) | Medium — new vtable slot, ABI-gated |
| P2300 PoC in link-tcp send path | [#20](https://github.com/GoodNet-io/goodnet/issues/20) | Medium — tcp.cpp:196, stdexec already linked |
| Forgejo CI wiring | [#22](https://github.com/GoodNet-io/goodnet/issues/22) | Low — runner exists, workflow exists |

**Key source paths:**

```
core/kernel/kernel.hpp        — Kernel struct, all registries
core/kernel/kernel.cpp        — Phase transitions, config reload
core/topology/                — build_topology(), on_topology_sealed dispatch
core/plugin/plugin_manager.cpp — dlopen, register_runtime
sdk/link.h                    — gn_link_vtable_t
sdk/host_api.h                — gn_host_api_t (what plugins call)
sdk/core.h                    — gn_core_* (what apps call)
sdk/plugin.h                  — plugin entry symbols
sdk/convenience.h             — C macros for plugin authors
sdk/cpp/link_plugin.hpp       — GN_LINK_PLUGIN macro + concept wiring
```

---

## Architecture research track

Long-horizon work that needs design before implementation.

### link-ice multi-connect (#18)

`IceSignalData` (candidate.hpp) has no session token — OFFER/ANSWER
signals route by `peer_pk` only. When two sessions exist for the same
peer, `link_ice.cpp:1291` creates a new session instead of routing to
the correct existing one.

**Design needed:** session token in `IceSignalData` envelope +
`AcceptFilterFn` on carrier `on_accept` for inbound demux.
Files: `plugins/links/ice/link_ice.cpp`, `session.cpp`, `candidate.hpp`.

### security-noise datagram (#7)

`cipher.cpp:94,136` — nonce is monotonic, no reorder buffer. No
capability check in the noise vtable. Fix: sliding window AEAD replay
tracker in `CipherState`. The security vtable has no link-capability
query path — this must live entirely in the plugin.

### P2300 migration (#20)

stdexec is already linked (`nix/stdexec.nix`, `CMakeLists.txt:257`).
`timer_registry.cpp` already uses it. First target: `tcp.cpp:196`
`do_send()` — replace `asio::dispatch(strand_, lambda)` with
`exec::schedule | stdexec::then | exec::start_detached`. UDP send
(`udp.cpp:439`) has no backpressure gate at all.

### io_uring UDP (#19)

Compile-flag path inside link-udp (`-DGN_UDP_IO_URING=ON`), not a new
plugin. Model: existing `GN_UDP_CXX26_SEND` gate. SQ fill level as
native backpressure signal. Requires `liburing` in flake build inputs.

### Bridge inline plugins (#30)

`gn_core_register_runtime` (sdk/core.h:651) and `gn_core_host_api`
(sdk/core.h:808) are exposed. Python and Rust bridges currently load
only `.so` files. Both need callback substrate + vtable wrapper traits.

---

## Cross-platform (#29)

| Target | Status | What's needed |
|--------|--------|---------------|
| Windows x86_64 | ✅ CI runs | — |
| WASM WASI | ✅ CI runs | — |
| WASM Emscripten | ✅ CI runs | Node.js smoke (`node goodnet.js --version`) |
| macOS x86_64/aarch64 | ⚠️ CI skips | Apple SDK staging via `requireFile` — document |
| Android aarch64 | ❌ no CI job | NDK r28 on runner; label-gated job needed |

---

## Workflow reference

```sh
nix run .#setup                     # one-time bootstrap
nix run .#build                     # debug
nix run .#build -- release          # release
nix run .#test                      # vanilla
nix run .#test -- asan              # AddressSanitizer + UBSan
nix run .#test -- tsan              # ThreadSanitizer
nix run .#plugin -- pull link-ice   # clone one plugin
nix run .#plugin -- update          # git pull --ff-only all slots
```

Pre-commit: clang-tidy strict on staged C++ + ABI/livedoc checks.
Pre-push (to main only): livedoc check + pytest + vanilla ctest.
Bypass once: `git commit --no-verify` / `git push --no-verify`.
