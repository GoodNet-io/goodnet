# Plugin linkage modes

Three ways a plugin's code lands in front of the kernel today,
plus one in design. The C ABI in `sdk/plugin.h` is the only stable
contract between kernel and plugin — every mode preserves it
bit-for-bit; what varies is *where* the entry symbols live and
*how* the kernel calls them.

## 1. Dynamic (`dlopen`, default)

`make build && make test` produces one `.so` per plugin under
`build/plugins/lib*.so`. `gn_plugin_init`, `gn_plugin_register`,
`gn_plugin_unregister`, `gn_plugin_shutdown`, `gn_plugin_sdk_version`,
and `gn_plugin_descriptor` are exported by name; `PluginManager`
resolves each through `dlsym`. Plugins ship as independent git
repos with their own Nix flakes and SHA-256-pinned manifest entries
(`docs/contracts/plugin-manifest.en.md`).

This is the production-default path. Operators reload, swap, and
hot-update plugins without touching the kernel binary.

## 2. Static (single-binary, `-DGOODNET_STATIC_PLUGINS=ON`)

`make build-static` compiles every bundled plugin as an
`add_library(... OBJECT)` and links every plugin's code into the
`goodnet` binary itself. Entry symbols carry a per-plugin suffix
(`gn_plugin_init_link_tcp`, `gn_plugin_register_link_ipc`, …) so
they don't collide at link time; the `GN_PLUGIN_*_NAME` macros in
`sdk/plugin.h` drive the rename. A generated `static_plugins.cpp`
(via `cmake/StaticPlugins.cmake`) gathers each plugin's entry
pointers into `gn_plugin_static_registry[]`, which
`PluginManager::load_static()` iterates instead of `dlopen`.

When to pick this mode:

- Embedded or air-gapped deployments where a single binary is
  easier to ship and verify than a binary + N `.so` files.
- Sanitizer trees (LSan would otherwise leak the dlopen handle
  on every restart cycle).
- Anywhere LTO across plugins matters — current measurements show
  ~2.8× compression vs. dynamic shipping (Release + mold + LTO):

| Build | Size |
|-------|------|
| dynamic kernel binary | 760 KB |
| 11 dynamic plugin `.so` (sum) | 3.2 MB |
| dynamic total shipped | **3.9 MB** |
| static single binary | **1.4 MB** (≈ 1 MB stripped) |

Plugin git repos that participate in static builds use the
`GN_PLUGIN_*_NAME` macros in their entry surface (so the dynamic
build still emits `gn_plugin_init` while the static build emits
the suffixed names automatically). Plugins authored from the
bundled templates pick this up without further work.

## 3. Out-of-process worker (`kind: remote`, **runtime present**)

Wire-protocol header lives in `sdk/remote/wire.h`; slot ids in
`sdk/remote/slots.h`; the per-frame CBOR shape is documented in
`docs/contracts/remote-plugin.en.md`. The kernel-side runtime lives
in `core/plugin/remote_host.{hpp,cpp}` — it spawns a worker child
over `socketpair(AF_UNIX, SOCK_STREAM)` (POSIX) or a named pipe
pair (Windows, deferred), drives the framing reader thread, and
exposes the same `call_init / call_register / call_unregister /
call_shutdown` surface the `dlopen` path uses. The worker links
the `goodnet_remote_plugin_stub` static library from `sdk/cpp/`,
which mirrors the kernel side and publishes a synthetic
`host_api_t` whose every slot serialises a `HOST_CALL` and waits
on the reply.

A `remote_echo://` proof binary lives at
`plugins/workers/remote_echo` — registers as a link plugin whose
`send` slot copies bytes straight back through
`host_api.notify_inbound_bytes`, demonstrating the full kernel↔
worker round trip without any new transport. The regression
suite at `tests/unit/plugin/test_remote_host.cpp` boots the real
worker over the wire (5 cases: HELLO handshake, lifecycle
round-trip, scheme exposed through the synthesised vtable, bad
binary surfaced as error, idempotent teardown).

Payload is a CBOR subset (major types 0/1/2/3/4/5 + simple values
20/21/22 from major 7; no floats, no indefinite-length). Handle
translation keeps every `void* host_ctx` and `void* self` as a
`uint64_t` opaque on the wire — the kernel-side dispatcher maps
to its real pointer, the worker's `host_ctx` is synthetic. The
codec is hand-rolled (`core/plugin/wire_codec.{hpp,cpp}`) with no
third-party dependency; mirror it from another language using
its native CBOR library on the same subset.

`PluginManager` integration (so manifests can carry
`kind: "remote"` and the kernel will pick this path automatically)
is the next chunk of work; the wire and the worker side ship
ready for it.

## Cross-platform posture

Plugin code that participates in any of these modes builds on
Linux, macOS, FreeBSD, NetBSD, and DragonFly today. The IPC
plugin's POSIX-only paths (`SO_PEERCRED`, `LOCAL_PEERCRED`,
parent-dir `chmod 0700`) are guarded under
`__linux__` / `__APPLE__` / `__FreeBSD__` / `__NetBSD__` /
`__DragonFly__`; the matching `query_peer_cred()` helper picks
the right syscall. Windows builds skip the IPC plugin entirely
(`if(WIN32) return()` in the plugin's CMakeLists) until the
named-pipe carrier lands; the rest of the kernel and other
plugins build with Asio's portable reactor abstraction.

`flake.nix` continues to advertise Linux-only Nix systems for now
— macOS support requires platform-marker work on each plugin's
flake (`meta.platforms = lib.platforms.linux ++ lib.platforms.darwin`),
which lands per-plugin as each transport gets its own port.
