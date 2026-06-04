# GoodNet Nix build system

Complete map of what lives in `nix/` and how the flake-based build
system works — from a fresh clone to a running cross-platform binary.

## Quick reference

```sh
nix run .#setup             # one-time bootstrap: mirrors + plugins + hooks
nix run .#build             # debug build in build/
nix run .#build -- release  # release build in build-release/
nix run .#build -- static   # single-binary static ELF in build-static/
nix run .#test              # 1510 unit + integration tests
nix run .#test -- asan      # AddressSanitizer run
nix run .#test -- tsan      # ThreadSanitizer run
nix run .#test -- all       # vanilla + asan + tsan in sequence
nix run .#plugin -- pull security-noise      # pull one plugin repo
nix run .#plugin -- install                  # pull all canonical plugins
nix run .#plugin -- update                   # git pull --ff-only every slot
nix run .#plugin -- new link portmap         # scaffold a new plugin repo
```

---

## Architecture overview

```
flake.nix                      ← monorepo root, all outputs
│
├── nix/kernel-only/flake.nix  ← slim subflake consumed by plugin flakes
│                                 (breaks the circular-input problem)
│
├── nix/goodnet-static.nix     ← musl static single-ELF build
├── nix/goodnet-windows.nix    ← mingw cross build (Linux host)
├── nix/goodnet-darwin.nix     ← macOS cross build (requires Apple SDK)
├── nix/goodnet-android.nix    ← Android NDK cross build
├── nix/goodnet-wasm.nix       ← WASI 1.0 wire-codec only
├── nix/goodnet-wasm-emscripten.nix  ← full kernel → browser WASM
│
├── nix/install-plugins.nix    ← batch-pull all canonical plugin slots
├── nix/pull-plugin.nix        ← pull one plugin by repo name
├── nix/init-mirrors.nix       ← bare-clone each slot to local mirror dir
├── nix/plugin.nix             ← router: pull | install | update | new
├── nix/new-plugin.nix         ← scaffold a plugin directory + flake
├── nix/plugin-helpers.nix     ← shared helpers consumed by plugin flakes
│
├── nix/setup.nix              ← init-mirrors + install-plugins + install-hooks
├── nix/install-hooks.nix      ← symlink .githooks/ into .git/hooks/
├── nix/bootstrap-env.nix      ← per-user XDG layout (identity+plugins+manifest)
├── nix/init-app.nix           ← scaffold a downstream consumer project
├── nix/sample-peer.nix        ← throwaway test peer on tcp://0.0.0.0:9101
├── nix/dev-shell-app.nix      ← downstream consumer dev shell
├── nix/docker.nix             ← wrap static ELF in a reproducible image
└── nix/docs.nix               ← Doxygen + diagram generation
```

---

## Build targets

### goodnet-core (dynamic, default)

```sh
nix build          # → ./result/ (symlink into /nix/store)
```

Standard release build for x86_64-linux and aarch64-linux. Outputs:
- `lib/libgoodnet_kernel.so` — runtime kernel
- `lib/libgoodnet.a` — SDK static archive
- `lib/cmake/GoodNet/` — CMake find-package files

Plugins are **not** included here. They are separate `.so` files loaded
at runtime via `dlopen` from the manifest.

### goodnet-core-static (`nix/goodnet-static.nix`)

```sh
nix run .#build -- static
# or: nix build .#goodnet-core-static
```

musl + static link via `pkgsStatic`. All canonical plugins are
**compiled in** and registered at startup via renamed entry points
(`gn_plugin_init_link_tcp`, etc.). Result is a single ELF with no
dynamic dependencies — runs in scratch/distroless containers.

Excluded from the bundle: `handler-store` (sqlite), `handler-dns`
(c-ares) — gated in root `CMakeLists.txt` on
`GOODNET_STATIC_PLUGINS=ON`.

### docker-static (`nix/docker.nix`)

```sh
nix build .#docker-static
docker load -i result
docker run --rm goodnet:nix-static goodnetd --version
```

Reproducible `buildLayeredImage` wrapping the static ELF. Layer order
minimises cache invalidation: base layer = nix store paths, top layer =
kernel binary.

### Cross-platform builds (Linux host only)

| Target | `nix build .#` attribute | Notes |
|--------|--------------------------|-------|
| Windows x86_64 | `goodnet-windows` | mingw; outputs `goodnet.exe` |
| macOS x86_64 | `goodnet-darwin-x86_64` | requires Apple SDK staged via `requireFile` |
| macOS aarch64 | `goodnet-darwin-aarch64` | same SDK requirement |
| Android aarch64 | `goodnet-android-aarch64` | NDK r28; bionic smoke, kernel only |
| WASM (WASI 1.0) | `goodnet-wasm` | wire-codec subset, no sockets |
| WASM (browser) | `goodnet-wasm-emscripten` | full kernel → `goodnet.js` + `goodnet.wasm` |

**Darwin / Android gating**: both targets carry `passthru.skip_reason`.
CI reads this and applies `continue-on-error: true` automatically when
the required SDK is absent — the build does not fail the pipeline.

**Emscripten WASM threading**: compiled with `-sUSE_PTHREADS=1` (maps
to Web Workers). The hosting page must serve:
```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```
for `SharedArrayBuffer` to be available.

---

## Plugin system

### Layout

Plugins are **not part of the monorepo** — they live in their own git
repositories and are cloned on demand into `plugins/<kind>/<name>/`:

```
plugins/
  handlers/  heartbeat/  dns/  store/  web_api_proxy/  zstd_decompress/
  links/     tcp/  udp/  ws/  ws_inject/  ipc/  tls/  ice/  quic/ …
  security/  noise/  null/  pkcs11/
  strategies/  float_send_rtt/
  protocols/   gnet/  (tracked in monorepo — protocol layer)
```

`plugins/protocols/` is the only subdirectory tracked by the kernel
monorepo (static protocol layers compiled into the kernel). Everything
else is gitignored at the monorepo level.

### Three-level lookup

When any plugin command needs a source URL, it checks in order:

1. `${GOODNET_PLUGIN_MIRROR_DIR}/<repo>.git` — private bare mirror
2. `${XDG_DATA_HOME:-$HOME/.local/share}/goodnet-mirrors/<repo>.git`
3. `https://github.com/GoodNet-io/<repo>` — public fallback

This allows air-gapped / private-fork workflows: mirror once, pull
offline forever.

### Pull a single plugin

```sh
nix run .#plugin -- pull link-ice
# clones https://github.com/GoodNet-io/link-ice into plugins/links/ice/
```

### Pull all canonical plugins

```sh
nix run .#plugin -- install
# equivalent to pull for every slot in the canonical map
```

### Update already-cloned plugins

```sh
nix run .#plugin -- update
# git pull --ff-only for each present slot
```

### Set up local mirrors (`nix/init-mirrors.nix`)

```sh
nix run .#setup   # calls init-mirrors as part of the bootstrap
```

For each plugin slot that already has a `.git/`:
1. `git clone --bare <plugin-dir>` → `${MIRROR_DIR}/<repo>.git`
2. Adds `origin` remote in the working clone pointing at the mirror
3. `git push -u origin <branch>` to sync

Subsequent `plugin -- pull` calls resolve from the local mirror first.

### Scaffold a new plugin

```sh
nix run .#plugin -- new link portmap
```

Writes `plugins/links/portmap/` with:
- `CMakeLists.txt` — `add_library(…OBJECT…)` + `add_plugin(…)`
- `default.nix` — kernel-side derivation
- `flake.nix` — standalone dev/test/build flake
- `portmap.cpp` — entry skeleton (`gn_plugin_init`, `gn_plugin_shutdown`)
- `tests/` — placeholder gtest (passes immediately)

The standalone flake consumes `nix/kernel-only/flake.nix` — not the
monorepo root — so plugin flakes never create circular inputs.

---

## Kernel-only subflake (`nix/kernel-only/flake.nix`)

Plugin flakes declare:
```nix
inputs.goodnet.url = "github:GoodNet-io/goodnet";
```
and consume `inputs.goodnet.packages.${system}.goodnet-core`.

If they imported the root flake, a cycle would form: root imports all
plugin flakes → plugin flake imports root. The `kernel-only` subflake
solves this by never importing any plugin.

Re-exports:
- `packages.goodnet-core` / `.default`
- `lib.plugin-helpers` (from `../plugin-helpers.nix`)
- `lib.compose` (the `composeNode` function)

Source filtering: `sdk/`, `core/`, `cmake/`, `nix/`,
`plugins/protocols/` only — plugin source never touches the kernel
derivation, so kernel doesn't rebuild on plugin edits.

---

## Plugin helper library (`nix/plugin-helpers.nix`)

Consumed by every standalone plugin flake to avoid copy-paste:

```nix
let helpers = goodnet.lib.plugin-helpers; in {
  devShells.default = helpers.mkPluginDevShell pkgs { … };
  apps = helpers.mkPluginApps pkgs { pluginName = "noise"; };
}
```

Provides:
- `sanitizerFlags.{asan,tsan}` — centralised compiler flag tuples
- `mkBuildScript` — CMake configure snippet
- `mkPluginDevShell` — standard shell (ccache, clang-tools, gdb)
- `mkPluginApps` — five-app set: build, debug, test, test-asan, test-tsan

Centralising sanitizer flags means a flag bump lands once for kernel
and every plugin without coordinating PRs.

---

## Node composition (`composeNode`)

For deployment, a "node" bundles a kernel binary with a pinned plugin
set and a config:

```nix
# In a deployment flake or NixOS module:
composeNode pkgs {
  kernel  = goodnetd.packages.${system}.default;
  plugins = with goodnet.packages.${system}; [
    link-tcp security-noise handler-heartbeat
  ];
  config   = ./node.json;
  identity = ./identity.bin;   # optional
}
```

Build steps:
1. Collect `lib/goodnet/plugins/lib*.so` from each plugin derivation
2. Run `goodnetd manifest gen lib*.so` to SHA-256-pin each `.so`
3. Copy kernel + plugins to `$out/`
4. Generate or copy `etc/goodnet/node.json`
5. Wrap `goodnetd` as `goodnet-node` with all paths pre-baked

Output layout:
```
$out/bin/goodnetd
$out/bin/goodnet-node          ← wrapper with --config/--manifest/--identity
$out/lib/goodnet/plugins/lib*.so
$out/etc/goodnet/node.json
$out/etc/goodnet/manifest.json
$out/etc/goodnet/identity.bin  ← only if provided
```

---

## Dev shell variants

### `nix develop` (kernel contributor)

Full shell: ccache, clang-tools, gdb, graphviz, python3 (with
pyyaml + libclang for livedoc).

Toolchain: **gcc 16** on `x86_64-linux` (via the
`sempiternal-aurora/nixpkgs` flake input); **gcc 15** on all other
platforms.  The shell exports `GOODNET_CXX_LIB_DIR` (pointing to the
active `libstdc++` directory) so `CMAKE_BUILD_RPATH` bakes the correct
`libstdc++.so.6` path into every test binary — `ctest` works outside
`nix develop` without a `LD_LIBRARY_PATH` wrapper.

Build inputs include: libsodium, spdlog, fmt, nlohmann-json,
**stdexec** (P2300 / `GN_CXX26_EXEC=1`), gtest, Boost.Asio.

**Auto-pull on entry**: on first `nix develop` after a fresh clone,
the shell checks every plugin slot. Missing slots trigger
`nix run .#setup` automatically — one clone + one develop is all
that's needed.

### `nix develop goodnet#app` (downstream consumer)

Exposes these env vars to the shell and CMake:
- `GOODNET_CORE_LIB` — path to `libgoodnet_kernel.so`
- `GOODNET_LIB_DIR` — directory of kernel libs
- `GOODNET_PLUGIN_PATH` — directory of plugin `.so` files
- `GOODNET_IDENTITY` — `~/.local/share/goodnet/identity/default.bin`
- `GOODNET_MANIFEST` — baseline manifest JSON

Used by the `goodnet_app(…)` CMake helper and the `gn::sdk::Core` RAII
constructor. See `docs/operator/downstream-app-setup.en.md` for the
full consumer workflow.

---

## Git hooks (`.githooks/`)

Install with `nix run .#setup` (idempotent) or manually:
```sh
git config core.hooksPath .githooks
```

### pre-commit

1. **ABI boundary enforcement** — rejects `#include "plugins/…"` in
   core and `#include "core/…"` in plugins.
2. **Livedoc drift check** — if `sdk/`, `core/`, or `docs/contracts/`
   changed, runs `python3 tools/livedoc.py --check`. Fails if any
   auto-generated fact file would change.
3. **clang-tidy strict** — staged C++ files checked against
   `build/compile_commands.json` (requires one prior `nix run .#build`).
   Warnings treated as errors.

Bypass (one-off): `git commit --no-verify`

### pre-push (to `main` only)

1. `tools/livedoc.py --check`
2. `pytest tests/livedoc tests/tools`
3. `cmake --build build && ctest --test-dir build`

Bypass: `git push --no-verify`

---

## Test variants

| Command | Instrumentation | Build dir | Notes |
|---------|----------------|-----------|-------|
| `nix run .#test` | none | `build/` | 1510/1510 |
| `nix run .#test -- asan` | ASan + UBSan | `build-asan/` | known lambda leak in TurnTcpAlloc |
| `nix run .#test -- tsan` | TSan | `build-tsan/` | 0 races as of rc6 |
| `nix run .#test -- coverage` | lcov | `build-coverage/` | ≥74 % line |
| `nix run .#test -- all` | vanilla+asan+tsan | multiple | skips coverage (slow) |

---

## How `.goodnet/` and `~/.local/share/goodnet/` relate

`~/.local/share/goodnet/` is the **per-user XDG data directory**
populated by `nix run .#bootstrap-env`:

```
~/.local/share/goodnet/
  identity/default.bin       ← Ed25519 device identity key
  plugins/lib*.so            ← baseline plugin set (built by Nix)
  manifests/baseline.json    ← SHA-256-pinned manifest for the above
  config.json                ← sample node config (operator-editable)
```

This directory is the runtime data home. The kernel reads identity and
manifest from here unless overridden by `--identity` / `--manifest`
flags. It is never committed to git.

`nix run .#sample-peer` uses a **temp workdir** (fresh identity,
fresh manifest) so it never touches `~/.local/share/goodnet/` and is
safe to run alongside a production daemon.

---

## Makefile

`Makefile` is a thin ergonomic wrapper. Every target shells out to the
corresponding `nix run` command. Useful when `nix run` is too verbose
to type repeatedly:

```sh
make setup          # → nix run .#setup
make build          # → nix run .#build
make build-release  # → nix run .#build -- release
make test           # → nix run .#test
make test-asan      # → nix run .#test -- asan
make test-all       # → nix run .#test -- all
make plugin-new KIND=link NAME=portmap
make plugin-pull NAME=security-noise
make plugin-install
```

The flake is the single source of truth. Makefile targets are aliases
only — they never contain logic.
