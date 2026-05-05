# Plugin spinoff cookbook

Each plugin tree under `plugins/<kind>/<name>/` is self-contained:
it owns its `CMakeLists.txt` (with standalone `find_package(GoodNet
REQUIRED)` mode), its `default.nix`, its `LICENSE`, its `README.md`,
its `tests/`, and — for plugins with their own contract — its
`docs/`. Promoting a plugin into its own GitHub repo is purely
mechanical.

## v1.0 baseline — stays in the monorepo

The `GoodNet-io/goodnet` repo at v1.0.0-rc1 carries the kernel,
the SDK, and these baseline plugins:

| Path | Repo destination at rc1 |
|---|---|
| `plugins/protocols/gnet`     | `GoodNet-io/goodnet` (mandatory) |
| `plugins/protocols/raw`      | `GoodNet-io/goodnet` |
| `plugins/security/noise`     | `GoodNet-io/goodnet` |
| `plugins/security/null`      | `GoodNet-io/goodnet` |
| `plugins/links/{tcp,udp,ws,ipc,tls}` | `GoodNet-io/goodnet` |
| `plugins/handlers/heartbeat` | `GoodNet-io/goodnet` |

## v1.1+ spinoff candidates

When a non-baseline plugin lands in the monorepo and its first
shipping cycle clears, lift it into `GoodNet-io/<plugin>` so its
release cadence and issue tracker stop sharing space with the
kernel.

Procedure (replace `<plugin>` and `<kind>` with the actual names):

```sh
# 0. Working clone, on a clean dev branch.
git clone git@github.com:GoodNet-io/goodnet.git goodnet-<plugin>-spinoff
cd goodnet-<plugin>-spinoff

# 1. Filter the history down to the plugin tree, lift it to the
#    repo root. `git filter-repo` rewrites every commit so the
#    spinoff repo's history covers only the plugin.
git filter-repo \
    --path plugins/<kind>/<plugin>/ \
    --path-rename plugins/<kind>/<plugin>/:

# 2. Replace the kernel-shared LICENSE pointer with the plugin's
#    own copy if the plugin licenses differently from the kernel.
#    (Baseline plugins under `plugins/links/` are MIT, security and
#    handler plugins are Apache-2.0; check `LICENSE` in the plugin
#    tree before relicensing.)

# 3. Push to the new repo URL.
git remote set-url origin git@github.com:GoodNet-io/<plugin>.git
git push -u origin main

# 4. In `GoodNet-io/goodnet`, drop the now-spunoff path on the
#    next `dev → main` merge. The flake's per-plugin Nix package
#    switches to a `flake input = github:GoodNet-io/<plugin>`
#    reference so `nix run .#demo` still composes.
```

## Cross-repo build after spinoff

Each spinoff repo's `default.nix` already takes `goodnet-core` as
an input — that derivation in `GoodNet-io/goodnet`'s flake. The
spinoff repo's flake declares
`inputs.goodnet.url = "github:GoodNet-io/goodnet"` and exposes its
plugin via `pkgs.callPackage ./. { goodnet-core = goodnet.packages.${system}.goodnet-core; }`.

CMake consumers of the spunoff plugin write the same line they wrote
in-tree:

```cmake
find_package(GoodNet REQUIRED)
add_plugin(goodnet_<plugin> ${SOURCES})
target_link_libraries(goodnet_<plugin> PRIVATE GoodNet::sdk)
```

The plugin's standalone-mode preamble (already inside
`plugins/<kind>/<name>/CMakeLists.txt`) carries the
`if(NOT TARGET GoodNet::sdk) project(...) find_package(GoodNet REQUIRED)`
block — the exact same source compiles in either tree.

## What to verify before a spinoff push

1. `cd <plugin-tree> && cmake -B build -DCMAKE_PREFIX_PATH=<kernel-install>`
   succeeds against an out-of-tree kernel install.
2. `cmake --build build` produces the expected artefact
   (`lib<name>.so` for dlopen plugins, `lib<name>.a` for protocol
   layers).
3. `ctest --test-dir build` passes (when the plugin ships tests).
4. `nix build .#goodnet-<plugin>` from the original monorepo
   succeeds — the per-plugin derivation already composes through
   `goodnet-core` and the spinoff inherits the same shape.

## Things that do **not** travel with the plugin

- Kernel-side contracts (`docs/contracts/*.md` other than the
  plugin-private ones in `plugins/<x>/docs/`) — they describe the
  SDK boundary the plugin links against. Stay in `GoodNet-io/goodnet`.
- The `apps/goodnet/` operator CLI — kernel binary.
- Integration tests that compose multiple plugins
  (`tests/integration/`) — kernel-side composition suite.
- Manifest signing keys, deployment recipes — operator concern,
  ship in the kernel install package or the operator's own repo.
