# Downstream app setup

A new project that consumes the GoodNet kernel — a CLI, a daemon, a
gateway, an embedded client — used to require ten-plus manual steps
between `git init` and a first `cmake --build`: identity key
generation, manifest assembly, plugin `.so` resolution, config
write, dev shell selection, `LD_LIBRARY_PATH` plumbing. The
**bootstrap layer** collapses that into three commands.

## Three commands

```sh
nix run goodnet#init-app -- my-thing      # scaffold ./my-thing/
nix run goodnet#bootstrap-env             # one-time per-user XDG layout
cd my-thing
nix develop && cmake -B build && cmake --build build
./build/my-thing
```

`init-app` lays out the six-file consumer skeleton.
`bootstrap-env` populates `~/.local/share/goodnet/` with identity +
plugin set + manifest + sample config — once per user, not per
project. `nix develop` (= `nix develop goodnet#app`) drops into a
shell that exports the env vars the `goodnet_app(...)` CMake helper
and the `gn::sdk::Core` ctor both read.

## Components

### `nix run goodnet#init-app -- <NAME>`

Scaffolds `./<NAME>/` with:

| File             | Role                                                              |
|------------------|-------------------------------------------------------------------|
| `flake.nix`      | depends on `github:GoodNet-io/goodnet`, re-exports `app` devShell |
| `CMakeLists.txt` | `find_package(GoodNet)` + `goodnet_app(<NAME> main.cpp)`          |
| `main.cpp`       | minimal `gn::sdk::Core core;` template                            |
| `.envrc`         | `use flake` for direnv users                                      |
| `.gitignore`     | `build/`, `result*`, `.direnv/`                                   |
| `README.md`      | three-command setup recap                                         |

Name must match `[a-z][a-z0-9_-]*` and becomes both the directory
name and the CMake target name.

### `nix run goodnet#bootstrap-env`

Idempotent per-user layout:

```
~/.local/share/goodnet/
├── identity/
│   └── default.bin              # `goodnetd identity gen`
├── plugins/
│   └── lib*.so                  # baseline plugin set
├── manifests/
│   └── baseline.json            # `goodnetd manifest gen`
└── config.json                  # identity + manifest + plugin path
```

Baseline plugin set: link-tcp, link-udp, link-ws, security-noise,
security-null, handler-heartbeat. Missing derivations on a fresh
checkout are warned about but do not fail the whole step; the
remaining layout still becomes usable as plugins land.

Re-run with `--force` to regenerate identity + config (overwriting
operator edits). Plugin + manifest steps overwrite on every run so
a refresh picks up new plugin .so digests without `--force`.

When `goodnetd` is not on `PATH`, identity + manifest generation
degrade to instruction messages pointing at
`github:GoodNet-io/goodnetd`; install via
`nix profile install github:GoodNet-io/goodnetd` to wire those
steps in.

### `nix run goodnet#sample-peer`

Spawns a throwaway peer in a per-invocation `mktemp -d` so the
freshly-built consumer can dial it without first standing up a
second daemon by hand:

```sh
nix run goodnet#sample-peer &
# stdout:
#   peer_pubkey=<64 hex chars>
#   peer_url=tcp://0.0.0.0:9101
#   peer_workdir=/tmp/gn-sample-peer.XXXXXX
./build/my-thing
```

`SIGINT` / `SIGTERM` triggers the trap that kills the daemon and
removes the workdir. Override the listen URI through
`GOODNET_SAMPLE_PEER_URI`. Re-uses the user's bootstrap-env
plugin set + a fresh identity so the peer admits the same baseline
manifest the consumer dials against.

### `nix develop goodnet#app`

Pre-wired shell. Exports:

| Env var               | Default                                                 |
|-----------------------|---------------------------------------------------------|
| `GOODNET_CORE_LIB`    | `<goodnet-core>/lib/libgoodnet_kernel.so`               |
| `GOODNET_LIB_DIR`     | `<goodnet-core>/lib`                                    |
| `GOODNET_PLUGIN_PATH` | `~/.local/share/goodnet/plugins`                        |
| `GOODNET_IDENTITY`    | `~/.local/share/goodnet/identity/default.bin`           |
| `GOODNET_MANIFEST`    | `~/.local/share/goodnet/manifests/baseline.json`        |

`LD_LIBRARY_PATH` is augmented with both `GOODNET_LIB_DIR` and
`GOODNET_PLUGIN_PATH` so a freshly-built binary runs straight out
of `./build/` without a wrapping step. `buildInputs` carries
cmake, ninja, pkg-config, libsodium, openssl, and the kernel-side
`find_package(GoodNet)` closure (asio, spdlog, fmt, nlohmann_json)
through `inputsFrom`.

### `goodnet_app(<TARGET> sources...)` CMake helper

Installed under `<prefix>/lib/cmake/GoodNet/goodnet_app.cmake` and
auto-included by `find_package(GoodNet)`. Single call replaces:

```cmake
add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE
    GoodNet::sdk GoodNet::kernel_shared PkgConfig::SODIUM)
target_compile_features(my_app PRIVATE cxx_std_23)
set_target_properties(my_app PROPERTIES
    BUILD_RPATH   "${GOODNET_LIB_DIR};${GOODNET_PLUGIN_PATH}"
    INSTALL_RPATH "${GOODNET_LIB_DIR};${GOODNET_PLUGIN_PATH}")
```

with:

```cmake
find_package(GoodNet REQUIRED)
goodnet_app(my_app main.cpp)
```

`GOODNET_LIB_DIR` and `GOODNET_PLUGIN_PATH` resolve at configure
time. Resolution order:

1. CMake cache variable (already set explicitly by the caller)
2. Env var (`GOODNET_LIB_DIR` / `GOODNET_PLUGIN_PATH` — what the
   `app` devShell exports)
3. Env var `GOODNET_CORE_LIB` (dirname → `GOODNET_LIB_DIR`)
4. Imported target `GoodNet::kernel_shared`'s `IMPORTED_LOCATION`
   (find_package result), or `$XDG_DATA_HOME/goodnet/plugins` for
   the plugin path

After the macro returns, the caller may attach extra
`target_link_libraries` / `target_compile_definitions` / etc.
calls; the macro intentionally only owns the kernel + SDK +
libsodium link surface.

## Troubleshooting

### Binary fails to dlopen the kernel

```
my_app: error while loading shared libraries: libgoodnet_kernel.so:
  cannot open shared object file
```

Exit `nix develop` and re-enter so `LD_LIBRARY_PATH` re-picks up
`GOODNET_LIB_DIR`. Outside the dev shell, wrap the invocation:

```sh
LD_LIBRARY_PATH=$GOODNET_LIB_DIR:$GOODNET_PLUGIN_PATH ./build/my_app
```

The CMake helper sets both BUILD_RPATH and INSTALL_RPATH so a
binary built inside the shell already has the path embedded; the
wrapping is only needed for binaries built before this layer
landed.

### `bootstrap-env` reports plugins missing

```
bootstrap-env: link-tcp not in flake outputs yet — skipping.
```

The kernel flake itself only exposes the kernel today; loadable
plugins live in their own per-plugin gits (`github:GoodNet-io/
link-tcp` etc.) and are added to the kernel's local checkout via
`nix run goodnet#setup`. Re-run `bootstrap-env` after the plugins
materialise.

### `init-app` refuses to overwrite

```
init-app: ./my-thing already exists, refusing to clobber.
```

Either pick a new name, or remove the directory by hand
(`rm -rf my-thing`) and re-run — the scaffolder will not delete
existing files.

### `sample-peer` left a workdir behind

If the daemon exited uncleanly, the trap may have missed the
cleanup. The script prints the workdir path on every run; remove
it manually:

```sh
rm -rf /tmp/gn-sample-peer.XXXXXX
```

## Hardware keys (future)

`bootstrap-env` writes a file-backed identity (`identity/default.bin`,
64-byte libsodium Ed25519 secret key, mode `0600`) — this is the
**current default and the only built-in option**. A file copy is
an identity steal.

HSM-backed identity (PKCS#11 token, TPM 2.0, macOS Keychain,
WebAuthn) is on the roadmap and lands across a 5-phase refactor
documented in `docs/contracts/identity.en.md` §12. The
operator-facing workflow — `goodnetd identity import-hsm`,
`goodnetd doctor` HSM checks, `goodnetd quickstart --hsm` — is
sketched in `docs/operator/identity-hsm-setup.en.md` (draft,
gated until Phase 4 lands).

The bootstrap shape on this page is unchanged by the HSM work.
The Phase 5 `gn::sdk::Core` ctor gains an `Identity::from_hsm()`
factory; the file-backed path stays the default for projects that
do not opt in.

## SDK layers

| Headers | CMake target | For whom |
|---------|-------------|---------|
| `sdk/core.h` | `GoodNet::sdk` | Everyone — C ABI to start the kernel |
| `sdk/host_api.h` | `GoodNet::sdk` | Plugins — receive this struct from the kernel |
| `sdk/cpp/*.hpp` | `GoodNet::sdk_dx` | Plugins — C++ helpers wrapping the C ABI |
| `bridges/cpp/*.hpp` | `GoodNet::cpp` | Apps — RAII wrappers over `core.h` for C++ consumers |
| `core/*.hpp` | `GoodNet::kernel` | In-tree only — internal kernel headers, not for consumers |

`gn::sdk::Core` (in `bridges/cpp/`) is the entry point the scaffolded
`main.cpp` uses. It owns the kernel lifecycle that would otherwise live
in `main.cpp`. `sdk/cpp/` helpers are for plugin authors, not app authors;
the distinction is that plugins receive a `host_api` struct from the kernel,
while apps start the kernel through `core.h` and hold it via `gn::sdk::Core`.

## See also

* `nix/init-app.nix`, `nix/bootstrap-env.nix`, `nix/sample-peer.nix`
  — the hooks themselves.
* `nix/dev-shell-app.nix` — the `app` devShell wrapper.
* `cmake/goodnet_app.cmake` — the CMake helper macro.
* `bridges/cpp/core.hpp` — `gn::sdk::Core` RAII wrapper that the
  scaffolded `main.cpp` template opens against.
* `sdk/cpp/` — C++ plugin helpers (not for app consumers).
* `docs/operator/build.en.md` — full build reference including SDK
  layer table and SOVERSION details.
* `docs/contracts/plugin-manifest.en.md` — manifest format the
  bootstrap step generates.
* `docs/contracts/identity.en.md` — canonical identity contract
  including the 5-phase HSM-backend roadmap.
* `docs/operator/identity-hsm-setup.en.md` — forward-looking
  operator guide for HSM-backed identity (gated until Phase 4).
