# GoodNet build reference

Three canonical build paths exist; pick the one that matches your role.

| Path | Who | Entry point |
|------|-----|-------------|
| **Monorepo dev** | Kernel / plugin contributor | `nix run .#build` or `cmake --preset dev` inside `nix develop` |
| **Release tarball** | Operator downloading binaries | `nix build` → patchelf → `.tar.gz` |
| **Standalone downstream** | App author using the SDK | `find_package(GoodNet)` against an installed release |

---

## 1. Monorepo dev

### Quick start

```sh
git clone https://github.com/GoodNet-io/goodnet.git
cd goodnet
nix run .#setup       # clone plugins, install hooks
nix run .#build       # debug build → build/
nix run .#test        # 1510 tests
```

`nix run .#build` never requires `nix develop`. It resolves the pinned
toolchain from the flake and calls cmake + ninja inside a nix shell —
`libstdc++.so.6` and every compile dependency come from the store, not
from the system. The GLIBCXX version mismatch that used to break `ctest`
outside `nix develop` does not occur.

### cmake --preset

For IDE integration or incremental builds inside `nix develop`:

```sh
nix develop
cmake --preset dev        # Debug, all tests/plugins/apps ON → build/
cmake --build build
ctest --test-dir build
```

Available presets (see `CMakePresets.json`):

| Preset | BUILD_TYPE | Apps | Plugins | Tests | Dir |
|--------|-----------|------|---------|-------|-----|
| `dev` | Debug | ON | ON | ON | `build/` |
| `release` | Release + LTO | ON | ON | OFF | `build-release/` |
| `ci-asan` | Debug + ASan/UBSan | OFF | ON | ON | `build-asan/` |
| `ci-tsan` | Debug + TSan | OFF | ON | ON | `build-tsan/` |
| `kernel-only` | Debug | OFF | OFF | ON | `build-kernel-only/` |

All presets set `CMAKE_EXPORT_COMPILE_COMMANDS=ON` and use Ninja.

### What gets built

A full `cmake --preset dev` build produces:

```
build/
  lib/libgoodnet_kernel.so.1.0.0   ← runtime kernel (SOVERSION 1)
  lib/libgoodnet_kernel.so.1       ← symlink (SONAME)
  lib/libgoodnet_kernel.so         ← dev symlink (NAMELINK)
  lib/libgoodnet.a                 ← SDK static archive
  lib/cmake/GoodNet/               ← find_package files
  plugins/                         ← all bundled plugin .so files
  bin/goodnetd                     ← operator CLI
  bin/gssh                         ← SSH-over-GoodNet CLI
```

### Updating plugin flake.lock files

Plugin flakes pin the kernel through their own `flake.lock`. When the
kernel advances, update all locks in one shot:

```sh
nix run .#update-locks
```

This iterates every `plugins/*/*/flake.lock` and calls
`nix flake update --override-input goodnet path:.` in that directory.

---

## 2. Release tarball

The CI release pipeline (``.forgejo/workflows/release.yml``) runs on a
tag push and produces portable `.tar.gz` files that run on any glibc
Linux without Nix.

### Build steps (what CI does)

```sh
# kernel + plugins
nix build --print-build-logs

# goodnetd — built from monorepo with inputs pointing at the checked-out tree
nix build ./apps/goodnetd# \
  --override-input goodnet path:. \
  --override-input protocol-gnet path:./plugins/protocols/gnet \
  --print-build-logs -o result-goodnetd

# gssh
nix build ./apps/gssh# --print-build-logs -o result-gssh
```

### Tarball layout

```
goodnet-<TAG>-linux-x86_64/
  bin/goodnetd          ← operator daemon CLI
  bin/gssh              ← SSH-over-GoodNet CLI
  lib/
    libgoodnet_kernel.so.1.0.0
    libgoodnet_kernel.so.1     ← SONAME symlink
    <transitive Nix store deps copied here>
  plugins/
    lib*.so             ← all bundled plugins
```

### Portability mechanism

patchelf rewrites RPATH and interpreter on every binary before
archiving:

- Binaries in `bin/`: `--set-rpath '$ORIGIN/../lib'` + correct
  interpreter (`/lib64/ld-linux-x86-64.so.2` on x86_64)
- Libraries in `lib/`: `--set-rpath '$ORIGIN'`
- Plugins in `plugins/`: `--set-rpath '$ORIGIN/../../lib'`

This means `libgoodnet_kernel.so.1` resolves relative to the unpacked
directory tree, not from `/nix/store/…`.

### Running the tarball on a stock Linux

```sh
tar xzf goodnet-v1.0.0-rc6-linux-x86_64.tar.gz
./bin/goodnetd version
```

No `LD_LIBRARY_PATH` is needed — the embedded RPATH covers it.

---

## 3. Standalone downstream

A project that uses the GoodNet SDK but does not live in the monorepo.

### CMake consumer pattern

```cmake
find_package(GoodNet REQUIRED)
# optional — only if your app uses the gnet protocol
find_package(GoodNetProtocolGnet QUIET)

add_executable(my-app main.cpp)
target_link_libraries(my-app PRIVATE GoodNet::sdk GoodNet::kernel_shared)
# or use the helper macro:
# goodnet_app(my-app main.cpp)
```

`find_package(GoodNet)` succeeds when:
- the kernel is installed (`nix build`, then `cmake --install`), or
- the `GoodNet::sdk` target is already defined (you're inside the
  monorepo and did not guard with `if(NOT TARGET GoodNet::sdk)`).

### Scaffold a new project

```sh
nix run goodnet#init-app -- my-thing
cd my-thing
nix run goodnet#bootstrap-env   # one-time: identity + plugins + manifest
nix develop                     # drops into app devShell
cmake -B build && cmake --build build
```

See `docs/operator/downstream-app-setup.en.md` for the full workflow.

### `.goodnet/` source override

To develop an app against a local kernel checkout without installing
the kernel globally, symlink the in-tree build outputs:

```sh
# inside your app project:
mkdir -p .goodnet
ln -s /path/to/goodnet/build/lib   .goodnet/lib
ln -s /path/to/goodnet/build/plugins .goodnet/plugins
# then point CMake at the local lib:
cmake -B build -DGOODNET_LIB_DIR=$PWD/.goodnet/lib
```

`.goodnet/` is gitignored and never committed.

---

## 4. SDK layers

| Headers | CMake target | For whom |
|---------|-------------|---------|
| `sdk/core.h` | `GoodNet::sdk` | Everyone — C ABI to start the kernel |
| `sdk/host_api.h` | `GoodNet::sdk` | Plugins — receive this struct from the kernel |
| `sdk/cpp/*.hpp` | `GoodNet::sdk_dx` | Plugins — C++ helpers wrapping the C ABI |
| `bridges/cpp/*.hpp` | `GoodNet::cpp` | Apps — RAII wrappers over `core.h` for C++ consumers |
| `core/*.hpp` | `GoodNet::kernel` | In-tree only — internal kernel headers, not for consumers |

`sdk/core.h` is the only stable surface that all three paths share.
`bridges/cpp/` (`GoodNet::cpp` / `gn::sdk::Core`) is the recommended
starting point for new C++ apps; it owns the lifecycle that would
otherwise live in `main.cpp`.

### Shared library versioning (SOVERSION)

The runtime library follows the GNU shared-library convention:

```
libgoodnet_kernel.so.1.0.0   ← actual file (VERSION = project version)
libgoodnet_kernel.so.1       ← SONAME symlink  (SOVERSION = major)
libgoodnet_kernel.so         ← dev symlink      (NAMELINK, dev package only)
```

SOVERSION tracks `GN_SDK_VERSION_MAJOR`. A MAJOR bump means the
`host_api` C ABI changed in an incompatible way (slot removed, slot
reordered, size-prefix changed). When MAJOR bumps, increment SOVERSION
in `core/CMakeLists.txt` and update both the `SOVERSION` and `VERSION`
properties on `goodnet_kernel_shared`.

For packaging: the runtime package installs with `NAMELINK_SKIP` (only
`libgoodnet_kernel.so.1.0.0` and the SONAME symlink); the `-dev` package
installs with `NAMELINK_ONLY` (only `libgoodnet_kernel.so`). This
matches the Debian/RPM split-package convention.

---

## 5. Cross-platform matrix

See [`nix-build-system.en.md § Cross-platform builds`](nix-build-system.en.md)
for the full table with SDK requirements and WASM threading notes.

| Target | `nix build .#` | Status |
|--------|---------------|--------|
| Linux x86_64 | `default` | Stable |
| Linux aarch64 | `default --system aarch64-linux` | Stable |
| Windows x86_64 | `goodnet-windows` | Advisory |
| macOS x86_64/aarch64 | `goodnet-darwin-{x86_64,aarch64}` | Advisory (Apple SDK) |
| Android aarch64 | `goodnet-android-aarch64` | CI smoke, kernel only |
| WASM (WASI / browser) | `goodnet-wasm`, `goodnet-wasm-emscripten` | Subset / full |

musl static build (no dynamic deps, distroless-ready):

```sh
nix build .#goodnet-core-static
# or: nix run .#build -- static
```

---

## 6. CMakePresets.json reference

The root `CMakePresets.json` declares five presets. All share:
- `CMAKE_EXPORT_COMPILE_COMMANDS=ON`
- Ninja generator
- `CMAKE_CXX_STANDARD=23`

**dev** — daily contributor use.
All feature flags ON. Debug symbols. Tests included. Apps included.

**release** — matches what `nix run .#build -- release` produces.
LTO enabled, no tests, no debug symbols.

**ci-asan** — AddressSanitizer + UBSan. Apps OFF (goodnetd links kernel
which has additional asan suppressions; run asan on kernel/plugin tests
directly, not through the daemon).

**ci-tsan** — ThreadSanitizer. Same apps-OFF reasoning.

**kernel-only** — minimal: no plugins, no apps, kernel + tests only.
Fastest configure and build; useful when iterating on `core/` alone.

Custom flags still work alongside a preset:
```sh
cmake --preset dev -DGOODNET_BUILD_EXAMPLES=OFF
```
