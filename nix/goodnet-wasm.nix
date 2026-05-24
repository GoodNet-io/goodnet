# Kernel-core cross-build to WebAssembly / WASI.
#
# Route: **`pkgs.pkgsCross.wasi32`** — the wasi32 cross stdenv
# resolves cleanly at the current nixpkgs pin and exposes a
# `wasm32-unknown-wasi-clang++` wrapper with a static-libcxx
# sysroot. Emscripten (`pkgs.emscripten` + `emcc -sSTANDALONE_WASM=1`)
# is the documented fallback: same WASI-shaped output, but a heavier
# closure and a CMake recipe that does not pick the wasi32 stdenv up.
# Pin notes the route here so a future attempt understands the
# choice without re-deriving it.
#
# Subset built today (first of three WASM directions in
# `docs/ROADMAP.en.md` §WASM-web):
#
#   * `core/plugin/wire_codec.cpp`        — minimal CBOR codec used
#                                            by the subprocess-plugin
#                                            wire protocol.
#   * `plugins/protocols/gnet/wire.cpp`   — GNET v1 deframer +
#                                            header parser.
#
# Both TUs are exception-free under the guard added in
# `core/plugin/wire_codec.cpp` (the nixpkgs wasi32 libc++ is
# compiled with `LIBCXX_ENABLE_EXCEPTIONS=false`, see
# `pkgs/development/compilers/llvm/common/libcxx/default.nix`).
# Output is a single static archive `lib/libgoodnet-wasm.a`
# linkable into a downstream wasm32-wasi consumer (browser-side
# bridge, `wasmtime` host) plus a header tree at
# `include/goodnet/{sdk,core,plugins}` mirroring the in-tree
# layout so consumers `#include <sdk/types.h>` exactly as they
# do in a native build.
#
# Subset NOT in scope (deliberately):
#
#   * Sockets (`core/plugin/remote_host.cpp`,
#     `plugins/links/{tcp,udp,tls,ws,ice,quic,ipc}`) — WASI 1.0 has
#     no Berkeley socket surface; preview2 sockets are experimental
#     and not stable. Browser-side WebSocket / WebRTC adapters are
#     direction 2 of `docs/ROADMAP.en.md` §WASM-web.
#   * `dlopen` (`core/plugin/runtimes/dynamic.cpp`) — WASI preview1
#     has no dynamic linking; preview2 exposes a component-model
#     loader the kernel does not integrate against. The TU stays
#     in tree behind a `__wasi__` guard so a stray inclusion still
#     compiles to a `GN_ERR_NOT_FOUND` stub.
#   * `fork` / `execve` (`core/plugin/remote_host.cpp` POSIX path)
#     — WASI has neither. Subprocess plugin runtime is excluded
#     wholesale from the wasm-side source list.
#   * Threads — wasi-libc / wasi-libcxx on the nixpkgs pin ship
#     with `_LIBCPP_HAS_THREADS=0` and no pthread layer. The TUs
#     above are single-threaded by construction; bringing in
#     `core/kernel/timer_registry.cpp` or
#     `core/crypto/crypto_worker_pool.cpp` would require a
#     wasi-threads-enabled sysroot (preview2 + a `-pthread`
#     rebuild of libc++) and stays scoped out.
#   * Asio — header-only in principle, but the headers pull in
#     `<sys/socket.h>` / `<netinet/in.h>` / pthread types that the
#     wasi-sysroot does not provide. The kernel's IO surface is
#     orthogonal to the wire codec / framing layer and stays a
#     native-only concern.
#
# Drives the toolchain by hand rather than re-using the root
# `CMakeLists.txt`: the root CMake calls `find_package(spdlog)` /
# `find_package(OpenSSL)` etc., none of which resolve under
# `pkgsCross.wasi32`. The wasm subset has no such dependencies, so
# a five-line `clang++ -c` + `ar rcs` invocation produces the
# archive without dragging the full CMake graph through a cross
# stdenv that cannot satisfy it.
#
# Linux-host-only: pkgsCross runs on Linux and emits a WebAssembly
# module; the parent flake gates this attribute under `isLinux`.
{ pkgs, ... }:

let
  wasi = pkgs.pkgsCross.wasi32;
  cc   = wasi.stdenv.cc;

  # `wasm32-unknown-wasi-` is the binary prefix the cross wrapper
  # bin/ folder exposes; reading it off the stdenv avoids hard-
  # coding the triple when nixpkgs renames it.
  ccPrefix = wasi.stdenv.cc.targetPrefix;
in
# Use the cross stdenv so `hostPlatform` is the wasi target. That
# pairs with `meta.platforms = lib.platforms.wasi` cleanly — the
# native-stdenv form trips check-meta because `x86_64-linux` is
# not in the platform set. Same pattern as `goodnet-windows.nix`
# which goes through `cross.stdenv.mkDerivation`.
wasi.stdenv.mkDerivation {
  pname   = "goodnet-wasm";
  version = "1.0.0-rc6";

  src = pkgs.lib.cleanSourceWith {
    src    = ./..;
    filter = path: type:
      let
        rel = pkgs.lib.removePrefix (toString ./.. + "/") (toString path);
        top = builtins.head (pkgs.lib.splitString "/" rel);
      in
        # Only the subset the wasm-core build touches. Excludes
        # `build*`, `result*`, `bench`, `examples`, `tests`,
        # `bridges` — none of those reach a wasm linker today.
        builtins.elem top [
          "sdk" "core" "plugins" "cmake"
          "CMakeLists.txt" "LICENSE" "README.md"
        ];
  };

  # `cc` is the cross wrapper provided automatically by the cross
  # stdenv (`wasi.stdenv.mkDerivation` injects it as `$CXX`); no
  # explicit `nativeBuildInputs` entry is needed for the compiler.
  # The empty list satisfies stdenv's expectation without dragging
  # the native gcc15 toolchain into the build closure.
  nativeBuildInputs = [ ];

  dontConfigure = true;

  # Manual compile + archive. The wasi cross wrapper does the
  # libc++ wiring through `-D_LIBCPP_DISABLE_AVAILABILITY` style
  # defaults already; we only add the include paths the source
  # tree needs and pin `-std=c++23` so the same dialect as the
  # native kernel build applies.
  buildPhase = ''
    runHook preBuild

    mkdir -p obj

    # `-fno-exceptions` mirrors the libc++ build config so the
    # compiler does not emit landing pads the wasi-libcxx archive
    # cannot satisfy. The wire codec's lone `try/catch` block
    # already lives behind a `__cpp_exceptions` guard.
    CXX="${ccPrefix}c++"
    CXXFLAGS="-std=c++23 -O2 -fno-exceptions -I ."

    set -x
    $CXX $CXXFLAGS -c -o obj/wire_codec.o core/plugin/wire_codec.cpp
    # TODO: gnet extracted to GoodNet-io/protocol-gnet — wire WASM build separately
    # $CXX $CXXFLAGS -c -o obj/gnet_wire.o   plugins/protocols/gnet/wire.cpp

    # Archive into a single `.a`. `ranlib` is implicit through the
    # wasm32-unknown-wasi-ar wrapper.
    ${ccPrefix}ar rcs lib/libgoodnet-wasm.a \
      obj/wire_codec.o
    set +x

    runHook postBuild
  '';

  preBuild = ''
    mkdir -p lib
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out/lib $out/include/goodnet

    cp lib/libgoodnet-wasm.a $out/lib/

    # Mirror the source-tree header layout so a downstream consumer
    # writes `#include <sdk/types.h>` against `$out/include/goodnet`
    # the same way an in-tree TU writes against the repo root.
    cp -r sdk        $out/include/goodnet/
    # Only the headers that the wasm-side subset can include
    # without dragging the unbuilt POSIX bits. `core/plugin/` ships
    # the wire codec contract; the rest stays out so a consumer
    # cannot accidentally include `kernel/timer_registry.hpp` etc.
    mkdir -p $out/include/goodnet/core/plugin
    install -m 0644 \
      core/plugin/wire_codec.hpp \
      core/plugin/dl_compat.hpp \
      $out/include/goodnet/core/plugin/

    # TODO: gnet extracted to GoodNet-io/protocol-gnet — wire WASM build separately
    # mkdir -p $out/include/goodnet/plugins/protocols/gnet
    # install -m 0644 \
    #   plugins/protocols/gnet/wire.hpp \
    #   $out/include/goodnet/plugins/protocols/gnet/

    runHook postInstall
  '';

  doCheck = false;

  # Manifest line for `nix flake check` / operator introspection.
  # `lib/platforms.wasi` covers wasm32-wasi + wasm64-wasi; the
  # parent flake guard on `isLinux` keeps the attribute itself off
  # macOS / Windows hosts.
  meta = {
    description =
      "GoodNet kernel-core subset (wire codec + GNET framing) "
      + "cross-built to wasm32-wasi via pkgsCross.wasi32.";
    platforms = pkgs.lib.platforms.wasi;
    license   = pkgs.lib.licenses.mit;
  };

  # `passthru.route` documents which of the two WASM directions
  # this derivation took at eval time; the value also surfaces in
  # `nix flake show` so a CI dashboard can render the chosen
  # toolchain. If a future pin drops `pkgsCross.wasi32` and the
  # fallback emscripten path lands instead, flip this string and
  # adjust the build phase to call `emcc -sSTANDALONE_WASM=1`.
  passthru.route = "pkgsCross.wasi32";
  passthru.scope = [
    "core/plugin/wire_codec.cpp"
    # "plugins/protocols/gnet/wire.cpp"  # extracted to GoodNet-io/protocol-gnet
  ];
  # `skip_reason` stays empty when the build succeeds. A non-empty
  # value here is the convention the CI `wasm-cross-build` job
  # reads to print a "skipped" line instead of a failure when a
  # nixpkgs pin breaks the toolchain.
  passthru.skip_reason = "";
}
