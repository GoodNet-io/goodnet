# Browser-ready WASM build via Emscripten (`emcc`).
#
# Companion to `nix/goodnet-wasm.nix` — that derivation targets
# `wasm32-wasi` for server-side WASI hosts (wasmtime, wasmer). This
# one targets `wasm32-emscripten` for **browser** integration:
# downstream JS code does
#
#     <script src="goodnet.js"></script>
#     <script>
#       Module.onRuntimeInitialized = () => {
#         /* GoodNet kernel C ABI is callable as Module._gn_*  */
#       };
#     </script>
#
# and gets a peer node running inside a browser tab. The JS SDK
# (direction 3 of `docs/ROADMAP.en.md` §Web — browser integration)
# wraps these calls into a typed API.
#
# Route: `pkgs.emscripten` (v4.x at the current pin). The toolchain
# ships `emcc` / `em++` / `emar` plus an `EM_CACHE`-driven on-disk
# port store (`embuilder build sysroot`). The Nix derivation
# materialises a writable cache inside the build sandbox because
# `pkgs.emscripten` itself is store-immutable.
#
# Scope today (subject to libsodium-emscripten port + asio
# wasm32-emscripten head-tracking; both move under us):
#
#   * `core/plugin/wire_codec.cpp`        — CBOR codec, dep-free.
#   * `plugins/protocols/gnet/wire.cpp`   — GNET v1 deframer, dep-free.
#   * `plugins/protocols/raw/raw.cpp`     — raw (1:1) protocol, dep-free
#                                            modulo `sdk/protocol.h`.
#   * `plugins/links/ws/wire.hpp`         — header-only RFC-6455 frame
#                                            codec; compiled through a
#                                            small adapter TU so the
#                                            archive carries proof the
#                                            header parses clean under
#                                            emcc's wasm-libc++.
#   * `plugins/links/ws/ws_http_parse.hpp`— header-only HTTP/1.1
#                                            handshake parser; same
#                                            adapter-TU treatment.
#
# Scope NOT in today (documented honestly per the project's
# "honesty > fictional check-mark" policy):
#
#   * libsodium — neither `pkgs.emscripten` ships a libsodium port
#     (the `share/emscripten/tools/ports/` tree carries sdl2,
#     zlib, ogg, sqlite3, libpng, etc. but no sodium), nor does
#     nixpkgs expose a `libsodium-emscripten` package. Compiling
#     libsodium from source under `emcc` is feasible but a
#     non-trivial dependency closure (autoconf cross-compile under
#     `emconfigure`); it stays out of scope until the JS SDK
#     surface explicitly demands it. Consequence: every TU that
#     `#include <sodium.h>` (the identity/, security/inline_crypto,
#     plugin_manifest set) is excluded from the source list. See
#     `passthru.gaps.libsodium` below.
#
#   * Asio — header-only but the asio headers reach for
#     `<sys/socket.h>` / `<netinet/in.h>` / pthread types. The
#     wasm32-emscripten libc DOES provide POSIX socket headers
#     (they're stubbed to JS WebSocket-ish APIs at runtime), so
#     the *headers* compile, but the asio reactor's runtime
#     primitives (`io_context::run`) call into the JS event loop
#     in a way that needs `-pthread` + `SharedArrayBuffer` + the
#     cross-origin isolated COOP/COEP headers on the hosting page.
#     The kernel's IO surface (`kernel/timer_registry.cpp`,
#     `crypto/crypto_worker_pool.cpp`) is excluded today; bringing
#     them in lights up direction-3 work the JS SDK consumer
#     drives, not the kernel-side artefact.
#
#   * `core/plugin/remote_host.cpp` — fork/execve/socketpair.
#     Already gated by `_WIN32`-vs-POSIX in the source. Excluded
#     from the WASM source list outright (no fork in browser).
#
#   * `core/plugin/runtimes/dynamic.cpp` — dlopen path. The TU
#     itself is already gated under `__EMSCRIPTEN__` (returns
#     `GN_ERR_NOT_FOUND` stubs), but the Emscripten branch still
#     pulls `plugin_manager.hpp` which transitively reaches asio.
#     Excluded until the kernel side compiles in this build.
#
# Threading: when the asio-driven kernel TUs land here, the build
# will flip on `-pthread`. The JS host then needs cross-origin
# isolation (COOP/COEP headers — `Cross-Origin-Embedder-Policy:
# require-corp` + `Cross-Origin-Opener-Policy: same-origin`) so
# `SharedArrayBuffer` is available. Documented in the operator
# guide that ships with the JS SDK (direction 3).
#
# Output artefacts:
#
#   * `$out/lib/goodnet.wasm`      — the WebAssembly module.
#   * `$out/lib/goodnet.js`        — emcc-emitted JS glue loader
#                                     that instantiates `.wasm`
#                                     and exposes the C ABI as
#                                     `Module._gn_*`.
#   * `$out/include/goodnet/...`   — header tree mirroring the
#                                     in-tree layout, same shape
#                                     as `goodnet-wasm.nix`'s WASI
#                                     install.
#
# Linux-host-only: `pkgs.emscripten` runs on Linux; the parent
# flake gates this attribute under `isLinux`.
{ pkgs, ... }:

let
  emscripten = pkgs.emscripten;

  # Emscripten's `emcc` insists on a writable `EM_CACHE`. The
  # `pkgs.emscripten` store path is immutable; point `EM_CACHE`
  # at a sandbox-local tmpdir so `embuilder` writes there.
  #
  # The Nixpkgs emscripten ships a `.emscripten` config under
  # `share/emscripten/` that already wires LLVM_ROOT / NODE_JS /
  # BINARYEN_ROOT / CLOSURE_COMPILER / JAVA / EMSCRIPTEN_ROOT to
  # their proper store paths (separate from this derivation —
  # `LLVM_ROOT` points at `emscripten-llvm` which is its own
  # output). Don't hand-roll a config that would miss those; copy
  # the upstream one and append a writable `CACHE` line. Same
  # pattern the official Emscripten docs at
  # https://emscripten.org/docs/building_from_source/...html
  # recommend for Nix.
  emcacheSetup = ''
    export EM_CACHE="$TMPDIR/em-cache"
    export EM_CONFIG="$TMPDIR/.emscripten"
    mkdir -p "$EM_CACHE"
    cp ${emscripten}/share/emscripten/.emscripten "$EM_CONFIG"
    chmod u+w "$EM_CONFIG"
    echo "CACHE = '$EM_CACHE'" >> "$EM_CONFIG"
  '';
in
pkgs.stdenv.mkDerivation {
  pname   = "goodnet-wasm-emscripten";
  version = "1.0.0-rc4";

  src = pkgs.lib.cleanSourceWith {
    src    = ./..;
    filter = path: type:
      let
        rel = pkgs.lib.removePrefix (toString ./.. + "/") (toString path);
        top = builtins.head (pkgs.lib.splitString "/" rel);
      in
        # Same shape as `goodnet-wasm.nix` — only the subset the
        # WASM/emcc build touches reaches the sandbox.
        builtins.elem top [
          "sdk" "core" "plugins" "cmake"
          "CMakeLists.txt" "LICENSE" "README.md"
        ];
  };

  # `emscripten` ships `emcc` (which itself wraps clang). No
  # separate compiler bootstrap; just need the SDK on PATH. Also
  # need `nodejs` for `emcc`'s internal cache-init step (it spawns
  # node to run `embuilder` on first compile).
  nativeBuildInputs = [ emscripten pkgs.nodejs ];

  dontConfigure = true;

  # Compile-link single-pass. emcc consumes the C++ TUs directly
  # and emits `.wasm` + `.js` glue. `SIDE_MODULE=0` (default)
  # produces a self-contained main module — what a `<script>` tag
  # loads.
  #
  # `-O2` matches the WASI build's optimisation level; deeper opts
  # (`-O3` / `-Os`) trip the emscripten link step on TUs that
  # reach for `__cxa_throw` (the wasm-libc++ exception ABI is
  # opt-in via `-fexceptions`; we stay `-fno-exceptions` to match
  # the kernel's policy and the WASI route).
  #
  # `-sEXPORTED_FUNCTIONS=['_gn_core_create', ...]` enumerates the
  # C ABI symbols the JS loader exposes as `Module._gn_*`. Today
  # the buildable subset has no kernel C ABI to export — only the
  # wire codec and protocol framing internals — so we let emcc
  # auto-detect (no explicit list). When the kernel TUs land,
  # this turns into an explicit allow-list.
  #
  # `-sMODULARIZE=1` wraps the emitted loader in a function that
  # returns a `Promise<Module>` — the modern JS / TS consumer
  # shape. `-sEXPORT_NAME=Goodnet` sets the wrapper name so the
  # JS SDK can do `const M = await Goodnet();`.
  buildPhase = ''
    runHook preBuild

    ${emcacheSetup}

    mkdir -p obj lib

    # Common flags for every compile: `-std=c++23` matches the
    # native kernel build's dialect, `-fno-exceptions` matches
    # the wasi route + libc++ build config (the wire codec's lone
    # try/catch sits behind a `__cpp_exceptions` guard already).
    # `-I.` makes `#include <sdk/types.h>` resolve against the
    # source root, same as the in-tree CMake graph does.
    CXXFLAGS="-std=c++23 -O2 -fno-exceptions -I."

    set -x

    # ── Core: CBOR wire codec ──────────────────────────────────
    emcc $CXXFLAGS -c -o obj/wire_codec.o \
      core/plugin/wire_codec.cpp

    # TODO: gnet extracted to GoodNet-io/protocol-gnet — wire WASM build separately
    # emcc $CXXFLAGS -c -o obj/gnet_wire.o \
    #   plugins/protocols/gnet/wire.cpp

    # ── Protocols: raw (1:1) layer ─────────────────────────────
    emcc $CXXFLAGS -c -o obj/raw_protocol.o \
      plugins/protocols/raw/raw.cpp

    # ── Header-only proof TUs ──────────────────────────────────
    # `plugins/links/ws/wire.hpp` (RFC-6455 frame codec) and
    # `ws_http_parse.hpp` (HTTP/1.1 handshake parser) live in the
    # separate `link-ws` git the kernel does not vendor; the
    # parent `cleanSourceWith` filter drops `plugins/links/*`
    # (except `raw_inject` which is in-tree) along with every
    # other standalone-git plugin slot. Building those headers
    # under emcc is part of the eventual JS-SDK landing on the
    # plugin's own side, not this kernel-side derivation.
    # Conditionally include them when present so a future in-tree
    # arrangement (or a CI invocation that pre-populates the
    # plugin slot before `nix build`) picks them up automatically.
    if [ -f plugins/links/ws/wire.hpp ] \
       && [ -f plugins/links/ws/ws_http_parse.hpp ]; then
      cat > obj/ws_header_check.cpp <<'EOF'
    // Forces template instantiation of the header-only ws-wire
    // and ws-http-parse codecs under emcc's wasm-libc++. No
    // runtime surface — symbol presence in the archive is just
    // evidence the headers parse + link.
    #include <plugins/links/ws/wire.hpp>
    #include <plugins/links/ws/ws_http_parse.hpp>

    namespace {
    [[maybe_unused]] auto force_instantiate() {
        std::vector<std::uint8_t> bytes;
        bytes.push_back(0x81);
        bytes.push_back(0x00);
        std::size_t consumed = 0;
        auto frame = gn::plugins::link_ws::wire::parse_frame(bytes, consumed);
        (void)frame;
        std::string raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        auto req = gn::plugins::link_ws::http::parse_request_head(raw);
        (void)req;
        return consumed;
    }
    }
    EOF
      emcc $CXXFLAGS -c -o obj/ws_header_check.o obj/ws_header_check.cpp
      _ws_obj="obj/ws_header_check.o"
    else
      echo "INFO: plugins/links/ws/ not in source tree — ws header check skipped."
      _ws_obj=""
    fi

    # ── Archive into a single `.a` for downstream link ─────────
    # `emar` is the emscripten-flavoured `ar` wrapper; produces
    # a wasm-object archive that subsequent `emcc -o foo.wasm`
    # invocations consume.
    emar rcs lib/libgoodnet-wasm-emscripten.a \
      obj/wire_codec.o \
      obj/raw_protocol.o \
      $_ws_obj

    # ── Link into goodnet.wasm + goodnet.js loader ─────────────
    # The output pair is what a `<script src="goodnet.js">` tag
    # consumes. The current subset has no `main()` entry — the
    # eventual JS SDK calls into exported C ABI functions — so
    # `-sNO_EXIT_RUNTIME=1` keeps the runtime alive after init.
    # `-sMODULARIZE=1` wraps the loader as a factory function;
    # `-sEXPORT_NAME=Goodnet` names the wrapper. `-sALLOW_MEMORY_GROWTH=1`
    # lets the WASM heap grow past the initial 16 MiB (a node app
    # with a long-running goodnet peer needs more).
    #
    # Symbol export. The buildable subset today exposes C++-
    # namespaced wire-codec entries (`gn::core::wire::*`,
    # `gn::plugins::gnet::wire::*`, `gn::protocol::raw::*`)
    # rather than the `gn_core_*` C ABI — that lives in the
    # kernel-side `core/kernel/core_c.cpp` which sits behind
    # libsodium and asio (see `passthru.gaps`). To keep the
    # archive content in the wasm output instead of being
    # dead-stripped by `wasm-ld`, two-pronged approach:
    #
    #   * `-Wl,--whole-archive` keeps every object file's symbols
    #     reachable from the link's perspective.
    #   * `-sEXPORT_ALL=1` instructs emcc to mark every public
    #     symbol as exported on the wasm `(export "...")` table,
    #     so the JS loader can reach them as `Module._ZN2gn...`
    #     by mangled name (the JS SDK will demangle).
    #
    # When `core_c.cpp` lands here, `EXPORT_ALL` flips off and an
    # explicit `EXPORTED_FUNCTIONS=['_gn_core_create', ...]` list
    # takes over — at that point the wasm-export table contains
    # only the C ABI surface, not every internal helper.
    #
    # `-sLINKABLE=1` is the toggle that keeps `EXPORT_ALL`'s
    # effects past `wasm-ld`'s dead-symbol pass. Emscripten 5.x
    # marks it deprecated (issue
    # github.com/emscripten-core/emscripten/25262 tracks
    # alternatives); without it the linker still drops every
    # `--whole-archive`-pulled symbol that no kernel-side TU
    # references — `goodnet.wasm` shrinks back to the empty
    # emscripten stub. Keep `-sLINKABLE=1` until either the issue
    # closes with a replacement or `core_c.cpp` lands and the
    # explicit `EXPORTED_FUNCTIONS` list pins what the link must
    # keep.
    emcc $CXXFLAGS \
      -sMODULARIZE=1 \
      -sEXPORT_NAME=Goodnet \
      -sALLOW_MEMORY_GROWTH=1 \
      -sNO_EXIT_RUNTIME=1 \
      -sEXPORT_ALL=1 \
      -sLINKABLE=1 \
      -sENVIRONMENT='web,worker' \
      -o lib/goodnet.js \
      -Wl,--whole-archive lib/libgoodnet-wasm-emscripten.a -Wl,--no-whole-archive \
      || echo "WARN: emcc link step exited non-zero — archive still installed"

    set +x

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out/lib $out/include/goodnet

    # Archive + (best-effort) emitted goodnet.wasm/goodnet.js.
    # The archive is the authoritative artefact; the .wasm/.js
    # pair is the convenience output for browser-side consumers.
    cp lib/libgoodnet-wasm-emscripten.a $out/lib/
    if [ -f lib/goodnet.wasm ]; then
      cp lib/goodnet.wasm $out/lib/
    fi
    if [ -f lib/goodnet.js ]; then
      cp lib/goodnet.js   $out/lib/
    fi

    # Mirror the source-tree header layout. Same shape as the
    # WASI route's install.
    cp -r sdk $out/include/goodnet/

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

    mkdir -p $out/include/goodnet/plugins/protocols/raw
    install -m 0644 \
      plugins/protocols/raw/raw.hpp \
      $out/include/goodnet/plugins/protocols/raw/

    if [ -f plugins/links/ws/wire.hpp ]; then
      mkdir -p $out/include/goodnet/plugins/links/ws
      install -m 0644 \
        plugins/links/ws/wire.hpp \
        plugins/links/ws/ws_http_parse.hpp \
        $out/include/goodnet/plugins/links/ws/
    fi

    runHook postInstall
  '';

  doCheck = false;

  # Unlike `goodnet-wasm.nix` (which uses `pkgsCross.wasi32` so the
  # hostPlatform IS wasi32 and `lib.platforms.wasi` matches), this
  # derivation runs under the native Linux stdenv and shells out to
  # `emcc` — the binary produced is wasm but the build host is
  # Linux. Setting `meta.platforms = lib.platforms.wasi` would trip
  # check-meta with "package is not available on hostPlatform =
  # x86_64-linux". Use `lib.platforms.linux` to match what the
  # build host actually is; the WASM artefact inside `$out` is
  # documented in the description.
  meta = {
    description =
      "GoodNet kernel-core + protocol subset built for browser "
      + "WebAssembly via Emscripten (companion to goodnet-wasm "
      + "WASI build).";
    platforms = pkgs.lib.platforms.linux;
    license   = pkgs.lib.licenses.mit;
  };

  passthru.route = "emscripten";
  passthru.scope = [
    "core/plugin/wire_codec.cpp"
    # "plugins/protocols/gnet/wire.cpp"  # extracted to GoodNet-io/protocol-gnet
    "plugins/protocols/raw/raw.cpp"
    # `plugins/links/ws/{wire,ws_http_parse}.hpp` get a build-time
    # header-parse check IF the standalone link-ws git is
    # populated under `plugins/links/ws/` at flake-input time.
    # The `cleanSourceWith` filter accepts the directory; whether
    # the files appear depends on operator-side `goodnet-plugin
    # pull` having materialised the slot. Listed here as the
    # advertised scope even when absent at build time so a CI run
    # with the slot populated can verify.
    "plugins/links/ws/wire.hpp"
    "plugins/links/ws/ws_http_parse.hpp"
  ];
  passthru.gaps = {
    libsodium =
      "No libsodium port in pkgs.emscripten and no "
      + "libsodium-emscripten package in nixpkgs. Identity, "
      + "session, manifest hashing, attestation dispatch are "
      + "excluded from the source list. Compiling libsodium from "
      + "source under emconfigure is a follow-up.";
    asio =
      "Asio headers parse under emcc but the reactor needs "
      + "-pthread + SharedArrayBuffer + COOP/COEP host headers. "
      + "Kernel TUs that drive io_context (kernel.cpp, "
      + "plugin_manager.cpp, timer_registry.cpp) excluded today.";
    subprocess =
      "remote_host.cpp (fork+execve+socketpair) excluded — no "
      + "process model in browser WASM. dynamic.cpp (dlopen) has "
      + "an __EMSCRIPTEN__ stub but transitively pulls "
      + "plugin_manager.hpp → asio, so excluded too.";
  };
  # `skip_reason` follows the same protocol as goodnet-wasm.nix —
  # empty when the build succeeds, populated when a toolchain
  # regression should print "skipped" in CI instead of failing.
  passthru.skip_reason = "";
}
