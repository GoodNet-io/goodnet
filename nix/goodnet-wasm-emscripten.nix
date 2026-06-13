# Browser-ready WASM build via Emscripten (`emcc`).
#
# Produces a self-contained WASM module exposing the full GoodNet
# kernel C ABI (`sdk/core.h`) as `Module._gn_core_*`. Downstream
# JS/TS code loads the pair:
#
#     const M = await Goodnet();   // goodnet.js factory
#     const core = M._gn_core_create();
#     M._gn_core_init(core);
#     M._gn_core_start(core);
#
# and gets a peer kernel running inside a browser tab or a Node.js
# process. The `bridges/js/src/WasmTransport.ts` wrapper provides a
# typed API over these raw calls.
#
# Threading: the kernel drives an asio io_context thread pool.
# Emscripten maps pthreads to Web Workers. The hosting page MUST
# serve two response headers:
#
#     Cross-Origin-Opener-Policy: same-origin
#     Cross-Origin-Embedder-Policy: require-corp
#
# so that `SharedArrayBuffer` (required by Emscripten pthreads) is
# available. Without these headers the module will throw on init.
#
# Output artefacts:
#
#   $out/lib/goodnet.js        — emcc-emitted loader (factory function)
#   $out/lib/goodnet.wasm      — WebAssembly module
#   $out/lib/goodnet.worker.js — pthread Web Worker bootstrap
#   $out/lib/libgoodnet-wasm-emscripten.a — intermediate archive
#   $out/include/goodnet/      — SDK headers mirroring in-tree layout
#
# Linux-host-only: `pkgs.emscripten` runs on Linux; the flake gates
# this output under `isLinux`.
{ pkgs, version ? "dev", ... }:

let
  emscripten = pkgs.emscripten;

  # Emscripten's `emcc` insists on a writable `EM_CACHE`. Copy the
  # upstream config (which already wires LLVM_ROOT / NODE_JS /
  # BINARYEN_ROOT / EMSCRIPTEN_ROOT to their store paths) and append
  # a writable CACHE line pointing into the sandbox tmpdir.
  emcacheSetup = ''
    export EM_CACHE="$TMPDIR/em-cache"
    export EM_CONFIG="$TMPDIR/.emscripten"
    mkdir -p "$EM_CACHE"
    cp ${emscripten}/share/emscripten/.emscripten "$EM_CONFIG"
    chmod u+w "$EM_CONFIG"
    echo "CACHE = '$EM_CACHE'" >> "$EM_CONFIG"
  '';

  # Full C ABI surface from sdk/core.h — every GN_EXPORT symbol.
  # `_malloc` / `_free` are included so JS can allocate buffers for
  # binary payloads passed into `gn_core_send_to` / callbacks.
  exportedFunctions = [
    "_gn_core_create"
    "_gn_core_create_from_json"
    "_gn_core_destroy"
    "_gn_core_install_identity_from_file"
    "_gn_core_install_identity_from_provider"
    "_gn_core_init"
    "_gn_core_start"
    "_gn_core_stop"
    "_gn_core_wait"
    "_gn_core_is_running"
    "_gn_core_reload_config_json"
    "_gn_core_limits"
    "_gn_core_set_limits"
    "_gn_core_get_pubkey"
    "_gn_core_connect"
    "_gn_core_listen"
    "_gn_core_send_to"
    "_gn_core_broadcast"
    "_gn_core_disconnect"
    "_gn_core_get_stats"
    "_gn_core_connection_count"
    "_gn_core_handler_count"
    "_gn_core_link_count"
    "_gn_core_subscribe"
    "_gn_core_unsubscribe"
    "_gn_core_on_conn_state"
    "_gn_core_off_conn_state"
    "_gn_core_load_plugin"
    "_gn_core_load_plugins_batch"
    "_gn_core_unload_plugin"
    "_gn_core_register_runtime"
    "_gn_core_register_security"
    "_gn_core_register_protocol"
    "_gn_core_register_handler"
    "_gn_core_register_link"
    "_gn_core_query_extension_checked"
    "_gn_core_register_extension"
    "_gn_core_unregister_extension"
    "_gn_core_host_api"
    "_gn_version"
    "_gn_version_packed"
    "_malloc"
    "_free"
  ];

  # emscripten accepts JSON arrays with either ' or " quoting.
  # Double-quote variants are used here so the strings can be passed
  # inside bash single-quoted arguments without breaking shell quoting.
  exportedFunctionsStr =
    "[" + pkgs.lib.concatMapStringsSep "," (f: "\"${f}\"") exportedFunctions + "]";

  # Runtime helpers the JS SDK uses to marshal values across the
  # WASM / JS boundary:
  #   ccall/cwrap     — call C functions from JS with type conversion
  #   UTF8ToString    — read a const char* from WASM memory
  #   stringToUTF8    — write a JS string into a WASM buffer
  #   lengthBytesUTF8 — measure UTF-8 length without writing
  #   getValue/setValue — read/write typed scalars from WASM memory
  #   addFunction     — wrap a JS function as a C function pointer
  #                     (used by WasmTransport for callbacks / link
  #                     vtables passed to gn_core_subscribe et al.)
  #   removeFunction  — release a wrapped function pointer slot
  exportedRuntimeMethods =
    "[\"ccall\",\"cwrap\",\"UTF8ToString\",\"stringToUTF8\","
    + "\"lengthBytesUTF8\",\"getValue\",\"setValue\","
    + "\"addFunction\",\"removeFunction\"]";

in
pkgs.stdenv.mkDerivation {
  pname   = "goodnet-wasm-emscripten";
  inherit version;

  src = pkgs.lib.cleanSourceWith {
    src    = ./..;
    filter = path: type:
      let
        rel = pkgs.lib.removePrefix (toString ./.. + "/") (toString path);
        top = builtins.head (pkgs.lib.splitString "/" rel);
      in
        builtins.elem top [
          "sdk" "core" "plugins" "cmake"
          "CMakeLists.txt" "LICENSE" "README.md"
        ];
  };

  nativeBuildInputs = [
    emscripten
    pkgs.nodejs
    # Header-only / header-primary deps. emcc is invoked directly
    # (no cmake) so include paths are passed explicitly in CXXFLAGS.
    pkgs.asio          # header-only; ASIO_STANDALONE avoids Boost
    pkgs.spdlog        # multi-output; headers via .dev
    pkgs.spdlog.dev
    pkgs.fmt           # multi-output; headers via .dev
    pkgs.fmt.dev
    pkgs.nlohmann_json # header-only
    # libsodium is compiled from source inside the derivation via
    # emconfigure / emmake — see buildPhase below.
  ];

  dontConfigure = true;

  buildPhase = ''
    runHook preBuild

    ${emcacheSetup}

    mkdir -p obj lib

    # ── Step 1: build libsodium for wasm32-emscripten ─────────────────────
    # No nixpkgs package provides a pre-built emscripten libsodium.
    # `emconfigure ./configure` injects emcc/ar/ranlib into the
    # autoconf environment; `emmake make` drives the cross-compile.
    # The result is a static archive at sodium-install/lib/libsodium.a
    # that the final link step consumes.
    echo "==> building libsodium for wasm32-emscripten"
    # libsodium.src is a Nix store directory (fetched source tree).
    mkdir -p sodium-src
    cp -r ${pkgs.libsodium.src}/. sodium-src/
    chmod -R u+w sodium-src
    mkdir -p sodium-install
    pushd sodium-src
    emconfigure ./configure \
      --prefix="$PWD/../sodium-install" \
      --disable-shared \
      --enable-static \
      --host=wasm32-unknown-emscripten \
      CFLAGS="-O2 -pthread"
    emmake make -j$NIX_BUILD_CORES
    emmake make install
    popd
    SODIUM_INC="$PWD/sodium-install/include"
    SODIUM_LIB="$PWD/sodium-install/lib/libsodium.a"

    # ── Step 2: compile the full kernel ───────────────────────────────────
    # Flags common to every TU:
    #   -std=c++23         matches the native kernel's dialect
    #   -fexceptions       WASM supports Wasm EH natively; spdlog requires it
    #   -O2                matches native Release build
    #   -pthread           required when linking with -sUSE_PTHREADS=1;
    #                      emcc maps this to Emscripten pthreads / Web Workers
    #   -I.                resolves <sdk/...> <core/...> against source root
    #   ASIO_STANDALONE    disables Boost; kernel uses standalone Asio
    #   SPDLOG_HEADER_ONLY makes spdlog a pure header library (no libspdlog)
    #   SPDLOG_FMT_EXTERNAL use external fmt (nixpkgs spdlog configured so)
    #   FMT_HEADER_ONLY    makes fmt a pure header library (no libfmt)
    CXXFLAGS="-std=c++23 -O2 -fexceptions -pthread"
    CXXFLAGS="$CXXFLAGS -I."
    CXXFLAGS="$CXXFLAGS -I${pkgs.asio}/include"
    CXXFLAGS="$CXXFLAGS -I${pkgs.spdlog.dev}/include"
    CXXFLAGS="$CXXFLAGS -I${pkgs.fmt.dev}/include"
    CXXFLAGS="$CXXFLAGS -I${pkgs.nlohmann_json}/include"
    CXXFLAGS="$CXXFLAGS -I$SODIUM_INC"
    CXXFLAGS="$CXXFLAGS -DASIO_STANDALONE"
    CXXFLAGS="$CXXFLAGS -DSPDLOG_HEADER_ONLY -DSPDLOG_FMT_EXTERNAL"
    CXXFLAGS="$CXXFLAGS -DFMT_HEADER_ONLY"

    set -x

    # Kernel TUs — mirrors core/CMakeLists.txt _goodnet_kernel_sources.
    # Excluded:
    #   plugin/remote_host.cpp     — fork/execve/socketpair; no process model in WASM
    #   plugin/runtimes/remote.cpp — includes remote_host.hpp; same exclusion
    # Included with guard:
    #   plugin/runtimes/dynamic.cpp — __EMSCRIPTEN__ branch stubs dlopen to GN_ERR_NOT_FOUND
    KERNEL_SRCS="
      core/config/config.cpp
      core/identity/keypair.cpp
      core/identity/derive.cpp
      core/identity/attestation.cpp
      core/identity/libsodium_signer.cpp
      core/identity/identity_plugin_signer.cpp
      core/identity/node_identity.cpp
      core/identity/sub_key_registry.cpp
      core/identity/rotation.cpp
      core/kernel/capability_blob.cpp
      core/kernel/connection_context.cpp
      core/registry/connection.cpp
      core/registry/extension.cpp
      core/registry/handler.cpp
      core/registry/security.cpp
      core/registry/link.cpp
      core/registry/protocol_layer.cpp
      core/registry/send_queue.cpp
      core/security/session.cpp
      core/security/inline_crypto.cpp
      core/crypto/crypto_worker_pool.cpp
      core/kernel/link_capability.cpp
      core/kernel/router.cpp
      core/kernel/kernel.cpp
      core/kernel/core_c.cpp
      core/kernel/host_api_builder.cpp
      core/kernel/host_api/internal.cpp
      core/kernel/host_api/messaging.cpp
      core/kernel/host_api/identity.cpp
      core/kernel/host_api/control.cpp
      core/kernel/host_api/notifications.cpp
      core/kernel/service_resolver.cpp
      core/kernel/timer_registry.cpp
      core/topology/topology_builder.cpp
      core/kernel/attestation_dispatcher.cpp
      core/kernel/metrics_registry.cpp
      core/plugin/plugin_manager.cpp
      core/plugin/plugin_manifest.cpp
      core/plugin/wire_codec.cpp
      core/plugin/runtimes/dynamic.cpp
      core/plugin/runtimes/static.cpp
      core/plugin/static_registry_default.cpp
      core/util/log.cpp
      core/util/log_config.cpp
    "

    for src in $KERNEL_SRCS; do
      obj="obj/$(echo "$src" | tr '/' '_' | sed 's/\.cpp$/.o/')"
      emcc $CXXFLAGS -c -o "$obj" "$src"
    done

    # ── Step 3: archive ───────────────────────────────────────────────────
    emar rcs lib/libgoodnet-wasm-emscripten.a obj/*.o

    # ── Step 4: link → goodnet.wasm + goodnet.js ──────────────────────────
    # -sUSE_PTHREADS=1         Emscripten pthreads via Web Workers
    # -sPTHREAD_POOL_SIZE=4    pre-create 4 workers (avoids first-use latency)
    # -sALLOW_MEMORY_GROWTH=1  heap grows past the initial 16 MiB
    # -sNO_EXIT_RUNTIME=1      keep runtime alive after init (library, not app)
    # -sMODULARIZE=1           emit a factory function (returns Promise<Module>)
    # -sEXPORT_NAME=Goodnet    factory is `const M = await Goodnet()`
    # -sALLOW_TABLE_GROWTH     function table grows as addFunction() is called
    #                          (needed for subscribe callbacks + link vtables)
    # -sEXPORTED_FUNCTIONS     only the C ABI surface (no internal symbols)
    # -sEXPORTED_RUNTIME_METHODS  JS helpers for memory / callback marshalling
    # -sENVIRONMENT='web,worker'  omit Node.js-only startup paths
    emcc $CXXFLAGS \
      -sUSE_PTHREADS=1 \
      -sPTHREAD_POOL_SIZE=4 \
      -sALLOW_MEMORY_GROWTH=1 \
      -sNO_EXIT_RUNTIME=1 \
      -sMODULARIZE=1 \
      -sEXPORT_NAME=Goodnet \
      -sALLOW_TABLE_GROWTH \
      -sEXPORTED_FUNCTIONS='${exportedFunctionsStr}' \
      -sEXPORTED_RUNTIME_METHODS='${exportedRuntimeMethods}' \
      -sENVIRONMENT='web,worker' \
      -o lib/goodnet.js \
      -Wl,--whole-archive lib/libgoodnet-wasm-emscripten.a -Wl,--no-whole-archive \
      "$SODIUM_LIB"

    set +x

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out/lib $out/include/goodnet

    cp lib/libgoodnet-wasm-emscripten.a $out/lib/
    for f in lib/goodnet.wasm lib/goodnet.js lib/goodnet.worker.js; do
      [ -f "$f" ] && cp "$f" $out/lib/
    done

    # SDK headers — same layout as the WASI build's install.
    cp -r sdk $out/include/goodnet/

    # Core headers: public-facing kernel/ and plugin/ interfaces.
    mkdir -p \
      $out/include/goodnet/core/kernel \
      $out/include/goodnet/core/plugin \
      $out/include/goodnet/core/plugin/runtimes \
      $out/include/goodnet/core/registry \
      $out/include/goodnet/core/identity \
      $out/include/goodnet/core/security \
      $out/include/goodnet/core/crypto \
      $out/include/goodnet/core/config \
      $out/include/goodnet/core/util
    find core -name '*.hpp' -o -name '*.h' | while read -r hdr; do
      dest="$out/include/goodnet/$hdr"
      mkdir -p "$(dirname "$dest")"
      install -m 0644 "$hdr" "$dest"
    done

    runHook postInstall
  '';

  doCheck = false;

  meta = {
    description =
      "Full GoodNet kernel built for browser WebAssembly via Emscripten. "
      + "Exposes the complete gn_core_* C ABI as Module._gn_core_*. "
      + "Hosting page requires COOP/COEP headers for SharedArrayBuffer "
      + "(pthread / Web Worker support).";
    platforms = pkgs.lib.platforms.linux;
    license   = pkgs.lib.licenses.mit;
  };

  passthru.route = "emscripten";

  passthru.scope = [
    # ctx_accessors
    "core/kernel/connection_context.cpp"
    # kernel sources (remote_host.cpp + runtimes/remote.cpp excluded)
    "core/config/config.cpp"
    "core/identity/keypair.cpp"
    "core/identity/derive.cpp"
    "core/identity/attestation.cpp"
    "core/identity/libsodium_signer.cpp"
    "core/identity/identity_plugin_signer.cpp"
    "core/identity/node_identity.cpp"
    "core/identity/sub_key_registry.cpp"
    "core/identity/rotation.cpp"
    "core/kernel/capability_blob.cpp"
    "core/registry/connection.cpp"
    "core/registry/extension.cpp"
    "core/registry/handler.cpp"
    "core/registry/security.cpp"
    "core/registry/link.cpp"
    "core/registry/protocol_layer.cpp"
    "core/registry/send_queue.cpp"
    "core/security/session.cpp"
    "core/security/inline_crypto.cpp"
    "core/crypto/crypto_worker_pool.cpp"
    "core/kernel/link_capability.cpp"
    "core/kernel/router.cpp"
    "core/kernel/kernel.cpp"
    "core/kernel/core_c.cpp"
    "core/kernel/host_api_builder.cpp"
    "core/kernel/host_api/internal.cpp"
    "core/kernel/host_api/messaging.cpp"
    "core/kernel/host_api/identity.cpp"
    "core/kernel/host_api/control.cpp"
    "core/kernel/host_api/notifications.cpp"
    "core/kernel/service_resolver.cpp"
    "core/kernel/timer_registry.cpp"
    "core/topology/topology_builder.cpp"
    "core/kernel/attestation_dispatcher.cpp"
    "core/kernel/metrics_registry.cpp"
    "core/plugin/plugin_manager.cpp"
    "core/plugin/plugin_manifest.cpp"
    "core/plugin/wire_codec.cpp"
    "core/plugin/runtimes/dynamic.cpp"  # __EMSCRIPTEN__ stub
    "core/plugin/runtimes/static.cpp"
    "core/plugin/static_registry_default.cpp"
    "core/util/log.cpp"
    "core/util/log_config.cpp"
  ];

  passthru.gaps = {
    subprocess =
      "core/plugin/remote_host.cpp (fork+execve+socketpair) and "
      + "core/plugin/runtimes/remote.cpp (RemoteHost client) are "
      + "excluded — no process model in browser WASM. "
      + "core/plugin/runtimes/dynamic.cpp compiles with its "
      + "__EMSCRIPTEN__ stub (returns GN_ERR_NOT_FOUND for all calls).";
  };

  passthru.skip_reason = "";
}
