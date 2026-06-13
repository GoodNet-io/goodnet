# nix/dev-shell-app.nix — `nix develop goodnet#app`.
#
# Per-downstream-consumer shell. Drops the operator into a configured
# environment where the GoodNet kernel + bundled plugins + bootstrap
# identity / manifest paths are pre-wired through env vars that the
# `goodnet_app(...)` CMake helper (under `cmake/goodnet_app.cmake`)
# and the `gn::sdk::Core` XDG-default constructor read.
#
# Exported env vars:
#
#   GOODNET_CORE_LIB     — absolute path to the kernel's shared
#                          object (`lib/libgoodnet_kernel.so` out
#                          of the `goodnet-core` derivation). The
#                          CMake helper passes the parent dir to
#                          BUILD_RPATH so a consumer binary finds
#                          the kernel at run time without a separate
#                          LD_LIBRARY_PATH dance.
#   GOODNET_PLUGIN_PATH  — `~/.local/share/goodnet/plugins` (the
#                          path `gn-bootstrap-env` populates).
#                          Read by `gn::sdk::Core` for plugin
#                          discovery + by the helper macro for
#                          BUILD_RPATH so dlopen'd plugins resolve
#                          relative imports correctly.
#   GOODNET_IDENTITY     — `~/.local/share/goodnet/identity/default.bin`.
#                          Picked up by the default `Core` ctor via
#                          the bootstrap config.
#   GOODNET_MANIFEST     — `~/.local/share/goodnet/manifests/
#                          baseline.json`. Same source.
#   GOODNET_LIB_DIR      — directory portion of GOODNET_CORE_LIB.
#                          Useful as a single string the helper
#                          macro hands to BUILD_RPATH without
#                          re-deriving the dirname inside CMake.
#
# `LD_LIBRARY_PATH` is augmented with both the kernel lib dir and
# the plugin dir so anything built in the shell (`cmake --build`)
# can also `./build/myapp` straight away without an explicit
# wrapping step.
#
# `buildInputs` carries the C/C++ toolchain the helper macro needs
# at configure + build time: cmake, ninja, pkg-config, libsodium,
# openssl, the SDK headers + `goodnet-core` derivation (which
# propagates the kernel-side find_package(GoodNet) config).

{ pkgs, goodnet-core }:

let
  # Lift the kernel's library dir into a single string the
  # shellHook can pin without re-globbing. `lib/libgoodnet_kernel.so`
  # is the OUTPUT_NAME pinned by `core/CMakeLists.txt`.
  kernelLibDir = "${goodnet-core}/lib";
  kernelLib    = "${kernelLibDir}/libgoodnet_kernel.so";
in
(pkgs.mkShell.override { stdenv = pkgs.gcc15Stdenv; }) {
  name = "goodnet-app";

  # `inputsFrom` brings every CMake / pkg-config find target the
  # kernel itself uses — so `find_package(GoodNet REQUIRED)` in the
  # consumer's CMakeLists.txt sees the same transitive closure
  # (asio, spdlog, fmt, openssl, sodium, …) without the downstream
  # author copying the list.
  inputsFrom = [ goodnet-core ];

  nativeBuildInputs = with pkgs; [
    cmake
    ninja
    pkg-config
  ];

  buildInputs = with pkgs; [
    libsodium
    openssl
    # asio is header-only; spdlog/fmt/nlohmann_json ride in via the
    # kernel's propagatedBuildInputs through `inputsFrom`. Keep
    # libsodium + openssl explicit because the helper macro's
    # `target_link_libraries` line names them by IMPORTED target.
  ];

  shellHook = ''
    export GOODNET_CORE_LIB="${kernelLib}"
    export GOODNET_LIB_DIR="${kernelLibDir}"
    export GOODNET_PLUGIN_PATH="''${GOODNET_PLUGIN_PATH:-$HOME/.local/share/goodnet/plugins}"
    export GOODNET_IDENTITY="''${GOODNET_IDENTITY:-$HOME/.local/share/goodnet/identity/default.bin}"
    export GOODNET_MANIFEST="''${GOODNET_MANIFEST:-$HOME/.local/share/goodnet/manifests/baseline.json}"

    # Augment LD_LIBRARY_PATH so a freshly-built consumer binary
    # finds the kernel + plugins at run time without a second
    # wrapping step. Pre-existing entries stay first so the operator
    # can shadow either path for ad-hoc testing.
    case ":''${LD_LIBRARY_PATH:-}:" in
      *":$GOODNET_LIB_DIR:"*) ;;
      *) export LD_LIBRARY_PATH="''${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}$GOODNET_LIB_DIR" ;;
    esac
    case ":''${LD_LIBRARY_PATH:-}:" in
      *":$GOODNET_PLUGIN_PATH:"*) ;;
      *) export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$GOODNET_PLUGIN_PATH" ;;
    esac

    if [ ! -d "$GOODNET_PLUGIN_PATH" ] || \
       ! compgen -G "$GOODNET_PLUGIN_PATH/lib*.so" >/dev/null; then
      cat <<MSG
    goodnet#app: ~/.local/share/goodnet/ is not populated.
      Run \`nix run goodnet#bootstrap-env\` to lay down identity +
      plugins + manifest before \`cmake --build\` can produce a
      binary that finds them at run time.
    MSG
    fi

    cat <<EOF

GoodNet app devShell

  Pre-wired env:
    GOODNET_CORE_LIB     = $GOODNET_CORE_LIB
    GOODNET_LIB_DIR      = $GOODNET_LIB_DIR
    GOODNET_PLUGIN_PATH  = $GOODNET_PLUGIN_PATH
    GOODNET_IDENTITY     = $GOODNET_IDENTITY
    GOODNET_MANIFEST     = $GOODNET_MANIFEST

  Three-command setup recap:
    nix run goodnet#bootstrap-env       # one-time per-user XDG layout
    cmake -B build && cmake --build build
    ./build/<your-target>

  Counter-party for local testing:
    nix run goodnet#sample-peer &

EOF
  '';
}
