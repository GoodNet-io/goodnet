# nix/mkCppPlugin.nix — high-level wrapper for GoodNet plugins.
#
# Composes a raw cmake build with the packaging step from
# nix/buildPlugin.nix. A per-plugin default.nix that opts into
# this wrapper shrinks to ~10 lines:
#
#   { pkgs, mkCppPlugin, goodnet-core }:
#   mkCppPlugin {
#     name        = "goodnet-plugin-noise";
#     type        = "security";
#     version     = "0.1.0";
#     description = "Noise XX security provider";
#     src         = ./.;
#     deps        = with pkgs; [ libsodium ];
#     inherit goodnet-core;
#   }
#
# Inputs (curried):
#   { pkgs, buildPlugin }
#
# Returned function:
#   { name, type, version, description ? "", src, deps ? [],
#     goodnet-core, cmakeFlags ? [] }
#
# Per-plugin CMakeLists.txt is expected to call `add_plugin(NAME ...)`
# from `cmake/AddPlugin.cmake` (provided through the goodnet-core
# CMake config exports) so output naming + visibility +
# size-optimization flags stay uniform across the plugin set.
#
# Failure modes (per project_goodnet_subplan_infrastructure §I-B):
#   - missing `goodnet-core` input                → loud Nix error
#   - `name`/`type`/`version` validation          → buildPlugin asserts
#   - cmake configure fails (missing find_package, version skew, …)
#                                                  → cmake exit propagates
#   - plugin emits no .so                          → buildPlugin loud-fails
#
# No silent fallbacks. The raw cmake step's stderr surfaces
# verbatim through the Nix builder log.

{ pkgs, buildPlugin }:

{ name
, type
, version
, description ? ""
, src
, deps ? [ ]
, goodnet-core
, cmakeFlags ? [ ]
}:

let
  rawBuild = pkgs.stdenv.mkDerivation {
    pname   = "${name}-raw";
    inherit version src;

    nativeBuildInputs = with pkgs; [ cmake ninja pkg-config ];
    buildInputs       = deps ++ [ goodnet-core ];

    cmakeFlags = [
      "-DCMAKE_BUILD_TYPE=Release"
      "-DBUILD_SHARED_LIBS=ON"
      "-DCMAKE_PREFIX_PATH=${goodnet-core}"
    ] ++ cmakeFlags;

    installPhase = ''
      set -euo pipefail
      mkdir -p $out/lib
      shopt -s nullglob
      so_count=0
      for sofile in $(find . -name "lib*.so" -type f); do
        cp "$sofile" $out/lib/
        so_count=$((so_count + 1))
      done
      shopt -u nullglob
      if [ "$so_count" -eq 0 ]; then
        echo "mkCppPlugin: cmake build produced no lib*.so under $PWD" >&2
        exit 1
      fi
    '';
  };
in
buildPlugin {
  inherit name type version description;
  drv = rawBuild;
}
