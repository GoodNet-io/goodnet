# nix/plugin-helpers.nix — shared building blocks for the per-plugin
# standalone flakes that live alongside `default.nix` under each
# `plugins/<kind>/<name>/`.
#
# A per-plugin `flake.nix` consumes this file through the `goodnet`
# flake input the plugin pulls in:
#
#   inputs.goodnet.url = "path:../../..";
#   outputs = { self, nixpkgs, goodnet }:
#     let
#       forAllSystems = ...;
#       helpers = goodnet.lib.plugin-helpers;
#     in {
#       packages = forAllSystems (system: pkgs: { ... });
#       devShells = forAllSystems (system: pkgs:
#         { default = helpers.mkPluginDevShell { inherit pkgs; ... }; });
#       apps = forAllSystems (system: pkgs:
#         helpers.mkPluginApps { inherit pkgs; pluginName = "noise"; });
#     };
#
# The helpers stay deliberately small — they capture only the bits
# every plugin shares (sanitizer flag tuples, the canonical app
# wrapper, the welcome banner) so individual flakes do not have to
# copy-paste them. Plugin-specific knobs (extra dev-shell tooling,
# whether the plugin even has tests, etc.) stay in the per-plugin
# `flake.nix` so the helper does not become a leaky god-object.
#
# This file is exposed via the kernel flake's `lib.plugin-helpers`
# output and takes no arguments at import time — every helper takes
# its `pkgs` directly so a plugin can call them under its own
# `forAllSystems` without a second indirection.

let
  # Sanitizer flag tuples kept in one place so a flag bump (e.g. add
  # `-fno-stack-protector`) lands once for every plugin. The shape
  # mirrors the kernel's top-level `flake.nix` apps.
  sanitizerFlags = {
    asan = "-fsanitize=address,undefined -fno-sanitize-recover=all"
         + " -O1 -g -fno-omit-frame-pointer";
    tsan = "-fsanitize=thread -O1 -g -fno-omit-frame-pointer";
  };

  # Centralised cmake configure invocation. A new build variant
  # (e.g. `RelWithDebInfo + ASan`) only needs an extra entry in the
  # apps attrset — not a new copy-pasted shell snippet.
  mkBuildScript = pkgs:
    { dir, buildType, testing ? false, sanitizer ? "" }: ''
      BUILD_DIR="''${BUILD_DIR:-${dir}}"
      cmake -B "$BUILD_DIR" -G Ninja \
        -DCMAKE_BUILD_TYPE=${buildType} \
        -DBUILD_TESTING=${if testing then "ON" else "OFF"} \
        ${pkgs.lib.optionalString (sanitizer != "")
          "-DCMAKE_CXX_FLAGS=\"${sanitizer}\""}
      cmake --build "$BUILD_DIR" -j
    '';

  # Every app re-enters the plugin's own dev shell through `nix
  # develop --command` so PATH / CMAKE_PREFIX_PATH / pkg-config
  # resolve identically whether the user runs `nix run .#test` or
  # types `cmake --build build` by hand inside `nix develop`.
  #
  # PWD safety: `nix develop "."` resolves the dot at exec time, so
  # a stray PWD outside the plugin directory used to silently route
  # the operator into the kernel monorepo's flake (which exposes
  # apps under the same names) and run the wrong build. Each
  # standalone plugin flake carries the `# goodnet-standalone-plugin
  # : <name>` marker comment so the wrapper can refuse to enter a
  # flake that isn't the plugin it was built for. `FLAKE_DIR` is
  # an explicit override for callers running from elsewhere.
  mkDevApp = pkgs: pluginName: name: cmd: {
    type = "app";
    program = "${pkgs.writeShellScriptBin name ''
      set -euo pipefail
      flake_dir="''${FLAKE_DIR:-$PWD}"
      marker="# goodnet-standalone-plugin: ${pluginName}"
      if ! grep -qF "$marker" "$flake_dir/flake.nix" 2>/dev/null; then
        echo "${name}: $flake_dir is not the ${pluginName} plugin flake." >&2
        echo "       cd into the plugin directory first," >&2
        echo "       or set FLAKE_DIR=<plugin-path>." >&2
        exit 1
      fi
      exec ${pkgs.nix}/bin/nix develop "$flake_dir" \
        --command bash -c '${cmd}'
    ''}/bin/${name}";
  };

  # Common dev-shell shape: pulls every transitive build / native
  # build input the plugin derivation needs through `inputsFrom`,
  # then layers ccache + clang-tools + gdb on top. Plugins that need
  # extra tooling (e.g. doxygen for docs) pass it via `extraPackages`.
  #
  # CMAKE_PREFIX_PATH precedence: nix surfaces every `inputsFrom`
  # store path under `NIXPKGS_CMAKE_PREFIX_PATH` but does NOT prepend
  # it to a user-inherited `CMAKE_PREFIX_PATH`. When the operator has
  # an older GoodNet install in `~/.nix-profile` (e.g. from a previous
  # `nix profile install`), that stale path stays first on
  # `CMAKE_PREFIX_PATH` and CMake's `find_package(GoodNet REQUIRED)`
  # resolves to the old `GoodNetConfig.cmake` from the profile —
  # which can still drag in dependencies the current kernel has
  # since dropped (Boost was the trigger seen in QUIC / WS). Prepend
  # the flake-built inputs so the kernel-only `goodnet-core` from
  # this dev shell always wins regardless of what the operator
  # happens to have under `~/.nix-profile`.
  mkPluginDevShell = pkgs:
    { plugin, extraPackages ? [ ], welcomeText ? ""
    , stdenv ? pkgs.gcc15Stdenv }:
    (pkgs.mkShell.override { inherit stdenv; }) {
      inputsFrom = [ plugin ];
      packages = (with pkgs; [
        clang-tools ccache cmake-format jq gdb
      ]) ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.valgrind ]
        ++ extraPackages;
      shellHook = ''
        export CCACHE_DIR="$HOME/.cache/ccache"
        export CMAKE_C_COMPILER_LAUNCHER=ccache
        export CMAKE_CXX_COMPILER_LAUNCHER=ccache
        if [ -n "''${NIXPKGS_CMAKE_PREFIX_PATH:-}" ]; then
          if [ -n "''${CMAKE_PREFIX_PATH:-}" ]; then
            export CMAKE_PREFIX_PATH="$NIXPKGS_CMAKE_PREFIX_PATH:$CMAKE_PREFIX_PATH"
          else
            export CMAKE_PREFIX_PATH="$NIXPKGS_CMAKE_PREFIX_PATH"
          fi
        fi
        ${pkgs.lib.optionalString (welcomeText != "") ''
          cat <<'EOF'
${welcomeText}
EOF
        ''}
      '';
    };

  # The full set of standalone-plugin apps. Plugins that have no
  # gtest tests pass `hasTests = false` and only `build` + `debug`
  # are emitted; plugins that have a non-default test binary name
  # (the `debug` app launches `tests/<binary>` under gdb) pass it
  # via `debugBinary`.
  mkPluginApps = pkgs:
    { pluginName, hasTests ? true, debugBinary ? "test_${pluginName}" }:
    let
      mkBuild = mkBuildScript pkgs;
      mkApp = mkDevApp pkgs pluginName;
      buildApp = mkApp "${pluginName}-build" ''
        set -euo pipefail
        ${mkBuild { dir = "build"; buildType = "Release"; }}
      '';
      debugApp = mkApp "${pluginName}-debug" ''
        set -euo pipefail
        ${mkBuild { dir = "build-dbg"; buildType = "Debug"; testing = hasTests; }}
        exec ${pkgs.gdb}/bin/gdb \
          -ex "set print pretty on" \
          "''${BUILD_DIR:-build-dbg}/tests/${debugBinary}" "$@"
      '';
      testApps = pkgs.lib.optionalAttrs hasTests {
        test = mkApp "${pluginName}-test" ''
          set -euo pipefail
          ${mkBuild { dir = "build"; buildType = "Release"; testing = true; }}
          (cd "''${BUILD_DIR:-build}" && ctest --output-on-failure)
        '';
        test-asan = mkApp "${pluginName}-test-asan" ''
          set -euo pipefail
          ${mkBuild {
            dir = "build-asan"; buildType = "Debug";
            testing = true; sanitizer = sanitizerFlags.asan;
          }}
          (cd "''${BUILD_DIR:-build-asan}" && ctest --output-on-failure)
        '';
        test-tsan = mkApp "${pluginName}-test-tsan" ''
          set -euo pipefail
          ${mkBuild {
            dir = "build-tsan"; buildType = "Debug";
            testing = true; sanitizer = sanitizerFlags.tsan;
          }}
          (cd "''${BUILD_DIR:-build-tsan}" && ctest --output-on-failure)
        '';
      };
    in
    { build = buildApp; debug = debugApp; } // testApps;
in
{
  inherit sanitizerFlags mkBuildScript mkDevApp mkPluginDevShell mkPluginApps;
}
