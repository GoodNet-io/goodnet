# Standalone dev / test / build flake for the goodnet-security-noise
# plugin. Reuses the existing `default.nix` for the package derivation
# and exposes a per-plugin dev shell + the `build / test / test-asan /
# test-tsan / debug` apps that mirror the monorepo's top-level set so a
# plugin author can iterate from inside `plugins/security/noise/`
# without touching the kernel monorepo at all.
#
# Once `goodnet-core` is extracted to its own repo, the
# `inputs.goodnet.url` swaps from `path:../../..` to a `github:` /
# `git+https:` URL — the rest of the flake stays unchanged.
{
  description = "GoodNet Noise XX security provider — standalone plugin flake.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    goodnet.url = "path:../../..";
    goodnet.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, goodnet }:
    let
      # Mirrors the kernel flake's posture — Linux-only honestly.
      # Cross-platform support lands as a real port, not a list.
      forAllSystems = f:
        nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
          (system: f system (import nixpkgs { inherit system; }));

      # Every app re-enters this flake's own dev shell through `nix
      # develop --command` so PATH / CMAKE_PREFIX_PATH / pkg-config
      # resolve identically whether the user runs `nix run .#test` or
      # types `cmake --build build` by hand inside `nix develop`.
      mkDevApp = pkgs: name: cmd: {
        type = "app";
        program = "${pkgs.writeShellScriptBin name ''
          exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" \
            --command bash -c '${cmd}'
        ''}/bin/${name}";
      };
    in
    {
      packages = forAllSystems (system: pkgs:
        let goodnet-core = goodnet.packages.${system}.goodnet-core;
        in {
          default = pkgs.callPackage ./default.nix { inherit goodnet-core; };
        });

      devShells = forAllSystems (system: pkgs:
        let
          stdenv  = pkgs.gcc15Stdenv;
          plugin  = self.packages.${system}.default;
        in {
          default = (pkgs.mkShell.override { inherit stdenv; }) {
            # `inputsFrom = [ plugin ]` propagates every transitive
            # build / native build input the plugin derivation needs
            # (cmake, ninja, pkg-config, libsodium, goodnet-core, …)
            # so the dev shell never drifts from what `nix build` saw.
            inputsFrom = [ plugin ];
            packages = (with pkgs; [
              clang-tools ccache cmake-format jq gdb
            ]) ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.valgrind ];

            shellHook = ''
              export CCACHE_DIR="$HOME/.cache/ccache"
              export CMAKE_C_COMPILER_LAUNCHER=ccache
              export CMAKE_CXX_COMPILER_LAUNCHER=ccache

              cat <<'EOF'

  goodnet-security-noise  —  standalone plugin dev shell
    nix run .#build      — Release build (artefacts → ./build/)
    nix run .#test       — Release build with tests + ctest
    nix run .#test-asan  — ASan + UBSan build + ctest
    nix run .#test-tsan  — TSan build + ctest
    nix run .#debug      — Debug build + gdb on test_noise

  EOF
            '';
          };
        });

      apps = forAllSystems (system: pkgs:
        let
          # Centralised cmake configure invocation so a new build
          # variant (e.g. `RelWithDebInfo + ASan`) only needs a new
          # `mkBuild` line, not a new copy-pasted shell snippet.
          # `CMAKE_PREFIX_PATH` is left to the dev shell — `inputsFrom
          # = [ plugin ]` already wires every transitive dependency
          # (goodnet-core, libsodium, rapidcheck.dev, gtest, …) into
          # the CMake search path. Setting it explicitly here used to
          # clobber the dev shell's value and broke `find_package
          # (rapidcheck)` because the multi-output `dev` slot fell off
          # the path.
          mkBuild = { dir, buildType, testing ? false, sanitizer ? "" }: ''
            BUILD_DIR="''${BUILD_DIR:-${dir}}"
            cmake -B "$BUILD_DIR" -G Ninja \
              -DCMAKE_BUILD_TYPE=${buildType} \
              -DBUILD_TESTING=${if testing then "ON" else "OFF"} \
              ${pkgs.lib.optionalString (sanitizer != "")
                "-DCMAKE_CXX_FLAGS=\"${sanitizer}\""}
            cmake --build "$BUILD_DIR" -j
          '';
          asanFlags = "-fsanitize=address,undefined -fno-sanitize-recover=all"
                    + " -O1 -g -fno-omit-frame-pointer";
          tsanFlags = "-fsanitize=thread -O1 -g -fno-omit-frame-pointer";
        in {
          build = mkDevApp pkgs "noise-build" ''
            set -euo pipefail
            ${mkBuild { dir = "build"; buildType = "Release"; }}
          '';
          test = mkDevApp pkgs "noise-test" ''
            set -euo pipefail
            ${mkBuild { dir = "build"; buildType = "Release"; testing = true; }}
            (cd "''${BUILD_DIR:-build}" && ctest --output-on-failure)
          '';
          test-asan = mkDevApp pkgs "noise-test-asan" ''
            set -euo pipefail
            ${mkBuild {
              dir = "build-asan"; buildType = "Debug";
              testing = true; sanitizer = asanFlags;
            }}
            (cd "''${BUILD_DIR:-build-asan}" && ctest --output-on-failure)
          '';
          test-tsan = mkDevApp pkgs "noise-test-tsan" ''
            set -euo pipefail
            ${mkBuild {
              dir = "build-tsan"; buildType = "Debug";
              testing = true; sanitizer = tsanFlags;
            }}
            (cd "''${BUILD_DIR:-build-tsan}" && ctest --output-on-failure)
          '';
          debug = mkDevApp pkgs "noise-debug" ''
            set -euo pipefail
            ${mkBuild { dir = "build-dbg"; buildType = "Debug"; testing = true; }}
            exec ${pkgs.gdb}/bin/gdb \
              -ex "set print pretty on" \
              "''${BUILD_DIR:-build-dbg}/tests/test_noise" "$@"
          '';
        });
    };
}
