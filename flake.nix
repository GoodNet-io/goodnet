{
  description = "GoodNet — network kernel and SDK (the platform). Plugins are independent derivations that depend on the installed SDK.";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      forAllSystems = f:
        nixpkgs.lib.genAttrs
          [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ]
          (system: f system (import nixpkgs { inherit system; }));
    in
    {
      packages = forAllSystems (system: pkgs:
        let
          stdenv = pkgs.gcc15Stdenv;
          coreBuildInputs = with pkgs; [
            asio spdlog fmt nlohmann_json libsodium openssl
          ];
          coreNative = with pkgs; [ cmake ninja pkg-config ];
          testInputs = with pkgs; [ gtest rapidcheck ];
        in
        {
          default = stdenv.mkDerivation {
            pname   = "goodnet";
            version = "0.1.0";
            src     = pkgs.lib.cleanSourceWith {
              src    = ./.;
              filter = path: type:
                let b = builtins.baseNameOf path; in
                !(b == "build" || b == "result" || b == ".direnv");
            };
            nativeBuildInputs = coreNative ++ testInputs;
            buildInputs       = coreBuildInputs ++ testInputs;
            propagatedBuildInputs = coreBuildInputs;
            cmakeFlags = [
              "-DCMAKE_BUILD_TYPE=Release"
              "-DGOODNET_BUILD_TESTS=ON"
            ];
            doCheck = false;
          };
        });

      apps = forAllSystems (system: pkgs:
        let
          # All build apps re-enter the dev shell through `nix develop
          # --command`. `writeShellApplication` only sets up PATH from
          # `runtimeInputs`; CMake's `find_package(... CONFIG)` needs
          # the full `CMAKE_PREFIX_PATH` / `PKG_CONFIG_PATH` that the
          # dev shell wires from `inputsFrom = [ goodnet-core ]`.

          gn-dev = pkgs.writeShellScriptBin "gn-dev" ''
            exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" --command bash -c '
              BUILD_DIR="build"
              if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
                echo ">>> Configuring Debug build..."
                cmake -B "$BUILD_DIR" -G Ninja \
                  -DCMAKE_BUILD_TYPE=Debug \
                  -DGOODNET_BUILD_TESTS=ON
              fi
              cmake --build "$BUILD_DIR" -j"$(nproc)" "$@"
            ' _ "$@"
          '';

          gn-build = pkgs.writeShellScriptBin "gn-build" ''
            exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" --command bash -c '
              BUILD_DIR="build-release"
              if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
                echo ">>> Configuring Release build..."
                cmake -B "$BUILD_DIR" -G Ninja \
                  -DCMAKE_BUILD_TYPE=Release \
                  -DGOODNET_BUILD_TESTS=ON
              fi
              cmake --build "$BUILD_DIR" -j"$(nproc)" "$@"
            ' _ "$@"
          '';

          gn-test = pkgs.writeShellScriptBin "gn-test" ''
            exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" --command bash -c '
              BUILD_DIR="build"
              if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
                echo ">>> Configuring Debug build..."
                cmake -B "$BUILD_DIR" -G Ninja \
                  -DCMAKE_BUILD_TYPE=Debug \
                  -DGOODNET_BUILD_TESTS=ON
              fi
              cmake --build "$BUILD_DIR" -j"$(nproc)"
              ctest --test-dir "$BUILD_DIR" --output-on-failure "$@"
            ' _ "$@"
          '';

          # Opt-in: wire `.githooks/` into the local clone so
          # `git commit` runs `clang-tidy --warnings-as-errors=*` on
          # staged C++ files. Mirrors the CI strict lint gate at
          # commit time so PR feedback never trips on a diagnostic
          # the author already had in front of them.
          gn-install-hooks = pkgs.writeShellScriptBin "gn-install-hooks" ''
            set -euo pipefail
            git config core.hooksPath .githooks
            echo ">>> hooks installed: .githooks/"
            echo "    bypass any single commit with: git commit --no-verify"
          '';

          # `nix run .#demo` — the shortest path from `git clone` to
          # "two endpoints exchanged a frame over a Noise-secured TCP
          # channel". The build flips `GOODNET_BUILD_EXAMPLES=ON` and
          # produces a single `goodnet-demo` binary that owns both
          # ends of the conversation, so the user does not need a
          # peer to run.
          gn-demo = pkgs.writeShellScriptBin "gn-demo" ''
            exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" --command bash -c '
              BUILD_DIR="build-demo"
              if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
                echo ">>> Configuring demo build..."
                cmake -B "$BUILD_DIR" -G Ninja \
                  -DCMAKE_BUILD_TYPE=Release \
                  -DGOODNET_BUILD_EXAMPLES=ON \
                  -DGOODNET_BUILD_TESTS=OFF
              fi
              cmake --build "$BUILD_DIR" --target goodnet_demo -j"$(nproc)"
              "$BUILD_DIR/bin/goodnet-demo"
            ' _ "$@"
          '';

          sanitizerApps = import ./nix/sanitize.nix { inherit pkgs; };
        in
        {
          default       = { type = "app"; program = "${gn-dev}/bin/gn-dev"; };
          dev           = { type = "app"; program = "${gn-dev}/bin/gn-dev"; };
          build         = { type = "app"; program = "${gn-build}/bin/gn-build"; };
          test          = { type = "app"; program = "${gn-test}/bin/gn-test"; };
          test-asan     = { type = "app"; program = "${sanitizerApps.test-asan}/bin/gn-test-asan"; };
          test-tsan     = { type = "app"; program = "${sanitizerApps.test-tsan}/bin/gn-test-tsan"; };
          install-hooks = { type = "app"; program = "${gn-install-hooks}/bin/gn-install-hooks"; };
          demo          = { type = "app"; program = "${gn-demo}/bin/gn-demo"; };
        });

      devShells = forAllSystems (system: pkgs:
        let
          stdenv = pkgs.gcc15Stdenv;
          # `inputsFrom = [ goodnet-core ]` in a `mkShell` pulls every
          # build / native / propagated input the package needs into
          # the shell, so the dev environment matches the Nix build
          # exactly without re-listing dependencies here.
          goodnet-core = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        in
        {
          default = (pkgs.mkShell.override { inherit stdenv; }) {
            inputsFrom = [ goodnet-core ];
            packages = with pkgs; [
              clang-tools ccache cmake-format jq
              gdb valgrind
              doxygen graphviz
            ];

            # Welcome message points at the `nix run` apps so callers
            # never need to remember a CMake invocation by hand.
            # ccache is wired through so repeat builds do not pay the
            # full compile cost.
            shellHook = ''
              export CCACHE_DIR="$HOME/.cache/ccache"
              export CMAKE_C_COMPILER_LAUNCHER=ccache
              export CMAKE_CXX_COMPILER_LAUNCHER=ccache

              cat <<'EOF'

GoodNet devShell  (gcc15, C++23)
  nix run .#               — Debug build (incremental)
  nix run .#build          — Release build
  nix run .#test           — Debug build + ctest
  nix run .#test-asan
  nix run .#test-tsan
  nix run .#demo           — two-node Noise-over-TCP quickstart
  nix run .#install-hooks  — wire .githooks/ into this clone

EOF
            '';
          };
        });
    };
}
