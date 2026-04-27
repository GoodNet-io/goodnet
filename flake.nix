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
          deps = with pkgs; [
            boost spdlog fmt nlohmann_json libsodium
          ];
          devTools = with pkgs; [ gtest rapidcheck ];
          nativeTools = with pkgs; [ cmake ninja pkg-config ];
        in
        {
          # Platform = kernel + SDK + statically-linked mandatory mesh-framing
          # plugin (GNET). Other plugins are independent derivations.
          default = stdenv.mkDerivation {
            pname   = "goodnet";
            version = "0.1.0";
            src     = pkgs.lib.cleanSourceWith {
              src    = ./.;
              filter = path: type:
                let b = builtins.baseNameOf path; in
                !(b == "build" || b == "result" || b == ".direnv");
            };
            nativeBuildInputs = nativeTools ++ devTools;
            buildInputs       = deps ++ devTools;
            cmakeFlags = [ "-DCMAKE_BUILD_TYPE=Release" "-DBUILD_TESTING=ON" ];
            doCheck    = false;
          };
        });

      apps = forAllSystems (system: pkgs:
        let
          stdenv = pkgs.gcc15Stdenv;
          deps = with pkgs; [
            boost spdlog fmt nlohmann_json libsodium gtest rapidcheck
          ];
          nativeTools = with pkgs; [ cmake ninja pkg-config ];

          gn-build = pkgs.writeShellApplication {
            name = "gn-build";
            runtimeInputs = nativeTools ++ deps;
            text = ''
              cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON "$@"
              cmake --build build -j"$(nproc)"
            '';
          };

          gn-test = pkgs.writeShellApplication {
            name = "gn-test";
            runtimeInputs = nativeTools ++ deps;
            text = ''
              cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
              cmake --build build -j"$(nproc)"
              ctest --test-dir build --output-on-failure "$@"
            '';
          };

          sanitizerApps = import ./nix/sanitize.nix { inherit pkgs; };
        in
        {
          build     = { type = "app"; program = "${gn-build}/bin/gn-build"; };
          test      = { type = "app"; program = "${gn-test}/bin/gn-test"; };
          test-asan = { type = "app"; program = "${sanitizerApps.test-asan}/bin/gn-test-asan"; };
          test-tsan = { type = "app"; program = "${sanitizerApps.test-tsan}/bin/gn-test-tsan"; };
        });

      devShells = forAllSystems (system: pkgs:
        let
          stdenv = pkgs.gcc15Stdenv;
          deps = with pkgs; [
            boost spdlog fmt nlohmann_json libsodium gtest rapidcheck
          ];
        in
        {
          default = (pkgs.mkShell.override { inherit stdenv; }) {
            packages = with pkgs; [
              cmake ninja pkg-config
              clang-tools ccache cmake-format jq
              gdb valgrind
              doxygen graphviz
            ] ++ deps;

            shellHook = ''
              export CCACHE_DIR="$HOME/.cache/ccache"
              export CMAKE_C_COMPILER_LAUNCHER=ccache
              export CMAKE_CXX_COMPILER_LAUNCHER=ccache

              cfg()  { cmake -B build       -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON "$@"; }
              cfgd() { cmake -B build/debug -G Ninja -DCMAKE_BUILD_TYPE=Debug   -DBUILD_TESTING=ON "$@"; }
              b()    { cmake --build build       -j"$(nproc)" "$@"; }
              bd()   { cmake --build build/debug -j"$(nproc)" "$@"; }
              t()    { ctest --test-dir build --output-on-failure "$@"; }

              echo ""
              echo "GoodNet devShell  (gcc15, C++23)"
              echo "  cfg / b / t       — Release configure / build / test"
              echo "  cfgd / bd         — Debug configure / build"
              echo "  nix run .#build   — one-shot Release build"
              echo "  nix run .#test    — Debug build + ctest"
              echo ""
            '';
          };
        });
    };
}
