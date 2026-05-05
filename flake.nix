{
  description = "GoodNet kernel + SDK with bundled baseline plugins.";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      forAllSystems = f:
        nixpkgs.lib.genAttrs
          [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ]
          (system: f system (import nixpkgs { inherit system; }));

      # `goodnet.lib.compose` — operator-facing constructor.
      # Bundles the kernel binary + a chosen plugin set + an
      # optional config + identity into a single derivation. The
      # output layout matches what `goodnet run` expects out of
      # `/etc/goodnet`, so the wrapper script in `bin/goodnet-node`
      # invokes the real binary against the bundled paths without
      # any additional plumbing on the operator side.
      #
      # An operator's flake takes `goodnet` as a flake input and
      # writes:
      #
      #     goodnet.lib.compose pkgs {
      #       kernel  = goodnet.packages.${system}.goodnet-core;
      #       plugins = with goodnet.packages.${system}; [
      #         goodnet-link-tcp
      #         goodnet-security-noise
      #         goodnet-handler-heartbeat
      #       ];
      #       config   = ./node.json;     # optional
      #       identity = ./identity.bin;  # optional
      #     }
      composeNode = pkgs:
        { kernel
        , plugins ? [ ]
        , config ? null
        , identity ? null
        , pname ? "goodnet-node"
        , version ? "0.1.0"
        }:
        pkgs.stdenv.mkDerivation {
          inherit pname version;
          dontUnpack = true;
          nativeBuildInputs = [ pkgs.makeWrapper ];

          buildPhase = ''
            mkdir -p plugins
            for p in ${pkgs.lib.concatStringsSep " " plugins}; do
              for so in $p/lib/goodnet/plugins/lib*.so; do
                cp -L "$so" plugins/
              done
            done
            ${kernel}/bin/goodnet manifest gen plugins/lib*.so > manifest.json
          '';

          installPhase = ''
            mkdir -p $out/bin $out/lib/goodnet/plugins $out/etc/goodnet
            cp ${kernel}/bin/goodnet $out/bin/goodnet
            cp plugins/lib*.so $out/lib/goodnet/plugins/
            sed "s|plugins/|$out/lib/goodnet/plugins/|g" \
                manifest.json > $out/etc/goodnet/manifest.json
            ${if config != null then ''
              cp ${config} $out/etc/goodnet/node.json
            '' else ''
              echo '{}' > $out/etc/goodnet/node.json
            ''}
            ${pkgs.lib.optionalString (identity != null) ''
              install -m 0600 ${identity} $out/etc/goodnet/identity.bin
            ''}

            makeWrapper $out/bin/goodnet $out/bin/goodnet-node \
              --add-flags "run" \
              --add-flags "--config $out/etc/goodnet/node.json" \
              --add-flags "--manifest $out/etc/goodnet/manifest.json" \
              ${pkgs.lib.optionalString (identity != null)
                "--add-flags \"--identity $out/etc/goodnet/identity.bin\""}
          '';

          meta = {
            description = "Composed GoodNet node — kernel + selected plugins.";
            mainProgram  = "goodnet-node";
            platforms    = pkgs.lib.platforms.linux;
          };
        };
    in
    {
      lib = {
        # Operator entry point: `goodnet.lib.compose pkgs { ... }`.
        compose = composeNode;
      };


      packages = forAllSystems (system: pkgs:
        let
          stdenv = pkgs.gcc15Stdenv;
          coreBuildInputs = with pkgs; [
            asio spdlog fmt nlohmann_json libsodium openssl
          ];
          coreNative = with pkgs; [ cmake ninja pkg-config ];
          testInputs = with pkgs; [ gtest rapidcheck ];

          # Kernel-only build. Skips iterating `plugins/` so this
          # derivation produces just `goodnet_kernel` + SDK + GNET
          # (mandatory mesh framing) + `GoodNet::ctx_accessors` + the
          # operator CLI. Per-plugin derivations consume this through
          # `goodnet-core` and pull the SDK / AddPlugin.cmake helper
          # through `find_package(GoodNet)` at configure time.
          goodnet-core = stdenv.mkDerivation {
            pname   = "goodnet-core";
            version = "0.1.0";
            src     = pkgs.lib.cleanSourceWith {
              src    = ./.;
              filter = path: type:
                let b = builtins.baseNameOf path; in
                !(b == "build" || b == "result" || b == ".direnv");
            };
            nativeBuildInputs = coreNative;
            buildInputs       = coreBuildInputs;
            propagatedBuildInputs = coreBuildInputs;
            cmakeFlags = [
              "-DCMAKE_BUILD_TYPE=Release"
              "-DGOODNET_BUILD_TESTS=OFF"
              "-DGOODNET_BUILD_BUNDLED_PLUGINS=OFF"
            ];
            doCheck = false;
          };

          # Per-package distribution wrappers per
          # docs/contracts/plugin-manifest.md §8 +
          # project_goodnet_subplan_infrastructure §I-A/§I-B.
          # Per-plugin default.nix may opt into the high-level shape
          # `{ pkgs, mkCppPlugin, goodnet-core }: mkCppPlugin { … }`
          # or stay on raw mkDerivation — both shapes accept the
          # same `goodnet-core` derivation, so the choice is per
          # plugin author.
          buildPlugin = import ./nix/buildPlugin.nix {
            inherit (pkgs) lib;
            inherit pkgs;
          };
          mkCppPlugin = import ./nix/mkCppPlugin.nix {
            inherit pkgs buildPlugin;
          };

          # Conditionally inject `mkCppPlugin` based on the plugin's
          # declared argument set so existing raw-mkDerivation
          # default.nix files keep building unchanged. A plugin
          # author opts into the wrapper by adding `mkCppPlugin`
          # to their function signature; legacy shape is left alone.
          callPlugin = name: kind:
            let
              pluginPath = ./plugins + "/${kind}/${name}/default.nix";
              pluginArgs = builtins.functionArgs (import pluginPath);
              extra = { inherit goodnet-core; }
                // pkgs.lib.optionalAttrs (pluginArgs ? mkCppPlugin)
                     { inherit mkCppPlugin; }
                // pkgs.lib.optionalAttrs (pluginArgs ? buildPlugin)
                     { inherit buildPlugin; };
            in
            pkgs.callPackage pluginPath extra;

          # Full in-tree build: kernel + every bundled plugin + tests.
          # Used by CI sanitisers and the dev-shell quickstart; not
          # the operator-facing artefact (operators compose through
          # `goodnet.lib.compose` from `goodnet-core` + selected
          # plugin derivations).
          everything = stdenv.mkDerivation {
            pname   = "goodnet-everything";
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
        in
        {
          # Operator default: kernel only. The Linux-model analogue is
          # `linux-headers` + selected drivers, not a kitchen-sink
          # `linux-all`. Per-plugin packages follow below.
          default = goodnet-core;

          inherit goodnet-core everything;

          goodnet-handler-heartbeat = callPlugin "heartbeat" "handlers";
          goodnet-link-tcp          = callPlugin "tcp"       "links";
          goodnet-link-udp          = callPlugin "udp"       "links";
          goodnet-link-ws           = callPlugin "ws"        "links";
          goodnet-link-ipc          = callPlugin "ipc"       "links";
          goodnet-link-tls          = callPlugin "tls"       "links";
          goodnet-security-noise    = callPlugin "noise"     "security";
          goodnet-security-null     = callPlugin "null"      "security";
          goodnet-protocol-gnet     = callPlugin "gnet"      "protocols";
          goodnet-protocol-raw      = callPlugin "raw"       "protocols";
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

          # `nix run .#goodnet -- <subcommand> [args]` — operator-facing
          # multicall CLI. Builds Release if needed, then runs the
          # in-tree binary with the passed args. Same shell-app pattern
          # as `gn-demo` so the dev shell's CMAKE_PREFIX_PATH /
          # PKG_CONFIG_PATH are available for `find_package`.
          gn-goodnet = pkgs.writeShellScriptBin "gn-goodnet" ''
            exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" --command bash -c '
              BUILD_DIR="build-release"
              if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
                echo ">>> Configuring Release build..."
                cmake -B "$BUILD_DIR" -G Ninja \
                  -DCMAKE_BUILD_TYPE=Release \
                  -DGOODNET_BUILD_TESTS=OFF
              fi
              cmake --build "$BUILD_DIR" --target goodnet -j"$(nproc)"
              "$BUILD_DIR/bin/goodnet" "$@"
            ' _ "$@"
          '';

          # `nix run .#node -- --config X --manifest Y` — alias for the
          # `goodnet run` subcommand. v1 ships the alias even though
          # `run` itself lands in Wave 8.1.b: when the subcommand
          # ships, the alias starts working without a flake bump. For
          # now it forwards to `goodnet run` and exits with the
          # «not yet implemented» message.
          gn-node = pkgs.writeShellScriptBin "gn-node" ''
            exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" --command bash -c '
              BUILD_DIR="build-release"
              if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
                echo ">>> Configuring Release build..."
                cmake -B "$BUILD_DIR" -G Ninja \
                  -DCMAKE_BUILD_TYPE=Release \
                  -DGOODNET_BUILD_TESTS=OFF
              fi
              cmake --build "$BUILD_DIR" --target goodnet -j"$(nproc)"
              "$BUILD_DIR/bin/goodnet" run "$@"
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
          goodnet       = { type = "app"; program = "${gn-goodnet}/bin/gn-goodnet"; };
          node          = { type = "app"; program = "${gn-node}/bin/gn-node"; };
        });

      devShells = forAllSystems (system: pkgs:
        let
          stdenv = pkgs.gcc15Stdenv;
          # `inputsFrom = [ goodnet-everything ]` brings the full
          # toolchain — kernel deps plus gtest / rapidcheck — into the
          # shell so `cmake --build && ctest` works out of the box.
          # The `default` package is the operator-facing kernel-only
          # build; the dev shell needs the test framework on top.
          goodnet-everything =
            self.packages.${pkgs.stdenv.hostPlatform.system}.everything;
        in
        {
          default = (pkgs.mkShell.override { inherit stdenv; }) {
            inputsFrom = [ goodnet-everything ];
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
  nix run .#goodnet -- ... — operator CLI (version, config validate, ...)
  nix run .#node    -- ... — operator CLI alias for `goodnet run`
  nix run .#install-hooks  — wire .githooks/ into this clone

EOF
            '';
          };
        });
    };
}
