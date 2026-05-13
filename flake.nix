{
  description = "GoodNet kernel + SDK with bundled baseline plugins.";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      # Cross-platform posture (honest):
      #
      # * **Linux x86_64 / aarch64** — full path. Every bundled
      #   plugin builds and tests run under sanitisers. CI gates on
      #   this matrix.
      # * **Darwin x86_64 / aarch64** — kernel + SDK + GNET protocol
      #   build via Asio's portable reactor; the kernel's
      #   `plugin_manager.cpp` falls back from `openat2` to the
      #   `O_NOFOLLOW` integrity gate behind `__linux__`. Only the
      #   IPC plugin currently carries the `LOCAL_PEERCRED` port;
      #   other plugins (tcp/udp/ws/ice/quic/tls/heartbeat/noise/
      #   null/strategies) live in their own gits and gate
      #   themselves via `meta.platforms` — they simply don't appear
      #   in the per-plugin flake's output set on Darwin until each
      #   is ported. The composed-node derivation here keeps
      #   `meta.platforms = lib.platforms.linux` because operators
      #   want a bundle, not a half-set; the kernel-only
      #   `goodnet-core` derivation builds for Darwin today. See
      #   `docs/architecture/cross-platform.ru.md`.
      # * **Windows** — wire/build groundwork landed under
      #   `_WIN32` guards; the named-pipe runtime stays its own
      #   plan.
      forAllSystems = f:
        nixpkgs.lib.genAttrs
          [ "x86_64-linux" "aarch64-linux"
            "x86_64-darwin" "aarch64-darwin" ]
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
        , version ? "1.0.0-rc3"
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

        # Building blocks for per-plugin standalone flakes — see
        # `nix/plugin-helpers.nix` for the consumed interface.
        # A plugin's `flake.nix` uses these to keep its outputs
        # under ~50 lines instead of carrying an inline copy of
        # the sanitizer flag tuple, the dev shell shape, and the
        # five-app set every plugin shares.
        plugin-helpers = import ./nix/plugin-helpers.nix;
      };


      packages = forAllSystems (system: pkgs:
        let
          stdenv = pkgs.gcc15Stdenv;
          coreBuildInputs = with pkgs; [
            asio spdlog fmt nlohmann_json libsodium openssl gbenchmark
            # External bench baselines — iperf3 for raw TCP/UDP
            # throughput, socat for AF_UNIX echo, libuv for DX LOC.
            # All three stage cleanly in the dev shell so
            # bench/comparison/runners/run_all.sh works out of the
            # box; libwebrtc / nginx-quic remain Docker-only.
            iperf3 socat
            # SQLite for handler-store's optional SqliteStore
            # backend. Kernel itself never links sqlite; propagated
            # here so plugins/handlers/store/ can build in-tree
            # without a second `nix develop` shell, and so the
            # standalone plugin default.nix inherits it through
            # goodnet-core's propagatedBuildInputs.
            sqlite
            # c-ares for handler-dns upstream resolution (D-DNS.4).
            # Kernel doesn't link c-ares; same convenience pattern
            # as sqlite — in-tree dev gets pkg-config libcares
            # without a second devShell, standalone plugin builds
            # inherit it through propagatedBuildInputs.
            c-ares
          ];
          coreNative = with pkgs; [ cmake ninja pkg-config ];

          # Kernel-only build. Skips iterating `plugins/` so this
          # derivation produces just `goodnet_kernel` + SDK + GNET
          # (mandatory mesh framing) + `GoodNet::ctx_accessors` + the
          # operator CLI. Loadable plugins live in their own flakes;
          # this derivation does not depend on plugin source being
          # present in the monorepo's git tree.
          goodnet-core = stdenv.mkDerivation {
            pname   = "goodnet-core";
            version = "1.0.0-rc3";
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

        in
        {
          # The root flake exposes only the kernel — loadable plugins
          # live in their own flakes under `plugins/<kind>/<name>/`
          # and consume the kernel through `nix/kernel-only/`. There
          # is no `everything` aggregate any more: the operator
          # composes a node by listing the plugin flakes they want
          # and threading their `packages.<system>.default` through
          # `goodnet.lib.compose`. Aggregate CI testing is the same
          # operator-side recipe — no kernel-side enumeration of the
          # plugin set.
          default = goodnet-core;
          inherit goodnet-core;
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          # Reproducible Docker image around the static kernel.
          # Linux-only because dockerTools.buildLayeredImage emits a
          # Linux container; building from a Darwin host requires a
          # remote Linux builder.
          docker-static = import ./nix/docker.nix {
            inherit pkgs goodnet-core;
          };

          # Windows MVP cross-build via mingw-w64. Static-plugin
          # single-`goodnet.exe` with the lean bundle (TCP + UDP +
          # Noise + Null + heartbeat). Linux-host-only — pkgsCross
          # runs on Linux and emits Windows PE; no native MSVC path
          # is wired yet.
          goodnet-windows = import ./nix/goodnet-windows.nix {
            inherit pkgs;
          };
        });

      apps = forAllSystems (system: pkgs:
        let
          # All build apps re-enter the dev shell through `nix develop
          # --command`. `writeShellApplication` only sets up PATH from
          # `runtimeInputs`; CMake's `find_package(... CONFIG)` needs
          # the full `CMAKE_PREFIX_PATH` / `PKG_CONFIG_PATH` that the
          # dev shell wires from `inputsFrom = [ goodnet-core ]`.

          # `nix run .#build [-- release|debug]` — single build app
          # with subarg-driven variant select. Default debug. Each
          # variant lives in its own \`build-<variant>/\` so debug
          # and release coexist without pin-ponging the cache.
          gn-build = pkgs.writeShellScriptBin "gn-build" ''
            exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" --command bash -c '
              variant="''${1:-debug}"
              shift || true
              static_flag=""
              tests_flag="-DGOODNET_BUILD_TESTS=ON"
              case "$variant" in
                debug)   build_type=Debug   ; build_dir=build         ;;
                release) build_type=Release ; build_dir=build-release ;;
                static)  build_type=Release ; build_dir=build-static
                         static_flag="-DGOODNET_STATIC_PLUGINS=ON"
                         tests_flag="-DGOODNET_BUILD_TESTS=OFF"      ;;
                *) echo "build: unknown variant $variant (debug|release|static)" >&2
                   exit 1 ;;
              esac
              if [ ! -f "$build_dir/CMakeCache.txt" ]; then
                echo ">>> Configuring $build_type build in $build_dir..."
                cmake -B "$build_dir" -G Ninja \
                  -DCMAKE_BUILD_TYPE=$build_type \
                  $tests_flag $static_flag
              fi
              cmake --build "$build_dir" -j"$(nproc)" "$@"
            ' _ "$@"
          '';

          # `nix run .#test [-- asan|tsan|all]` — single test app
          # with subarg-driven sanitizer select. Default vanilla
          # debug (no instrumentation). \`asan\` and \`tsan\` build
          # in dedicated \`build-asan\` / \`build-tsan\` trees with
          # the appropriate flags + runtime env; \`all\` runs the
          # vanilla, asan, and tsan suites in sequence and bails on
          # the first failure. Trailing args after the variant are
          # forwarded to ctest (e.g. \`test -- asan -R Noise\`).
          gn-test = pkgs.writeShellScriptBin "gn-test" ''
            exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" --command bash -c '
              variant="''${1:-vanilla}"
              shift || true
              run_one() {
                local v="$1"; shift
                local build_dir flags runtime_env=""
                case "$v" in
                  vanilla)
                    build_dir=build flags=""
                    ;;
                  asan)
                    build_dir=build-asan
                    flags="-fsanitize=address,undefined -fno-sanitize-recover=all -O1 -g -fno-omit-frame-pointer"
                    runtime_env="ASAN_OPTIONS=abort_on_error=1:detect_leaks=1:halt_on_error=1:symbolize=1:strict_string_checks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1"
                    ;;
                  tsan)
                    build_dir=build-tsan
                    flags="-fsanitize=thread -O1 -g -fno-omit-frame-pointer"
                    runtime_env="TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1:history_size=4"
                    ;;
                  *)
                    echo "test: unknown variant $v (vanilla|asan|tsan|all)" >&2
                    return 1
                    ;;
                esac
                echo ">>> test: $v in $build_dir"
                if [ -n "$flags" ]; then
                  export NIX_HARDENING_ENABLE=""
                  export CFLAGS="$flags"
                  export CXXFLAGS="$flags"
                  export LDFLAGS="$flags"
                fi
                if [ ! -f "$build_dir/CMakeCache.txt" ]; then
                  cmake -B "$build_dir" -G Ninja \
                    -DCMAKE_BUILD_TYPE=Debug \
                    -DGOODNET_BUILD_TESTS=ON
                fi
                cmake --build "$build_dir" -j"$(nproc)"
                if [ -n "$runtime_env" ]; then
                  env $runtime_env \
                    LD_LIBRARY_PATH="$build_dir:$build_dir/plugins''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
                    ctest --test-dir "$build_dir" --output-on-failure "$@"
                else
                  ctest --test-dir "$build_dir" --output-on-failure "$@"
                fi
              }
              if [ "$variant" = "all" ]; then
                run_one vanilla "$@" && run_one asan "$@" && run_one tsan "$@"
              else
                run_one "$variant" "$@"
              fi
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

          # `nix run .#run -- <demo|node|goodnet> [args]` — single
          # umbrella over the three runnable artefacts. Builds the
          # corresponding target into a Release tree and execs it
          # with the trailing args. \`demo\` self-contained two-node
          # quickstart; \`node\` = \`goodnet run\` alias; \`goodnet\`
          # = the operator multicall CLI direct.
          gn-run = pkgs.writeShellScriptBin "gn-run" ''
            exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" --command bash -c '
              if [ $# -lt 1 ]; then
                echo "run: usage: nix run .#run -- <demo|node|goodnet> [args]" >&2
                exit 1
              fi
              kind="$1"; shift
              case "$kind" in
                demo)
                  build_dir=build-demo
                  if [ ! -f "$build_dir/CMakeCache.txt" ]; then
                    cmake -B "$build_dir" -G Ninja \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DGOODNET_BUILD_EXAMPLES=ON \
                      -DGOODNET_BUILD_TESTS=OFF
                  fi
                  cmake --build "$build_dir" --target goodnet_demo -j"$(nproc)"
                  exec "$build_dir/bin/goodnet-demo" "$@"
                  ;;
                goodnet|node)
                  build_dir=build-release
                  if [ ! -f "$build_dir/CMakeCache.txt" ]; then
                    cmake -B "$build_dir" -G Ninja \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DGOODNET_BUILD_TESTS=OFF
                  fi
                  cmake --build "$build_dir" --target goodnet -j"$(nproc)"
                  if [ "$kind" = "node" ]; then
                    exec "$build_dir/bin/goodnet" run "$@"
                  else
                    exec "$build_dir/bin/goodnet" "$@"
                  fi
                  ;;
                *)
                  echo "run: unknown kind $kind (demo|node|goodnet)" >&2
                  exit 1
                  ;;
              esac
            ' _ "$@"
          '';

          # `nix run .#new-plugin -- <kind> <name>` — scaffold a fresh
          # plugin under `plugins/<kind>/<name>/` with the standalone
          # CMakeLists branch, default.nix, standalone flake, source
          # skeleton, placeholder gtest, README, and a TODO LICENSE.
          gn-new-plugin = import ./nix/new-plugin.nix { inherit pkgs; };

          # `nix run .#pull-plugin -- <repo-name>` — clone a loadable
          # plugin's git into `plugins/<kind>/<name>/` so the kernel
          # build picks it up. Defaults to a local mirror under
          # `~/Desktop/projects/GoodNet-io/` pre-rc1 and falls back
          # to `github:goodnet-io/<repo-name>` once the org repos
          # are public.
          gn-pull-plugin = import ./nix/pull-plugin.nix { inherit pkgs; };

          # `nix run .#install-plugins` — pull every canonical
          # loadable plugin in one shot. The single command a new
          # contributor (or a CI runner) runs after `git clone` to
          # materialise the full loadable set under `plugins/<kind>
          # /<name>/`. Already-present plugins are skipped silently.
          gn-install-plugins =
            import ./nix/install-plugins.nix { inherit pkgs; };

          # `nix run .#setup` — one-shot bootstrap composing
          # init-mirrors + install-plugins + install-hooks for a
          # fresh kernel checkout. Replaces the previous flat
          # triplet with a single entry point.
          gn-setup = import ./nix/setup.nix {
            inherit pkgs;
            init-mirrors    = gn-init-mirrors;
            install-plugins = gn-install-plugins;
            install-hooks   = gn-install-hooks;
          };

          # `nix run .#plugin -- <new|pull|install|update> [args]`
          # — single dispatch over the plugin lifecycle. Replaces
          # the flat new-plugin / pull-plugin / install-plugins
          # triplet (those stay exposed for compat until cleanup).
          gn-plugin = import ./nix/plugin.nix {
            inherit pkgs;
            new-plugin      = gn-new-plugin;
            pull-plugin     = gn-pull-plugin;
            install-plugins = gn-install-plugins;
          };

          # `nix run .#update` — refresh both halves of the workspace
          # at once: \`nix flake update\` on the kernel pulls fresh
          # nixpkgs / kernel-only inputs, then \`plugin -- update\`
          # fast-forwards every loadable plugin against its
          # \`origin\`. Single command for "give me everything
          # current".
          gn-update = pkgs.writeShellApplication {
            name = "goodnet-update";
            runtimeInputs = [ pkgs.nix ];
            text = ''
              set -euo pipefail
              if [ ! -f flake.nix ]; then
                echo "update: run from the kernel monorepo root" >&2
                exit 1
              fi
              echo ">>> update: nix flake update (kernel inputs)"
              nix flake update
              echo ""
              echo ">>> update: plugin -- update (loadable plugins)"
              ${gn-plugin}/bin/goodnet-plugin update
              echo ""
              echo "update: done."
            '';
          };

          # `nix run .#init-mirrors` — bare-clone each plugin's
          # nested working git into `${MIRROR_DIR}/<repo>.git` and
          # wire `origin` in the working clone so subsequent
          # `git push` / `git pull` flow against the mirror.
          # Single-call setup that turns each in-tree plugin into
          # something `install-plugins` can re-clone for a fresh
          # checkout.
          gn-init-mirrors =
            import ./nix/init-mirrors.nix { inherit pkgs; };

          # `nix run .#docs` — generate Doxygen API reference,
          # SVG diagrams, and the architecture canvas. Wraps the
          # python diagram scripts so the toolchain (graphviz +
          # python `graphviz` package + doxygen) is sealed from
          # the host environment.
          gn-docs = import ./nix/docs.nix { inherit pkgs; };
        in
        {
          default = { type = "app"; program = "${gn-build}/bin/gn-build"; };
          setup   = { type = "app"; program = "${gn-setup}/bin/goodnet-setup"; };
          update  = { type = "app"; program = "${gn-update}/bin/goodnet-update"; };
          build   = { type = "app"; program = "${gn-build}/bin/gn-build"; };
          test    = { type = "app"; program = "${gn-test}/bin/gn-test"; };
          run     = { type = "app"; program = "${gn-run}/bin/gn-run"; };
          plugin  = { type = "app"; program = "${gn-plugin}/bin/goodnet-plugin"; };
          docs    = { type = "app"; program = "${gn-docs}/bin/goodnet-docs"; };
        });

      devShells = forAllSystems (system: pkgs:
        let
          stdenv = pkgs.gcc15Stdenv;
          # Explicit toolchain — kernel build deps plus the test
          # framework. Loadable plugin source is not in the
          # monorepo's git tree any more (each lives in its own
          # standalone git under `plugins/<kind>/<name>/`), so the
          # shell only needs what kernel + integration tests need;
          # plugin-side dev work is done in the plugin's own
          # `nix develop` shell.
          coreBuildInputs = with pkgs; [
            asio spdlog fmt nlohmann_json libsodium openssl gbenchmark
            # External bench baselines — iperf3 for raw TCP/UDP
            # throughput, socat for AF_UNIX echo, libuv for DX LOC.
            # All three stage cleanly in the dev shell so
            # bench/comparison/runners/run_all.sh works out of the
            # box; libwebrtc / nginx-quic remain Docker-only.
            iperf3 socat
            # SQLite for handler-store's optional SqliteStore
            # backend. Kernel itself never links sqlite; propagated
            # here so plugins/handlers/store/ can build in-tree
            # without a second `nix develop` shell, and so the
            # standalone plugin default.nix inherits it through
            # goodnet-core's propagatedBuildInputs.
            sqlite
            # c-ares for handler-dns upstream resolution (D-DNS.4).
            # Kernel doesn't link c-ares; same convenience pattern
            # as sqlite — in-tree dev gets pkg-config libcares
            # without a second devShell, standalone plugin builds
            # inherit it through propagatedBuildInputs.
            c-ares
          ];
          coreNative = with pkgs; [ cmake ninja pkg-config ];
          testInputs = with pkgs; [ gtest rapidcheck ];

          # Re-import setup here so the dev shell's `shellHook` can
          # dispatch to it without sharing scope with the `apps`
          # let-binding. Setup itself wires init-mirrors,
          # install-plugins, and install-hooks.
          gn-init-mirrors =
            import ./nix/init-mirrors.nix { inherit pkgs; };
          gn-install-plugins =
            import ./nix/install-plugins.nix { inherit pkgs; };
          gn-install-hooks = pkgs.writeShellScriptBin "gn-install-hooks" ''
            set -euo pipefail
            git config core.hooksPath .githooks
          '';
          gn-setup = import ./nix/setup.nix {
            inherit pkgs;
            init-mirrors    = gn-init-mirrors;
            install-plugins = gn-install-plugins;
            install-hooks   = gn-install-hooks;
          };
        in
        {
          default = (pkgs.mkShell.override { inherit stdenv; }) {
            nativeBuildInputs = coreNative;
            buildInputs       = coreBuildInputs ++ testInputs;
            packages = with pkgs; [
              clang-tools ccache cmake-format jq
              gdb
              gnumake
              doxygen graphviz
              # python3 — graphviz drives diagram rendering; libclang
              # parses sdk/*.h for the livedoc fact extractor; pyyaml
              # serialises the fact files that gen_diagrams + canvas
              # consume; pytest runs the livedoc unit suite under
              # tests/livedoc/.
              (python3.withPackages (ps: [
                ps.graphviz
                ps.libclang
                ps.pyyaml
                ps.pytest
              ]))
            ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.valgrind ];

            # Welcome message points at the `nix run` apps so callers
            # never need to remember a CMake invocation by hand.
            # ccache is wired through so repeat builds do not pay the
            # full compile cost.
            #
            # Auto-pull missing loadable plugins. Each shell entry
            # (interactive `nix develop` and the `--command` apps
            # the operator-facing scripts re-enter) runs a fast
            # idempotent check; if any of the eight loadable
            # plugin slots is empty, dispatch to `install-plugins`
            # so a fresh kernel checkout becomes a fully-wired
            # workspace without a separate manual setup step.
            # `|| true` keeps shell entry usable when no mirror /
            # remote is reachable — the operator sees the warning
            # `install-plugins` printed and can act on it.
            shellHook = ''
              export CCACHE_DIR="$HOME/.cache/ccache"
              export CMAKE_C_COMPILER_LAUNCHER=ccache
              export CMAKE_CXX_COMPILER_LAUNCHER=ccache

              _gn_plugin_slots="\
                plugins/handlers/heartbeat \
                plugins/links/tcp \
                plugins/links/udp \
                plugins/links/ws \
                plugins/links/ipc \
                plugins/links/tls \
                plugins/security/noise \
                plugins/security/null"
              _gn_missing=0
              for _gn_slot in $_gn_plugin_slots; do
                if [ ! -d "$_gn_slot/.git" ]; then
                  _gn_missing=1
                  break
                fi
              done
              if [ "$_gn_missing" = 1 ]; then
                echo ">>> goodnet: loadable plugins missing — running setup"
                ${gn-setup}/bin/goodnet-setup || true
                echo ""
              fi
              unset _gn_plugin_slots _gn_missing _gn_slot

              cat <<'EOF'

GoodNet devShell  (gcc15, C++23)

  Setup / refresh:
    nix run .#setup            mirrors + plugins + hooks (one-shot)
    nix run .#update           refresh kernel inputs + plugins

  Build / test:
    nix run .# [-- release|debug]            default debug
    nix run .#build [-- release|debug]
    nix run .#test  [-- asan|tsan|all]       default vanilla

  Run artefacts:
    nix run .#run -- <demo|node|goodnet> [args]

  Plugin lifecycle:
    nix run .#plugin -- <new|pull|install|update> [args]

  Make wrapper for the same commands: make help

EOF
            '';
          };
        });
    };
}
