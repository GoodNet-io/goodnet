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
      #   other plugins (link-{tcp,udp,ws,ice,quic,tls},
      #   handler-{heartbeat,store,dns}, security-{noise,null},
      #   strategy-float_send_rtt) live in their own gits and gate
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
      # Bundles a daemon binary + a chosen plugin set + an optional
      # config + identity into a single derivation. The output
      # layout matches what `goodnetd run` expects out of
      # `/etc/goodnet`, so the wrapper script in `bin/goodnet-node`
      # invokes the real binary against the bundled paths.
      #
      # **Daemon binary source** — the kernel repo does not ship
      # `goodnetd`; the daemon lives at
      # `github:GoodNet-io/goodnetd` and produces `bin/goodnetd`
      # in its own derivation. The `kernel` parameter below
      # expects a derivation that provides that path — typically
      # pulled as a flake input. Passing the bare kernel
      # output (which only ships libraries + plugin .sos) fails the
      # build with a clear "no such file" pointing at the missing
      # binary. An operator's flake threads both inputs:
      #
      #     inputs.goodnet.url   = "github:GoodNet-io/goodnet";
      #     inputs.goodnetd.url  = "github:GoodNet-io/goodnetd";
      #     ...
      #     goodnet.lib.compose pkgs {
      #       kernel  = goodnetd.packages.${system}.default;
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
            ${kernel}/bin/goodnetd manifest gen plugins/lib*.so > manifest.json
          '';

          installPhase = ''
            mkdir -p $out/bin $out/lib/goodnet/plugins $out/etc/goodnet
            cp ${kernel}/bin/goodnetd $out/bin/goodnetd
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

            makeWrapper $out/bin/goodnetd $out/bin/goodnet-node \
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
            # throughput, socat for AF_UNIX echo. Both stage cleanly
            # in the dev shell so bench/comparison/runners/run_all.sh
            # works out of the box. libp2p / iroh Rust baselines come
            # in through their own `cargo build` under
            # bench/comparison/setup/{06_libp2p_rs,07_iroh}.sh.
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

          # Header-only redistribution channel for language bindings
          # (`GoodNet-io/bridges-rust`, `GoodNet-io/bridges-python`,
          # etc.) and other not-kernel consumers that need the SDK
          # surface without dragging the full kernel build closure.
          # Ships only `sdk/*.h` + `sdk/extensions/` + `sdk/remote/` +
          # `sdk/cpp/*.hpp` + `docs/contracts/*.en.md` + LICENSE.
          # The header-only model means a language binding pins a
          # specific `v*` tag of the kernel flake and gets a stable
          # ABI snapshot — same canonical source as the kernel's own
          # in-tree build consumes.
          sdk-headers = pkgs.stdenvNoCC.mkDerivation {
            pname   = "goodnet-sdk-headers";
            version = "1.0.0-rc4";
            src     = pkgs.lib.cleanSourceWith {
              src    = ./.;
              filter = path: type:
                let
                  rel = pkgs.lib.removePrefix (toString ./. + "/")
                                                (toString path);
                  topLevel = builtins.head
                    (pkgs.lib.splitString "/" rel);
                in
                  builtins.elem topLevel [ "sdk" "docs" "LICENSE" ];
            };
            dontBuild = true;
            installPhase = ''
              mkdir -p $out/include/sdk
              cp -r sdk/*.h sdk/extensions sdk/remote sdk/cpp $out/include/sdk/
              if [ -d sdk/test ]; then
                cp -r sdk/test $out/include/sdk/
              fi
              mkdir -p $out/share/doc/goodnet-sdk
              cp -r docs/contracts $out/share/doc/goodnet-sdk/
              cp LICENSE $out/share/doc/goodnet-sdk/
            '';
            meta = {
              description = "GoodNet SDK headers — C ABI + C++ bridges + normative contracts.";
              license     = pkgs.lib.licenses.mit;
            };
          };

          # Pip-installable Python wrapper over libgoodnet_kernel
          # through cffi (ABI mode). Pure-Python, no compiled
          # extensions — the kernel `.so` is loaded at runtime via
          # `dlopen`. The `goodnet-core` derivation is propagated so
          # the kernel library is on the consumer's runtime closure;
          # users still need `GOODNET_CORE_LIB` or `LD_LIBRARY_PATH`
          # pointing at `${goodnet-core}/lib/` for the dlopen to
          # resolve. See `bindings/python/README.md` for the runtime
          # dependency notes.
          goodnet-python = pkgs.python3Packages.buildPythonPackage {
            pname   = "goodnet";
            version = "0.1.0";
            src     = ./bindings/python;
            format  = "pyproject";
            nativeBuildInputs = with pkgs.python3Packages; [
              setuptools wheel
            ];
            propagatedBuildInputs = [
              pkgs.python3Packages.cffi
              goodnet-core
            ];
            # Tests gated on libgoodnet_kernel.so being reachable;
            # the smoke suite skips gracefully when it is not, but
            # the Nix sandbox blocks network and dlopen of paths
            # outside the build closure. We point GOODNET_CORE_LIB
            # at the propagated kernel build so `pytest` can drive
            # the lifecycle round-trip during `nix build`.
            checkInputs = [ pkgs.python3Packages.pytest ];
            preCheck = '''
              export GOODNET_CORE_LIB=${goodnet-core}/lib/libgoodnet_kernel.so
            ''';
            pythonImportsCheck = [ "goodnet" "goodnet._ffi" "goodnet.errors" ];
            meta = {
              description = "Python bindings for the GoodNet network kernel (cffi ABI mode).";
              license     = pkgs.lib.licenses.mit;
              platforms   = pkgs.lib.platforms.linux ++ pkgs.lib.platforms.darwin;
            };
          };
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          # Truly-static kernel + bundled plugin set against musl +
          # `pkgsStatic` versions of openssl, libsodium, spdlog, fmt,
          # libstdc++, libgcc. The resulting `bin/goodnet` has no
          # dynamic dependencies (ldd reports "not a dynamic
          # executable") and runs unchanged inside a `scratch`
          # container, a chroot, or a stripped embedded rootfs.
          # Linux-only because pkgsStatic targets the musl Linux
          # cross; Darwin static builds use a different toolchain.
          goodnet-core-static = import ./nix/goodnet-static.nix {
            inherit pkgs;
          };

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

          # `nix run .#build [-- release|debug|static]` — single
          # build app with subarg-driven variant select. Default
          # debug.
          #
          # `debug` and `release` re-enter the dev shell and run a
          # plain CMake build under the dynamic gcc15 toolchain;
          # each variant lives in its own `build-<variant>/` so the
          # two coexist without pin-ponging the cache.
          #
          # `static` is the truly-static cut: rather than running a
          # second CMake under the dev shell (which would inherit
          # the host's dynamic OpenSSL / libsodium / libstdc++ and
          # produce a "static plugins, dynamic libc" hybrid), it
          # dispatches to `nix build .#goodnet-core-static`. That
          # derivation rebuilds the kernel under `pkgsStatic` against
          # musl + statically-archived dependencies, then mirrors the
          # resulting tree at `build-static/` so the rest of the
          # repo's tooling (smoke tests, packaging scripts) keeps
          # finding the binary at the same path as the other
          # variants. The Nix store path is the source of truth; the
          # `build-static/` copy is a convenience.
          gn-build = pkgs.writeShellScriptBin "gn-build" ''
            exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" --command bash -c '
              variant="''${1:-debug}"
              shift || true
              if [ "$variant" = "static" ]; then
                # `nix build .#goodnet-core-static` produces a result
                # symlink with `lib/libgoodnet_kernel.a` + worker
                # binaries at `bin/`. Mirror the layout at
                # `build-static/` so external tooling (Docker
                # packaging, smoke scripts) reads the same path the
                # debug / release variants populate. The nix store
                # tree is read-only; `chmod -R u+w` after copy so a
                # subsequent run can prune the mirror.
                flake_dir="''${FLAKE_DIR:-.}"
                echo ">>> static: nix build $flake_dir#goodnet-core-static"
                ${pkgs.nix}/bin/nix build "$flake_dir#goodnet-core-static" \
                  -o "$flake_dir/result-static" "$@"
                if [ -d "$flake_dir/build-static" ]; then
                  chmod -R u+w "$flake_dir/build-static"
                  rm -rf "$flake_dir/build-static/bin" \
                         "$flake_dir/build-static/lib"
                fi
                mkdir -p "$flake_dir/build-static"
                cp -rL "$flake_dir/result-static/bin" \
                       "$flake_dir/build-static/bin"
                cp -rL "$flake_dir/result-static/lib" \
                       "$flake_dir/build-static/lib"
                chmod -R u+w "$flake_dir/build-static"
                echo ""
                echo "static build complete:"
                echo "  $flake_dir/build-static/bin/  (statically linked ELFs)"
                echo "  $flake_dir/build-static/lib/  (.a archives)"
                exit 0
              fi
              tests_flag="-DGOODNET_BUILD_TESTS=ON"
              case "$variant" in
                debug)   build_type=Debug   ; build_dir=build         ;;
                release) build_type=Release ; build_dir=build-release ;;
                *) echo "build: unknown variant $variant (debug|release|static)" >&2
                   exit 1 ;;
              esac
              if [ ! -f "$build_dir/CMakeCache.txt" ]; then
                echo ">>> Configuring $build_type build in $build_dir..."
                cmake -B "$build_dir" -G Ninja \
                  -DCMAKE_BUILD_TYPE=$build_type \
                  $tests_flag
              fi
              cmake --build "$build_dir" -j"$(nproc)" "$@"
            ' _ "$@"
          '';

          # `nix run .#test [-- asan|tsan|coverage|all]` — single test
          # app with subarg-driven sanitizer / coverage select. Default
          # vanilla debug (no instrumentation). \`asan\` and \`tsan\`
          # build in dedicated \`build-asan\` / \`build-tsan\` trees
          # with the appropriate flags + runtime env; \`coverage\`
          # builds in \`build-coverage\` under
          # \`-fprofile-arcs -ftest-coverage\` + \`-O0 -g\` (the
          # GOODNET_COVERAGE CMake option), runs ctest, then post-
          # processes the .gcda / .gcno tree with lcov to print line +
          # function coverage percent. \`all\` runs vanilla + asan +
          # tsan in sequence and bails on the first failure — coverage
          # is excluded because its lcov post-step is slow and would
          # double the cost of a multi-pass run without adding pass /
          # fail signal. Trailing args after the variant are forwarded
          # to ctest (e.g. \`test -- asan -R Noise\`).
          gn-test = pkgs.writeShellScriptBin "gn-test" ''
            exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" --command bash -c '
              variant="''${1:-vanilla}"
              shift || true
              run_one() {
                local v="$1"; shift
                local build_dir flags runtime_env=""
                local cmake_extra=""
                local post_cmd=""
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
                  coverage)
                    # Coverage is a CMake option (GOODNET_COVERAGE) rather
                    # than a CFLAGS injection because the -O0 it needs
                    # conflicts with the sanitiser -O1 path — keeping the
                    # toggle inside CMake means the same configure cannot
                    # accidentally combine coverage + sanitiser flags from
                    # a stale env.
                    build_dir=build-coverage
                    cmake_extra="-DGOODNET_COVERAGE=ON"
                    post_cmd="coverage_summary"
                    ;;
                  *)
                    echo "test: unknown variant $v (vanilla|asan|tsan|coverage|all)" >&2
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
                    -DGOODNET_BUILD_TESTS=ON \
                    $cmake_extra
                fi
                cmake --build "$build_dir" -j"$(nproc)"
                if [ -n "$runtime_env" ]; then
                  env $runtime_env \
                    LD_LIBRARY_PATH="$build_dir:$build_dir/plugins''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
                    ctest --test-dir "$build_dir" --output-on-failure "$@"
                else
                  ctest --test-dir "$build_dir" --output-on-failure "$@"
                fi
                if [ "$post_cmd" = "coverage_summary" ]; then
                  coverage_summary "$build_dir"
                fi
              }
              # `lcov --capture` reads the `.gcno` / `.gcda` tree that
              # the gcov compile + run pair leaves under `build-coverage/`.
              # The filter strips `/nix/store/*` (toolchain headers),
              # `*/build*/*` (generated config + protobuf-ish stubs), and
              # `*/tests/*` (the tests themselves — coverage of the test
              # harness is not what the gate measures) so the printed
              # totals reflect kernel + plugin source only. `lcov` is not
              # in the dev shell; `nix shell nixpkgs#lcov --command`
              # stages it inline so the script works whether or not the
              # operator pre-installed lcov.
              #
              # `--ignore-errors inconsistent,unused,mismatch,negative`
              # bridges a gcc-15 / lcov-2.3.2 protocol gap: gcc-15
              # emits gcov line records whose end-line metadata
              # occasionally disagrees with the intermediate-format
              # span lcov computes (typical case: gtest TestBody
              # methods whose macro-expanded body spans more lines
              # than lcov walks) and reports the odd -1 hit count on
              # template-heavy STL headers. lcov upgrades both to
              # ERROR by default and refuses to write the `.info`
              # file; the listed categories are the toolchain mismatch
              # — silencing them is the documented workaround, see
              # lcov(1) under `--ignore-errors`.
              coverage_summary() {
                bd="$1"
                if command -v lcov >/dev/null 2>&1; then
                  LCOV_CMD=""
                else
                  LCOV_CMD="${pkgs.nix}/bin/nix shell nixpkgs#lcov --command"
                fi
                $LCOV_CMD lcov --capture --directory "$bd" \
                  --ignore-errors inconsistent,unused,mismatch,negative \
                  --output-file "$bd/coverage.info"
                $LCOV_CMD lcov --remove "$bd/coverage.info" \
                  "/nix/store/*" "*/build*/*" "*/tests/*" \
                  "*/gtest/*" "*/gmock/*" \
                  --ignore-errors unused,inconsistent \
                  --output-file "$bd/coverage.filtered.info"
                $LCOV_CMD lcov --summary "$bd/coverage.filtered.info" \
                  --ignore-errors inconsistent
              }
              if [ "$variant" = "all" ]; then
                # `all` deliberately skips coverage — the lcov post-
                # processing roughly doubles the wall time and provides
                # no pass / fail signal beyond what ctest itself already
                # produces. Coverage stays a deliberate `-- coverage`
                # invocation.
                run_one vanilla "$@" && run_one asan "$@" && run_one tsan "$@"
              else
                run_one "$variant" "$@"
              fi
            ' _ "$@"
          '';

          # Opt-in: wire `.githooks/` into the local clone so
          # `git commit` runs `clang-tidy --warnings-as-errors=*` on
          # staged C++ files (pre-commit) and `git push` to
          # `refs/heads/main` re-runs the cheap CI subset
          # (livedoc --check + pytest + vanilla ctest) before the
          # push leaves the machine (pre-push). Both hooks live in
          # `.githooks/`; `core.hooksPath` picks the directory up
          # wholesale, so a new file in `.githooks/` is auto-wired
          # without touching this script.
          gn-install-hooks = pkgs.writeShellScriptBin "gn-install-hooks" ''
            set -euo pipefail
            git config core.hooksPath .githooks
            echo ">>> hooks installed: .githooks/"
            echo "    pre-commit  : clang-tidy on staged C++"
            echo "    pre-push    : test gate on push to main"
            echo "    bypass once : git commit/push --no-verify"
          '';

          # `nix run .#run -- <demo|node|goodnetd> [args]` — single
          # umbrella. \`demo\` builds + runs the self-contained
          # two-node quickstart from `examples/two_node/`; \`node\`
          # and \`goodnetd\` redirect the operator to the standalone
          # `GoodNet-io/goodnetd` repo since the daemon binary no
          # longer ships from this monorepo.
          gn-run = pkgs.writeShellScriptBin "gn-run" ''
            exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" --command bash -c '
              if [ $# -lt 1 ]; then
                echo "run: usage: nix run .#run -- <demo|node|goodnetd> [args]" >&2
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
                goodnet|goodnetd|node)
                  echo "run: the goodnetd daemon binary now ships from" >&2
                  echo "  github.com/GoodNet-io/goodnetd" >&2
                  echo "" >&2
                  echo "  build it standalone:" >&2
                  echo "    nix build github:GoodNet-io/goodnetd" >&2
                  echo "    ./result/bin/goodnetd $@" >&2
                  exit 1
                  ;;
                *)
                  echo "run: unknown kind $kind (demo|node|goodnetd)" >&2
                  exit 1
                  ;;
              esac
            ' _ "$@"
          '';

          # `nix run .#plugin -- new <kind> <name>` — scaffold a fresh
          # plugin under `plugins/<kind>/<name>/` with the standalone
          # CMakeLists branch, default.nix, standalone flake, source
          # skeleton, placeholder gtest, README, and a TODO LICENSE.
          gn-new-plugin = import ./nix/new-plugin.nix { inherit pkgs; };

          # `nix run .#plugin -- pull <repo-name>` — clone a loadable
          # plugin's git into `plugins/<kind>/<name>/` so the kernel
          # build picks it up. Defaults to a local bare mirror under
          # `${XDG_DATA_HOME}/goodnet-mirrors/` (overridable via
          # `GOODNET_PLUGIN_MIRROR_DIR`) and falls back to
          # `github:GoodNet-io/<repo-name>` if no mirror is set up.
          gn-pull-plugin = import ./nix/pull-plugin.nix { inherit pkgs; };

          # `nix run .#plugin -- install` — pull every canonical
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
          # the flat `new-plugin` / `pull-plugin` / `install-plugins`
          # triplet — the underlying derivations stay built (used by
          # `gn-setup`) but are not exposed as top-level apps; reach
          # them through this umbrella.
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

          # Mirror builder (invoked from `gn-setup`) — bare-clone each
          # plugin's nested working git into `${MIRROR_DIR}/<repo>.git`
          # and wire `origin` in the working clone so subsequent
          # `git push` / `git pull` flow against the mirror.
          # Single-call setup that turns each in-tree plugin into
          # something `install-plugins` can re-clone for a fresh
          # checkout. Not exposed as a top-level app; the bootstrap
          # path is `nix run .#setup`.
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
            # throughput, socat for AF_UNIX echo. Both stage cleanly
            # in the dev shell so bench/comparison/runners/run_all.sh
            # works out of the box. libp2p / iroh Rust baselines come
            # in through their own `cargo build` under
            # bench/comparison/setup/{06_libp2p_rs,07_iroh}.sh.
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
              # consume; pytest runs the python suites under
              # tests/livedoc/ (livedoc parser tests) and
              # tests/tools/ (bench_compare regression-gate smoke).
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
            # idempotent check; if any loadable plugin slot is
            # empty, dispatch to `install-plugins` so a fresh kernel
            # checkout becomes a fully-wired workspace without a
            # separate manual setup step. The slot list mirrors
            # `nix/install-plugins.nix` — keep both in sync when a
            # new plugin lands. `|| true` keeps shell entry usable
            # when no mirror / remote is reachable — the operator
            # sees the warning `install-plugins` printed and can
            # act on it.
            shellHook = ''
              export CCACHE_DIR="$HOME/.cache/ccache"
              export CMAKE_C_COMPILER_LAUNCHER=ccache
              export CMAKE_CXX_COMPILER_LAUNCHER=ccache

              _gn_plugin_slots="\
                plugins/handlers/heartbeat \
                plugins/handlers/store \
                plugins/handlers/dns \
                plugins/links/tcp \
                plugins/links/udp \
                plugins/links/ws \
                plugins/links/ipc \
                plugins/links/tls \
                plugins/links/ice \
                plugins/security/noise \
                plugins/security/null \
                bridges/cpp"
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
    nix run .#test  [-- asan|tsan|coverage|all]   default vanilla

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
