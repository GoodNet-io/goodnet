# nix/new-plugin.nix — `nix run .#new-plugin -- <kind> <name>` app.
#
# Generates the minimum-viable directory layout for a fresh plugin
# under `plugins/<kind>/<name>/`. Output mirrors what an in-tree
# plugin author would otherwise hand-roll: CMakeLists with the
# standalone branch wired to the kernel's helper macros,
# `default.nix` consumed by both the kernel aggregate flake and
# the plugin's own standalone flake, the standalone flake itself,
# a stub `<name>.cpp` carrying the plugin descriptor, a passing
# placeholder gtest under `tests/`, and TODO-marked README +
# LICENSE. After the run, `auto-discover.nix` picks the directory
# up the next time the kernel flake is evaluated.
#
# Templates are emitted with quoted heredocs (so neither bash nor
# the outer Nix string interpolate them) and then passed through
# `sed` to substitute four placeholders:
#
#   __KIND__           plural kind name (handlers / links / …)
#   __KIND_SINGULAR__  singular form (handler / link / …)
#   __NAME__           plugin name (matches the directory)
#   __PLUGIN_ATTR__    `goodnet-<kind_singular>-<name>`
#   __PLUGIN_TARGET__  `goodnet_<kind_singular>_<name>`
#
# This keeps the embedded templates readable — they look exactly
# like the files they will become — at the cost of two passes
# (heredoc + sed) per file. Worth it; the alternative is a swamp
# of `''$''${var}` escapes nested three contexts deep.

{ pkgs }:

pkgs.writeShellApplication {
  name = "goodnet-new-plugin";
  runtimeInputs = [ pkgs.gnused ];
  text = ''
    set -euo pipefail

    if [ $# -ne 2 ]; then
      cat >&2 <<USAGE
    Usage: nix run .#new-plugin -- <kind> <name>
      <kind>: handlers | links | protocols | security
      <name>: lowercase identifier matching [a-z][a-z0-9_-]*
    USAGE
      exit 1
    fi

    kind="$1"
    name="$2"

    case "$kind" in
      handlers|links|protocols|security) ;;
      *)
        echo "new-plugin: invalid kind '$kind'." >&2
        echo "  Valid kinds: handlers, links, protocols, security." >&2
        exit 1
        ;;
    esac

    if ! [[ "$name" =~ ^[a-z][a-z0-9_-]*$ ]]; then
      echo "new-plugin: name '$name' must match [a-z][a-z0-9_-]*" >&2
      echo "  (lowercase ASCII, may contain digits / underscore / dash," >&2
      echo "   must start with a letter)." >&2
      exit 1
    fi

    case "$kind" in
      handlers)  kind_singular="handler"  ;;
      links)     kind_singular="link"     ;;
      protocols) kind_singular="protocol" ;;
      security)  kind_singular="security" ;;
    esac

    plugin_attr="goodnet-''${kind_singular}-''${name}"
    plugin_target="goodnet_''${kind_singular}_''${name}"
    plugin_dir="plugins/''${kind}/''${name}"

    if [ -e "$plugin_dir" ]; then
      echo "new-plugin: $plugin_dir already exists, refusing to clobber." >&2
      echo "  Remove it manually if you really want to regenerate." >&2
      exit 1
    fi

    if [ ! -d plugins ] || [ ! -f flake.nix ]; then
      echo "new-plugin: run from the kernel monorepo root" >&2
      echo "  (the plugins/ directory and flake.nix must be reachable)." >&2
      exit 1
    fi

    mkdir -p "$plugin_dir/tests"

    # `subst` runs the four placeholders through sed. Quoted
    # heredoc above keeps both bash and the outer Nix string from
    # interpolating the template before this point.
    subst() {
      sed \
        -e "s|__KIND__|$kind|g" \
        -e "s|__KIND_SINGULAR__|$kind_singular|g" \
        -e "s|__NAME__|$name|g" \
        -e "s|__PLUGIN_ATTR__|$plugin_attr|g" \
        -e "s|__PLUGIN_TARGET__|$plugin_target|g"
    }

    cat <<'CMAKE' | subst > "$plugin_dir/CMakeLists.txt"
    cmake_minimum_required(VERSION 3.22)

    if(NOT TARGET GoodNet::sdk)
        project(__PLUGIN_TARGET__
            VERSION   0.1.0
            LANGUAGES CXX)
        find_package(GoodNet REQUIRED)
        goodnet_standalone_plugin_includes()
        include(CTest)
        if(BUILD_TESTING)
            find_package(GTest      REQUIRED)
            find_package(rapidcheck QUIET)
            goodnet_patch_rapidcheck_targets()
            set(GOODNET_BUILD_TESTS ON)
        endif()
    endif()

    # TODO: describe what this plugin does. The OBJECT library carries
    # the implementation for in-tree tests; the SHARED plugin via
    # add_plugin() registers entry points through the host_api.

    add_library(__PLUGIN_TARGET___objects OBJECT
        __NAME__.cpp
    )
    target_link_libraries(__PLUGIN_TARGET___objects PUBLIC GoodNet::sdk)
    target_compile_features(__PLUGIN_TARGET___objects PUBLIC cxx_std_23)
    target_compile_options(__PLUGIN_TARGET___objects PRIVATE
        -Wall -Wextra -Wpedantic -Wno-unused-parameter)
    set_target_properties(__PLUGIN_TARGET___objects PROPERTIES
        POSITION_INDEPENDENT_CODE ON)

    add_plugin(__PLUGIN_TARGET__
        __NAME__.cpp
    )
    target_link_libraries(__PLUGIN_TARGET__
        PRIVATE __PLUGIN_TARGET___objects)

    if(GOODNET_BUILD_TESTS)
        add_subdirectory(tests)
    endif()
    CMAKE

    cat <<'DEFNIX' | subst > "$plugin_dir/default.nix"
    # Standalone Nix derivation for the __PLUGIN_ATTR__ plugin.
    # Pulls the kernel SDK + AddPlugin.cmake helper through
    # `goodnet-core`'s propagatedBuildInputs.
    { stdenv
    , cmake
    , ninja
    , pkg-config
    , gtest
    , rapidcheck
    , goodnet-core
    , lib
    }:

    stdenv.mkDerivation {
      pname   = "__PLUGIN_ATTR__";
      version = "0.1.0";
      src     = ./.;
      nativeBuildInputs = [ cmake ninja pkg-config ];
      buildInputs       = [ goodnet-core gtest rapidcheck ];
      cmakeFlags = [
        "-DCMAKE_BUILD_TYPE=Release"
        "-DBUILD_TESTING=OFF"
      ];
      doCheck = false;

      meta = {
        description = "GoodNet plugin: __PLUGIN_ATTR__";
        # TODO: pick license per the project's strategic / periphery
        # split convention before this plugin merges.
        platforms = lib.platforms.linux;
      };
    }
    DEFNIX

    cat <<'FLAKE' | subst > "$plugin_dir/flake.nix"
    # Standalone dev / test / build flake for the __PLUGIN_ATTR__
    # plugin. See `plugins/security/noise/flake.nix` for the
    # canonical pattern; this flake is the scaffolded copy with
    # plugin-specific knobs swapped in.
    #
    # goodnet-standalone-plugin: __NAME__
    {
      description = "GoodNet __KIND_SINGULAR__ plugin: __NAME__ — standalone plugin flake.";

      inputs = {
        goodnet.url     = "path:../../..";
        nixpkgs.follows = "goodnet/nixpkgs";
      };

      outputs = { self, nixpkgs, goodnet }:
        let
          forAllSystems = f:
            nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
              (system: f system (import nixpkgs { inherit system; }));
          helpers = goodnet.lib.plugin-helpers;
        in
        {
          packages = forAllSystems (system: pkgs:
            let goodnet-core = goodnet.packages.''${system}.goodnet-core;
            in {
              default = pkgs.callPackage ./default.nix { inherit goodnet-core; };
            });

          devShells = forAllSystems (system: pkgs: {
            default = helpers.mkPluginDevShell pkgs {
              plugin = self.packages.''${system}.default;
              welcomeText = '''
      __PLUGIN_ATTR__  —  standalone plugin dev shell
        nix run .#build      — Release build (artefacts → ./build/)
        nix run .#test       — Release build with tests + ctest
        nix run .#test-asan  — ASan + UBSan build + ctest
        nix run .#test-tsan  — TSan build + ctest
        nix run .#debug      — Debug build + gdb on test___NAME__
    ''';
            };
          });

          apps = forAllSystems (system: pkgs:
            helpers.mkPluginApps pkgs {
              pluginName  = "__NAME__";
              debugBinary = "test___NAME__";
            });
        };
    }
    FLAKE

    cat <<'CPP' | subst > "$plugin_dir/$name.cpp"
    /// @file   plugins/__KIND__/__NAME__/__NAME__.cpp
    /// @brief  TODO: describe the plugin's role.

    #include <sdk/abi.h>
    #include <sdk/host_api.h>
    #include <sdk/plugin.h>

    namespace {

    // TODO: per-plugin state, vtables, registration logic.

    extern "C" int gn_plugin_init(const host_api_t* /*api*/, void* /*host_ctx*/) {
        // TODO: register vtables / extensions / channels here.
        return GN_OK;
    }

    extern "C" void gn_plugin_shutdown(void* /*host_ctx*/) {
        // TODO: tear down what gn_plugin_init registered.
    }

    }  // namespace

    GN_PLUGIN_DESCRIPTOR(
        /* name        */ "__PLUGIN_ATTR__",
        /* version     */ "0.1.0",
        /* sdk_major   */ 0,
        /* sdk_minor   */ 1,
        /* init        */ gn_plugin_init,
        /* shutdown    */ gn_plugin_shutdown
    );
    CPP

    cat <<'TESTSCMAKE' | subst > "$plugin_dir/tests/CMakeLists.txt"
    include(GoogleTest)

    add_executable(test___NAME__ test___NAME__.cpp)
    target_link_libraries(test___NAME__ PRIVATE
        GoodNet::sdk
        __PLUGIN_TARGET___objects
        GTest::gtest
        GTest::gtest_main)
    target_compile_features(test___NAME__ PRIVATE cxx_std_23)
    if(COMMAND goodnet_apply_pch)
        goodnet_apply_pch(test___NAME__)
    endif()
    gtest_discover_tests(test___NAME__
        DISCOVERY_TIMEOUT 30
        PROPERTIES TIMEOUT 60)
    TESTSCMAKE

    cat <<'TESTCPP' | subst > "$plugin_dir/tests/test_$name.cpp"
    /// @file   plugins/__KIND__/__NAME__/tests/test___NAME__.cpp
    /// @brief  TODO: replace this placeholder with real gtest cases.

    #include <gtest/gtest.h>

    TEST(__PLUGIN_TARGET__, PlaceholderPassesUntilRealTestsLand) {
        EXPECT_TRUE(true);
    }
    TESTCPP

    cat <<'README' | subst > "$plugin_dir/README.md"
    # __PLUGIN_ATTR__

    TODO: one-paragraph summary of what this plugin does.

    ## Build

    ```
    cd plugins/__KIND__/__NAME__
    nix develop
    nix run .#test
    ```

    ## Status

    Scaffolded by `nix run .#new-plugin`. Replace the TODOs in
    `__NAME__.cpp`, the test cases in `tests/test___NAME__.cpp`,
    the description in `default.nix`, and the placeholder
    `LICENSE` before merging into the plugin set.
    README

    cat <<'LICENSE' | subst > "$plugin_dir/LICENSE"
    TODO: pick a license per the project's strategic / periphery
    split convention. The plugin will not install successfully
    through add_plugin()'s LICENSE install rule until this file
    contains a real license text.
    LICENSE

    # The shell heredocs above were indented by four spaces so the
    # surrounding Nix `text = '''…'''` indented-string strips a
    # consistent prefix. Strip the same four-space prefix from
    # every emitted file before declaring success.
    for f in \
      "$plugin_dir/CMakeLists.txt" \
      "$plugin_dir/default.nix" \
      "$plugin_dir/flake.nix" \
      "$plugin_dir/$name.cpp" \
      "$plugin_dir/tests/CMakeLists.txt" \
      "$plugin_dir/tests/test_$name.cpp" \
      "$plugin_dir/README.md" \
      "$plugin_dir/LICENSE"
    do
      sed -i 's/^    //' "$f"
    done

    cat <<DONE
    Created $plugin_dir with:
      CMakeLists.txt    — standalone branch wired to GoodNetTesting helpers
      default.nix       — kernel-side derivation
      flake.nix         — standalone dev / test / build flake
      $name.cpp           — plugin entry skeleton
      tests/CMakeLists.txt
      tests/test_$name.cpp — placeholder passing test
      README.md
      LICENSE           — placeholder, pick a real license

    Next:
      cd $plugin_dir
      nix develop
      nix run .#test       (placeholder test passes immediately)
      Replace the TODOs in the listed files.
      Pick a real license; the build will fail at install time
        until LICENSE contains real text.
    DONE
  '';
}
