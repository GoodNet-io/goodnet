# Sanitizer test wrappers. Two writeShellScriptBin wrappers configure a
# separate build directory under the requested sanitizer, build the
# kernel + plugins, and run ctest. Wired into `flake.nix` apps so CI
# invokes them through `nix run .#test-asan` / `nix run .#test-tsan`.
#
# Nix's gcc wrapper hardening (`-fstack-protector-strong`,
# `-D_FORTIFY_SOURCE=2`) conflicts with sanitizer instrumentation —
# unset `NIX_HARDENING_ENABLE` so the wrapper does not prepend the
# hardening prologue.
{ pkgs }:

let
  mkSanitizerApp = { name, flags, runtimeEnv ? "" }:
    pkgs.writeShellScriptBin "gn-test-${name}" ''
      set -euo pipefail
      exec ${pkgs.nix}/bin/nix develop "''${FLAKE_DIR:-.}" --command bash -c '
        set -euo pipefail
        BUILD_DIR="build-${name}"
        export NIX_HARDENING_ENABLE=""
        export CFLAGS="${flags} -O1 -g -fno-omit-frame-pointer"
        export CXXFLAGS="${flags} -O1 -g -fno-omit-frame-pointer"
        export LDFLAGS="${flags}"
        ${runtimeEnv}
        if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
          echo ">>> Configuring ${name} sanitizer build..."
          cmake -B "$BUILD_DIR" -G Ninja \
                -DCMAKE_BUILD_TYPE=Debug \
                -DBUILD_TESTING=ON
        fi
        cmake --build "$BUILD_DIR" -j"$(nproc)"
        export LD_LIBRARY_PATH="$BUILD_DIR:$BUILD_DIR/plugins''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        ctest --test-dir "$BUILD_DIR" --output-on-failure "$@"
      ' _ "$@"
    '';
in
{
  test-asan = mkSanitizerApp {
    name = "asan";
    flags = "-fsanitize=address,undefined -fno-sanitize-recover=all";
    runtimeEnv = ''
      export ASAN_OPTIONS="abort_on_error=1:detect_leaks=1:halt_on_error=1:symbolize=1:strict_string_checks=1"
      export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
    '';
  };

  test-tsan = mkSanitizerApp {
    name = "tsan";
    flags = "-fsanitize=thread";
    runtimeEnv = ''
      export TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1:history_size=4"
    '';
  };
}
