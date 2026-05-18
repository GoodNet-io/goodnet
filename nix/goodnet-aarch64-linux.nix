# Linux aarch64 cross-build via `pkgs.pkgsCross.aarch64-multiplatform`.
# Mirrors `nix/goodnet-windows.nix`: a host-cross-target shape that
# runs on an x86_64 Linux build host and emits ELF ARM64 binaries.
# Unlike the mingw cross we keep every plugin that compiles on Linux
# (TLS / WS / QUIC / ICE / handler-store / handler-dns / strategies)
# — the host kernel ABI is the same, just a different ISA, so the
# `WIN32` skips in `plugins/CMakeLists.txt` don't apply.
#
# Consumed from the parent flake's
# `packages.x86_64-linux.goodnet-aarch64-linux` slot. Linux-host-only
# because `pkgsCross.aarch64-multiplatform` is a Linux-only cross
# stdenv inside nixpkgs; native ARM Linux hosts use the regular
# `packages.aarch64-linux.goodnet-core` entry instead. This derivation
# exists as a compile + link smoke gate for the cross matrix on
# x86_64 CI — there is no native aarch64 runner in the test gate yet.

{ pkgs, ... }:

let
  cross = pkgs.pkgsCross.aarch64-multiplatform;
in
cross.gcc15Stdenv.mkDerivation {
  pname   = "goodnet-aarch64-linux";
  version = "1.0.0-rc3";

  src = pkgs.lib.cleanSourceWith {
    src    = ./..;
    filter = path: type:
      let b = builtins.baseNameOf path; in
      !(b == "build" || b == "result" || b == ".direnv"
        || b == "build-release" || b == "build-static"
        || b == "build-asan"    || b == "build-tsan"
        || b == "build-demo"    || b == "build-static-lto");
  };

  # `cmake` + `ninja` + `pkg-config` come from the build host (x86_64
  # Linux); they target the aarch64-linux triple through the cross
  # stdenv's toolchain. Same shape as the mingw cross.
  nativeBuildInputs = with pkgs; [ cmake ninja pkg-config ];

  # All `buildInputs` are routed through `cross.*` so pkg-config + the
  # cross-stdenv's compiler wrapper resolve the aarch64-linux variants
  # (libraries + headers from `lib/aarch64-unknown-linux-gnu/`).
  # OpenSSL / libsodium / spdlog / fmt / nlohmann_json / asio /
  # sqlite / c-ares are the same set the x86_64 kernel + bundled
  # plugins consume — TLS / WS / QUIC / ICE link OpenSSL, handler-
  # store links sqlite, handler-dns links c-ares.
  buildInputs = with cross; [
    asio
    spdlog
    fmt
    nlohmann_json
    libsodium
    openssl
    sqlite
    c-ares
  ];

  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=Release"
    # Tests / bench need gtest + rapidcheck + google-benchmark cross-
    # built; skip them for the smoke gate — the goal of this
    # derivation is to confirm kernel + plugins compile + link under
    # the aarch64 cross stdenv, not to execute test binaries (there
    # is no native aarch64 runner in CI).
    "-DGOODNET_BUILD_TESTS=OFF"
    "-DGOODNET_BUILD_BUNDLED_PLUGINS=ON"
    # Default plugin shape: `.so` per plugin, loaded at runtime.
    # The kernel binary stays modular, same as the x86_64 path.
    "-DGOODNET_STATIC_PLUGINS=OFF"
    "-DGOODNET_BUILD_APPS=ON"
    # mold + LTO are not part of the cross toolchain by default; let
    # the cross stdenv's `ld.bfd` handle the link line. Skipping PCH
    # avoids a transitive cross-header probe that nixpkgs' precompile
    # step misroutes through the host gcc on some versions.
    "-DGOODNET_USE_MOLD=OFF"
    "-DGOODNET_USE_LTO=OFF"
    "-DGOODNET_USE_PCH=OFF"
  ];

  doCheck = false;

  meta = {
    description = "GoodNet kernel cross-built for Linux aarch64.";
    # `meta.platforms` is checked against `hostPlatform` (the target).
    # The flake gates this derivation under the x86_64-linux build
    # host so the cross only appears where pkgsCross is usable; the
    # produced binary's runtime platform is aarch64 Linux.
    platforms = [ "aarch64-linux" ];
  };
}
