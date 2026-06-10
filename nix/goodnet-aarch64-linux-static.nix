# Linux aarch64 truly-static cross-build via
# `pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic`. Same shape as
# `nix/goodnet-static.nix` (musl + static archives, no runtime
# closure outside the binary's interpreter) but targeting the
# aarch64 ISA so the result drops into an aarch64 `scratch`
# container, chroot, or embedded rootfs unchanged.
#
# Companion to `nix/goodnet-aarch64-linux.nix` (the dynamic cross
# cut). Stays Linux-host-only because pkgsCross runs on Linux. Bundle
# is the kernel + the `_goodnet_static_plugin_list` allowlist
# (TCP / UDP / IPC / Noise / Null / heartbeat) — sqlite + c-ares
# plugins stay out of the static cut for the same reason as the
# x86_64 static build (no static `.a` archives for c-ares /
# sqlite3 under the musl cross).

{ pkgs, ... }:

let
  # `pkgsCross.aarch64-multiplatform.pkgsStatic` is the aarch64 musl
  # static cross. `cross.gcc15Stdenv` then routes the link line
  # through the musl-aarch64 toolchain with static archives.
  static = pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic;

  # Mirror `nix/goodnet-static.nix`: force fmt / spdlog / sodium to
  # static-only so the executable's link picks the `.a` archive
  # unambiguously. pkgsStatic defaults to static for most libs, but
  # spdlog / fmt still emit a `.so` under the cross unless
  # `enableShared = false` is explicit.
  fmt-static = (static.fmt.override { enableShared = false; }).overrideAttrs (old: {
    cmakeFlags = (old.cmakeFlags or []) ++ [
      "-DFMT_TEST=OFF"
      "-DFMT_DOC=OFF"
    ];
    doCheck = false;
  });

  spdlog-static = (static.spdlog.override {
    staticBuild = true;
    fmt = fmt-static;
  }).overrideAttrs (old: {
    cmakeFlags = (old.cmakeFlags or []) ++ [
      "-DSPDLOG_BUILD_TESTS=OFF"
      "-DSPDLOG_BUILD_EXAMPLE=OFF"
    ];
    doCheck = false;
  });

  sodium-static = static.libsodium.overrideAttrs (old: {
    configureFlags = (old.configureFlags or []) ++ [
      "--disable-shared"
      "--enable-static"
    ];
  });
in
static.gcc15Stdenv.mkDerivation {
  pname   = "goodnet-aarch64-linux-static";
  version = "1.0.0-rc6";

  src = pkgs.lib.cleanSourceWith {
    src    = ./..;
    filter = path: type:
      let b = builtins.baseNameOf path; in
      !(b == "build"             || b == "result"
        || b == ".direnv"        || b == "build-release"
        || b == "build-static"   || b == "build-asan"
        || b == "build-tsan"     || b == "build-demo"
        || b == "build-static-lto");
  };

  nativeBuildInputs = with pkgs; [ cmake ninja pkg-config ];

  buildInputs = [
    fmt-static
    spdlog-static
    sodium-static
    (import ./stdexec.nix { pkgs = static; })
  ] ++ (with static; [
    asio
    nlohmann_json
    openssl
  ]);

  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=Release"
    "-DGOODNET_BUILD_TESTS=OFF"
    "-DGOODNET_BUILD_BUNDLED_PLUGINS=ON"
    "-DGOODNET_STATIC_PLUGINS=ON"
    "-DGOODNET_BUILD_APPS=ON"
    # `_goodnet_static_plugin_list` already excludes handler-store
    # (sqlite) and handler-dns (c-ares) from the static-plugin
    # allowlist; the plugin-side toggles below mirror that so
    # `add_subdirectory(plugins/...)` does not try to resolve the
    # missing `sqlite3.pc` / `libcares.pc` under the musl static
    # cross.
    "-DGOODNET_STORE_WITH_SQLITE=OFF"
    "-DGOODNET_DNS_WITH_UPSTREAM=OFF"
    "-DGOODNET_USE_MOLD=OFF"
    "-DGOODNET_USE_LTO=OFF"
    "-DGOODNET_USE_PCH=OFF"
  ];

  # End-to-end `-static` to ensure the executable's own link picks
  # the static archives — same rationale as `nix/goodnet-static.nix`.
  NIX_LDFLAGS_AFTER = "-static";
  CXXFLAGS = "-static-libgcc -static-libstdc++";

  dontPatchELF = true;
  doCheck = false;

  postInstall = ''
    mkdir -p $out/bin
    for w in remote_echo remote_noise_stub remote_handler_stub remote_slow_stub; do
      if [ -x "workers/$w" ]; then
        install -m 0755 "workers/$w" "$out/bin/$w"
      fi
    done
  '';

  meta = {
    description =
      "GoodNet kernel + bundled plugins — truly static musl aarch64 build.";
    mainProgram  = "goodnet";
    platforms    = [ "aarch64-linux" ];
    license      = pkgs.lib.licenses.mit;
  };
}
