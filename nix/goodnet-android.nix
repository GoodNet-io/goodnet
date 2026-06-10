# Android (aarch64 / arm64-v8a) cross-build via
# `pkgsCross.aarch64-android-prebuilt`. The "prebuilt" track is the
# Google-published NDK toolchain wrapper that nixpkgs surfaces — no
# source-clang rebuild, no SDK-license dance beyond
# `allowUnfree = true`. The build host stays Linux x86_64 / aarch64;
# the emitted artefact is a bionic-libc aarch64 ELF that runs inside
# the Android sandbox (API level matches whatever the prebuilt
# tracks; 27 ships against API 24+, see nixpkgs
# `pkgs/development/mobile/androidenv/`).
#
# **Scope** — kernel-only smoke. The first cut keeps
# `GOODNET_BUILD_BUNDLED_PLUGINS=OFF` so the `add_subdirectory
# (plugins/...)` walk never fires; the loadable-plugin trees under
# `plugins/<kind>/<name>/` carry their own ICE / QUIC / TLS link
# graph (OpenSSL, c-ares) that the kernel CI gate doesn't need to
# spell out. The composed Android bundle (kernel + static plugins
# + JNI glue) is a follow-up cut tracked in `docs/ROADMAP.en.md`.
# Today the gate proves the kernel's C++23 surface compiles + links
# against bionic — that's the regression net the cross-build CI job
# protects on every push to main.
#
# **Excluded from this derivation** (the noise gap the task brief
# called out):
#
#   * The full bundled-plugins walk (TLS, QUIC, WS, ICE, handler-
#     store, handler-dns, security-noise, etc.). Each loadable
#     plugin lives in its own git and will get its own android
#     derivation when the Android-side composed node spec lands.
#     `GOODNET_BUILD_BUNDLED_PLUGINS=OFF` short-circuits the walk.
#   * Operator-facing apps (`apps/`). `GOODNET_BUILD_APPS=OFF`
#     keeps the smoke build kernel-only.
#   * Tests + bench + fuzz + examples. Same `*=OFF` switches.
#   * Hot-reload / inotify probes — kernel uses dlopen which works
#     on bionic; no io_uring / inotify in the kernel sources today.
#
# **Bionic incompatibilities of note** — the existing
# `#if defined(__linux__)` guards in `core/plugin/remote_host.cpp`
# (prctl) and `core/plugin/runtimes/dynamic.cpp` (`/proc/self/fd/N`
# dlopen + openat2 fallback) all take the Linux branch on Android
# because bionic defines `__linux__`. `PR_SET_DUMPABLE` and
# `PR_SET_NO_NEW_PRIVS` are present on bionic. openat2 is gated
# behind `__has_include(<linux/openat2.h>)` which is absent on
# bionic — the gate falls through to the `O_NOFOLLOW` open path
# automatically. No source-level Android ifdefs needed for this
# cut; the existing `__linux__` envelope is correct.
{ pkgs, version ? "dev", ... }:

let
  # The Android NDK is published under Google's terms — nixpkgs marks
  # it `meta.license.unfree = true`. The kernel build doesn't carry
  # an NDK redistribution: the wrapper toolchain only runs at build
  # time on the developer's box / CI runner, the emitted aarch64 ELF
  # has no NDK contents linked in. Reimport nixpkgs with the unfree
  # toggle so the toolchain wrapper evaluates; the rest of the
  # closure (openssl / spdlog / fmt / libsodium / nlohmann_json /
  # asio cross-built for aarch64-android) inherits the same import.
  pkgsAndroid = import pkgs.path {
    inherit (pkgs.stdenv.hostPlatform) system;
    config = {
      allowUnfree = true;
      android_sdk.accept_license = true;
    };
  };

  cross = pkgsAndroid.pkgsCross.aarch64-android-prebuilt;

  # `nixpkgs` declares `asio.meta.platforms` as `unix` only. Android
  # is `unix` per nixpkgs' platform tag set, so the upstream recipe
  # accepts the cross — but asio's bundled `examples/` build trips
  # the same way it trips under mingw (POSIX-only constructs the
  # cross-stdenv doesn't ship). The kernel only needs the header
  # tree (`ASIO_STANDALONE` is set in the root `CMakeLists.txt`),
  # so strip the example build and install just `include/`.
  asio-android = (cross.asio.overrideAttrs (old: {
    buildPhase   = "true";
    installPhase = ''
      runHook preInstall
      mkdir -p $out/include $out/lib/pkgconfig
      cp -r include/asio.hpp include/asio $out/include/
      cat > $out/lib/pkgconfig/asio.pc <<EOF
      prefix=$out
      exec_prefix=$out
      libdir=$out/lib
      includedir=$out/include

      Name: asio
      Description: asio header-only library (aarch64-android cross subset)
      Version: ${old.version}
      Cflags: -I$out/include
      EOF
      runHook postInstall
    '';
  }));
in
cross.stdenv.mkDerivation {
  pname   = "goodnet-android-aarch64";
  inherit version;

  src = pkgs.lib.cleanSourceWith {
    src    = ./..;
    filter = path: type:
      let b = builtins.baseNameOf path; in
      !(b == "build" || b == "result" || b == ".direnv"
        || b == "build-release" || b == "build-static"
        || b == "build-asan"    || b == "build-tsan"
        || b == "build-demo");
  };

  # `cmake` + `ninja` + `pkg-config` come from the build host (Linux);
  # they target the aarch64-android triple through the cross stdenv's
  # toolchain wrapper. `pkgsAndroid` is reused so cmake's host
  # binaries match the same nixpkgs revision as the target libraries.
  nativeBuildInputs = with pkgsAndroid; [ cmake ninja pkg-config ];

  # Cross-built bionic libraries. libsodium IS available on bionic
  # through nixpkgs' `pkgsCross.aarch64-android-prebuilt` track, so
  # the kernel's compile-time `find_package(libsodium)` lands cleanly;
  # the security-noise plugin would build too if it were in scope.
  # OpenSSL 3.6+ is the prebuilt version, satisfying QUIC's API
  # requirement when that plugin lifts into the android bundle.
  buildInputs = [
    asio-android
    (import ./stdexec.nix { pkgs = cross; })
  ] ++ (with cross; [
    spdlog
    fmt
    nlohmann_json
    libsodium
    openssl
  ]);

  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=Release"
    # Kernel-only smoke. Tests / examples / fuzz / apps all stay off.
    "-DGOODNET_BUILD_TESTS=OFF"
    "-DGOODNET_BUILD_EXAMPLES=OFF"
    "-DGOODNET_BUILD_FUZZ=OFF"
    "-DGOODNET_BUILD_BENCH=OFF"
    "-DGOODNET_BUILD_APPS=OFF"
    # Loadable plugins under `plugins/<kind>/<name>/` stay out of the
    # first android cut — each ships its own android derivation when
    # the composed-bundle slot lands. `OFF` short-circuits the
    # `add_subdirectory(plugins)` walk so the kernel build doesn't
    # need every plugin's third-party graph resolved against the
    # android cross-stdenv.
    "-DGOODNET_BUILD_BUNDLED_PLUGINS=OFF"
    # mold / LTO under the NDK toolchain wrapper aren't reliable
    # today; the wrapper substitutes its own lld and lto plugin
    # paths and a host-side `-fuse-ld=mold` injection collides with
    # both. Stick to the toolchain default linker for the smoke
    # cut. PCH is off because the bionic libstdc++ headers' include
    # graph differs from the host's glibc tree and the precompiled
    # umbrella becomes a re-parse loss anyway.
    "-DGOODNET_USE_MOLD=OFF"
    "-DGOODNET_USE_LTO=OFF"
    "-DGOODNET_USE_PCH=OFF"
    # NDK does not support c++26 yet
    "-DCMAKE_CXX_STANDARD=23"
  ];

  doCheck = false;

  # The android NDK emits ELF without the standard
  # PT_INTERP/DT_NEEDED layout nixpkgs' patchELF fixup hook expects
  # (the NDK wraps libc / libdl into the runtime linker `linker64`
  # which lives at a fixed path on every android device). Skip the
  # fixup so the build doesn't trip on `patchelf --set-interpreter`
  # against a non-standard ELF.
  dontPatchELF = true;

  # Diagnostic surface for callers downstream (CI, ROADMAP livedoc
  # extractor) — the android cut documents what isn't in scope so a
  # follow-up cut knows what to lift next.
  passthru = {
    excluded-plugins = [
      "links/tcp" "links/udp" "links/ipc" "links/tls" "links/ws"
      "links/ice" "links/quic" "links/portmap" "links/raw_inject"
      "handlers/heartbeat" "handlers/store" "handlers/dns"
      "security/null" "security/noise"
      "strategies/float_send_rtt"
      "workers"
    ];
    # If the NDK toolchain itself becomes intractable on a future
    # nixpkgs bump, fill `skip_reason` with a one-line summary and
    # the CI job skips the build step rather than blocking the gate.
    # Empty means the build is expected to succeed.
    skip_reason = "";
  };

  meta = {
    description = "GoodNet kernel cross-built for Android aarch64 (bionic, NDK prebuilt).";
    # `meta.platforms` matches the host (target) platform per nixpkgs
    # convention. nixpkgs doesn't carry a dedicated `lib.platforms
    # .android` tag — the prebuilt NDK cross sets `hostPlatform.
    # isAndroid` instead. Bionic defines `__linux__`, so the kernel
    # build's compile-time guards take the linux branch, and the
    # `linux` platform tag is the closest match nixpkgs offers for
    # the meta.platforms check. The parent flake gates this attribute
    # under `isLinux` so it only appears for Linux build hosts.
    platforms = pkgs.lib.platforms.linux;
    license   = pkgs.lib.licenses.mit;
  };
}
