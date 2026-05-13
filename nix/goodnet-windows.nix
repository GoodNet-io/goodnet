# Windows MVP cross-build via `pkgs.pkgsCross.mingwW64`. Produces a
# static-plugin single-`goodnet.exe` that bundles kernel + gnet
# protocol + lean plugin set (TCP + UDP + Noise + Null + heartbeat).
# OpenSSL-requiring plugins (TLS, QUIC, WS) and POSIX-leaning
# (handler-store, handler-dns, ICE, IPC) stay out of the bundle for
# the first cut — `plugins/CMakeLists.txt` skips them under
# `WIN32`.
#
# This derivation is consumed from the parent flake's
# `packages.<linux-system>.goodnet-windows` slot — it stays
# Linux-host-only because mingw cross is a host-cross-target shape:
# pkgsCross runs on Linux and emits a Windows PE.
{ pkgs, ... }:

let
  cross = pkgs.pkgsCross.mingwW64;

  # `nixpkgs` declares `asio.meta.platforms` as `unix` only — but
  # asio is header-only (its build only ships POSIX-flavoured
  # `examples/`, none of which we consume), so for mingw we strip
  # the example build entirely and just install the headers. The
  # kernel's CMake hits `ASIO_STANDALONE` via `target_compile_
  # definitions(asio::asio INTERFACE ASIO_STANDALONE)` (root
  # CMakeLists.txt), so only the include path matters.
  asio-win = (cross.asio.overrideAttrs (old: {
    # Skip the upstream Makefile's POSIX-only `examples/`. The
    # package treats those as part of the `all` target; mingw
    # cross-builds trip on `posix::stream_descriptor` references.
    buildPhase   = "true";
    installPhase = ''
      runHook preInstall
      mkdir -p $out/include $out/lib/pkgconfig
      # nixpkgs asio sets `sourceRoot = "source/asio"` so the build
      # cwd is the `asio/` subdir of the unpacked tree; include
      # tree is reachable as `include/`.
      cp -r include/asio.hpp include/asio $out/include/
      cat > $out/lib/pkgconfig/asio.pc <<EOF
      prefix=$out
      exec_prefix=$out
      libdir=$out/lib
      includedir=$out/include

      Name: asio
      Description: asio header-only library (mingw cross subset)
      Version: ${old.version}
      Cflags: -I$out/include
      EOF
      runHook postInstall
    '';
  })).overrideAttrs (old: {
    meta = old.meta // {
      platforms = old.meta.platforms ++ pkgs.lib.platforms.windows;
    };
  });
in
cross.stdenv.mkDerivation {
  pname   = "goodnet-windows";
  version = "1.0.0-rc3";

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
  # they target the mingw triple through the cross stdenv's toolchain.
  nativeBuildInputs = with pkgs; [ cmake ninja pkg-config ];

  # Cross-built mingw libraries. Asio standalone is header-only so
  # the regular nixpkgs `asio` works through the cross stdenv. The
  # mingw stub of libsodium / spdlog / fmt / nlohmann_json /
  # pthreads is what gets linked into goodnet.exe.
  buildInputs =
    let
      # spdlog / fmt / libsodium are forced to static-only — the
      # Windows MVP ships a single `goodnet.exe` with no
      # neighbouring DLLs. Each upstream nixpkgs recipe exposes a
      # native knob:
      #   * fmt: `enableShared` (default true, flip false).
      #   * spdlog: `staticBuild` (default false, flip true).
      #   * libsodium: no parameter — re-run configure with
      #     `--disable-shared`.
      # spdlog `propagatedBuildInputs = [ fmt ]` — without rerouting
      # spdlog's fmt to OUR static fmt, the propagated default
      # leaks back as a shared-linkage candidate at the goodnet
      # link step. Hence the explicit `spdlog.override { fmt =
      # fmt-static; }` below.
      fmt-static = (cross.fmt.override { enableShared = false; }).overrideAttrs (old: {
        cmakeFlags = (old.cmakeFlags or []) ++ [
          "-DFMT_TEST=OFF"
          "-DFMT_DOC=OFF"
        ];
        doCheck = false;
      });
      spdlog-static = (cross.spdlog.override {
        staticBuild = true;
        fmt = fmt-static;
      }).overrideAttrs (old: {
        cmakeFlags = (old.cmakeFlags or []) ++ [
          "-DSPDLOG_BUILD_TESTS=OFF"
          "-DSPDLOG_BUILD_EXAMPLE=OFF"
        ];
        doCheck = false;
      });
      sodium-static = cross.libsodium.overrideAttrs (old: {
        configureFlags = (old.configureFlags or []) ++ [
          "--disable-shared"
          "--enable-static"
        ];
      });
    in
    [
      asio-win
      fmt-static
      spdlog-static
      sodium-static
    ] ++ (with cross; [
      nlohmann_json
      # `windows.pthreads` provides libwinpthread; mingw's gcc
      # `-static -static-libgcc -static-libstdc++` switches its
      # libstdc++ / libgcc / libwinpthread links to static archives
      # the toolchain ships alongside the dlls.
      windows.pthreads
    ]);

  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=Release"
    "-DGOODNET_BUILD_TESTS=OFF"
    "-DGOODNET_BUILD_BUNDLED_PLUGINS=ON"
    "-DGOODNET_STATIC_PLUGINS=ON"
    "-DGOODNET_BUILD_APPS=ON"
    # mold/LTO under mingw cross-toolchain is unstable today;
    # request ld and let the cross-stdenv toolchain pick its default
    # linker (mingw-w64 ships ld.bfd).
    "-DGOODNET_USE_MOLD=OFF"
    "-DGOODNET_USE_LTO=OFF"
    "-DGOODNET_USE_PCH=OFF"
  ];

  doCheck = false;

  # The static-plugin binary is just `bin/goodnet.exe`. With
  # `-static -static-libgcc -static-libstdc++` (set in apps/goodnet/
  # CMakeLists.txt under WIN32) plus `--disable-shared` rebuilds of
  # spdlog / fmt / libsodium in `buildInputs` above, the result is
  # a single self-contained executable — no neighbouring DLLs are
  # required at run-time. `dontPatchELF = true` skips the
  # nix-mingw fixup that would copy in the dynamic mingw runtime
  # DLLs that we just compiled away from.
  dontPatchELF = true;

  meta = {
    description = "GoodNet kernel cross-built for Windows x86_64 (mingw-w64).";
    # `meta.platforms` is checked against `hostPlatform` (the target),
    # not the build host. The flake gates this attribute under
    # `isLinux` so it only appears for Linux build hosts; once visible
    # the derivation produces a Windows PE, so the runtime platforms
    # are `pkgs.lib.platforms.windows`.
    platforms = pkgs.lib.platforms.windows;
  };
}
