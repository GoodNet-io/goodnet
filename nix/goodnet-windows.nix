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
  buildInputs = with cross; [
    asio
    spdlog
    fmt
    nlohmann_json
    libsodium
    windows.pthreads
  ];

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

  # The static-plugin binary is just `bin/goodnet.exe`. Cross-stdenv's
  # default `installPhase` already runs `cmake --install`, which the
  # apps/ CMakeLists wires to `install(TARGETS goodnet RUNTIME ...)`.
  # We just need to drop in any mingw runtime DLLs the .exe needs at
  # runtime (libstdc++-6.dll, libgcc_s_seh-1.dll, libwinpthread-1.dll
  # — all in `cross.stdenv.cc.cc.lib`).
  postInstall = ''
    mkdir -p $out/bin
    for dll in \
      ${cross.stdenv.cc.cc.lib}/${cross.stdenv.hostPlatform.config}/lib/libstdc++-6.dll \
      ${cross.stdenv.cc.cc.lib}/${cross.stdenv.hostPlatform.config}/lib/libgcc_s_seh-1.dll \
      ${cross.windows.pthreads}/bin/libwinpthread-1.dll; do
      [ -f "$dll" ] && cp "$dll" $out/bin/ || true
    done
  '';

  meta = {
    description = "GoodNet kernel cross-built for Windows x86_64 (mingw-w64).";
    platforms   = pkgs.lib.platforms.linux;
  };
}
