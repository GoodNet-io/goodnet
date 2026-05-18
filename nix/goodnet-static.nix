# Truly-static kernel build via `pkgsStatic`. Produces a
# self-contained `goodnet` binary whose only run-time dependency is
# the kernel's own `ld-linux-musl-*.so.1` interpreter — no shared
# OpenSSL, libsodium, spdlog, fmt, libstdc++, libgcc_s, or libc on
# the runtime side. The bundled plugin set (TCP, UDP, IPC, Noise,
# Null, heartbeat, etc.) is linked into the kernel binary via
# `-DGOODNET_STATIC_PLUGINS=ON`, so there are no neighbouring `.so`
# plugin files either.
#
# This is the canonical artefact behind `nix run .#build -- static`:
# the `gn-build` wrapper script routes that variant through
# `nix build .#goodnet-core-static`, copies the binary to the
# operator's `build-static/bin/` for parity with the other variants,
# and the result is a single ELF that runs unchanged inside a
# `scratch` or `distroless` container, in a chroot, or on a stripped
# embedded rootfs.
#
# Plugin slots that need POSIX-only or `dlopen`-leaning subsystems
# (handler-store/sqlite, handler-dns/c-ares, ICE-with-libp2p tools,
# QUIC-via-OpenSSL>=3.6) are kept out of the static bundle for the
# first cut. They are gated behind plugin-side options
# (`GOODNET_STORE_WITH_SQLITE=OFF`,
# `GOODNET_DNS_WITH_UPSTREAM=OFF`) or behind the kernel's own
# `_goodnet_static_plugin_list` allowlist in the root
# `CMakeLists.txt`; building under pkgsStatic activates those gates
# so a missing static sqlite / c-ares does not block the build.

{ pkgs, ... }:

let
  static = pkgs.pkgsStatic;

  # spdlog, fmt, libsodium, openssl rebuilt with `enableShared = false`
  # so their `.so` is absent and the kernel's executable link picks the
  # `.a` archive unambiguously. pkgsStatic already defaults to static
  # for most libraries, but spdlog/fmt's nixpkgs recipe still emits a
  # `.so` under the static cross unless `enableShared = false` is
  # passed explicitly.
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

  # libsodium under pkgsStatic already disables shared by default
  # through the cross stdenv. The explicit override below keeps the
  # configure flags loud so a future nixpkgs revision that flips the
  # default back to shared does not silently bring a `.so` back.
  sodium-static = static.libsodium.overrideAttrs (old: {
    configureFlags = (old.configureFlags or []) ++ [
      "--disable-shared"
      "--enable-static"
    ];
  });
in
static.gcc15Stdenv.mkDerivation {
  pname   = "goodnet-core-static";
  version = "1.0.0-rc4";

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
    # The kernel-side `_goodnet_static_plugin_list` allowlist in the
    # root CMakeLists.txt already excludes handler-store (sqlite) and
    # handler-dns (c-ares); flip the plugin-side options off as well
    # so the `add_subdirectory(plugins/...)` walk under
    # `GOODNET_BUILD_BUNDLED_PLUGINS=ON` does not try to resolve
    # `sqlite3.pc` or `libcares.pc` under pkgsStatic.
    "-DGOODNET_STORE_WITH_SQLITE=OFF"
    "-DGOODNET_DNS_WITH_UPSTREAM=OFF"
    # mold + LTO are not portable under the musl static cross today;
    # let the default ld pick a `ld.bfd` that knows how to resolve
    # `-static` link lines containing `crtbeginT.o` + `crtend.o`.
    "-DGOODNET_USE_MOLD=OFF"
    "-DGOODNET_USE_LTO=OFF"
    "-DGOODNET_USE_PCH=OFF"
  ];

  # Force `-static` end-to-end so the resulting `bin/goodnet` is a
  # truly static ELF. pkgsStatic ships static-only archives for our
  # `buildInputs`, but the executable's own link step still defaults
  # to dynamic when `-static` is absent from `LDFLAGS`. Adding the
  # flag here closes the gap; `-static-libgcc -static-libstdc++` are
  # implied by `-static` but stated for clarity and to silence the
  # warning gcc otherwise prints about implicit dynamic libgcc.
  NIX_LDFLAGS_AFTER = "-static";

  # `pkgsStatic.gcc15Stdenv` already wires `-static` through its
  # compiler wrapper for libraries it produces, but the kernel's
  # final executable link still needs the flag on its own command
  # line. `CFLAGS` / `CXXFLAGS` are picked up by CMake's
  # `add_executable` link step (it forwards both compile and link
  # phases through the C++ driver).
  CXXFLAGS = "-static-libgcc -static-libstdc++";

  # Skip nixpkgs' default ELF-fixup pass — patchelf complains about
  # static binaries because they carry no interpreter / DT_NEEDED
  # entries to rewrite. Stripping is fine; `pkgsStatic` already
  # invokes `strip --strip-unneeded` through its build hooks.
  dontPatchELF = true;

  doCheck = false;

  # The operator-facing `goodnetd` daemon now ships from a separate
  # repo (`github.com/GoodNet-io/goodnetd`), so this derivation's
  # `apps/` subtree is empty and the install phase ships only the
  # static archive + plugin object library + worker subprocesses.
  # Copy the `remote_echo` worker into `bin/` so the smoke test
  # (`ldd $out/bin/remote_echo` / `file $out/bin/remote_echo`) has
  # a real ELF to inspect — every other artefact is a `.a` archive
  # and `ldd` would refuse those outright. The worker links the
  # same kernel object library + libsodium + OpenSSL + spdlog the
  # daemon does, so its dynamic-section closure is a faithful
  # proxy for "did pkgsStatic catch every system library".
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
      "GoodNet kernel + bundled plugins — truly static musl build.";
    mainProgram  = "goodnet";
    platforms    = pkgs.lib.platforms.linux;
    license      = pkgs.lib.licenses.mit;
  };
}
