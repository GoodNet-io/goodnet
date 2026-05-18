## Darwin cross-build via `pkgs.pkgsCross.{x86_64,aarch64}-darwin`.
## Produces a kernel-only `goodnet_kernel` archive + SDK headers for
## the requested Apple target from a Linux build host. The Asio
## reactor rides on `kqueue` portably; the kernel itself carries
## `__linux__` guards around prctl/PR_SET_*/closefrom/openat2/proc-fd
## paths (see `core/plugin/remote_host.cpp`, `core/plugin/runtimes/
## dynamic.cpp`), so under `__APPLE__` the kernel parses and links
## but degrades to the portable `O_NOFOLLOW` integrity path.
##
## Apple SDK caveat — nixpkgs cannot legally redistribute Apple's
## SDK; `pkgsCross.*-darwin.stdenv` therefore expects the operator to
## stage `apple-sdk_*` through `requireFile` (Xcode license).
## In a pure-Nix cross from Linux without that staging the link step
## raises `SDK not found` or `xcrun: not installed`. This derivation
## still tries the full configure + build: the `passthru.skip_reason`
## attribute is what CI reads to short-circuit gracefully. The build
## intentionally does NOT depend on Apple-licensed binaries (no
## CocoaPods / Xcode / Swift). Bundled plugins are gated off — the
## per-plugin flakes own their own darwin port story per
## `docs/architecture/cross-platform.ru.md`.
##
## Linux-host-only: cross-from-Linux runs on Linux and emits Mach-O.
## Native Darwin operators just use `nix build .#packages.aarch64-
## darwin.goodnet-core` against the regular non-cross attr set.
{ pkgs, arch ? "x86_64", ... }:

let
  cross =
    if arch == "aarch64" then pkgs.pkgsCross.aarch64-darwin
    else if arch == "x86_64" then pkgs.pkgsCross.x86_64-darwin
    else throw "goodnet-darwin: unknown arch '${arch}' (x86_64|aarch64)";

  ## `nixpkgs` declares `asio.meta.platforms` as `unix`; macOS is in
  ## that set so the regular cross.asio resolves without the platform
  ## overlay needed for mingw. Asio is header-only — `ASIO_STANDALONE`
  ## kills the boost-system dep; the kqueue reactor compiles under
  ## the same `<asio.hpp>` umbrella as the epoll path.
  asio-darwin = cross.asio;
in
cross.stdenv.mkDerivation {
  pname   = "goodnet-darwin-${arch}";
  version = "1.0.0-rc4";

  src = pkgs.lib.cleanSourceWith {
    src    = ./..;
    filter = path: type:
      let b = builtins.baseNameOf path; in
      !(b == "build" || b == "result" || b == ".direnv"
        || b == "build-release" || b == "build-static"
        || b == "build-asan"    || b == "build-tsan"
        || b == "build-demo"    || b == "build-coverage");
  };

  nativeBuildInputs = with pkgs; [ cmake ninja pkg-config ];

  ## Header-only / portable deps. spdlog + fmt + libsodium +
  ## nlohmann_json compile clean under the Apple cross stdenv when
  ## the SDK is staged. Without it, the cross.stdenv setup itself
  ## fails earlier than this derivation — see `passthru.skip_reason`.
  buildInputs = [
    asio-darwin
  ] ++ (with cross; [
    spdlog
    fmt
    libsodium
    nlohmann_json
  ]);

  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=Release"
    "-DGOODNET_BUILD_TESTS=OFF"
    ## Kernel-only first cut — plugins each own their own darwin
    ## port story. Per-plugin flakes will flip their `meta.platforms`
    ## once they're ported; the kernel composition stays
    ## linux-platforms-only until that lands.
    "-DGOODNET_BUILD_BUNDLED_PLUGINS=OFF"
    "-DGOODNET_BUILD_APPS=OFF"
    ## mold + LTO + ccache PCH paths assume a Linux toolchain layout;
    ## the Apple cross stdenv ships its own ld64; skip the kernel's
    ## linker / LTO knobs so the cross stdenv's defaults apply.
    "-DGOODNET_USE_MOLD=OFF"
    "-DGOODNET_USE_LTO=OFF"
    "-DGOODNET_USE_PCH=OFF"
  ];

  doCheck = false;

  ## Skip the nixpkgs ELF fixup — Mach-O artefacts have their own
  ## install_name_tool pass that the cross stdenv handles via
  ## `fixupPhase`; the Linux-side `patchelf` pass would refuse a
  ## Mach-O file outright.
  dontPatchELF = true;

  meta = {
    description =
      "GoodNet kernel cross-built for Apple ${arch} (kernel-only, plugins ported per-flake).";
    ## `meta.platforms` checks against `hostPlatform` (the target),
    ## not the build host. The flake gates this attribute under
    ## `isLinux` for the build host; once visible the derivation
    ## emits Mach-O, so the runtime platform is darwin.
    platforms = pkgs.lib.platforms.darwin;
  };

  ## CI reads `passthru.skip_reason` to short-circuit the
  ## darwin-cross-build job when the Apple SDK is absent in pure
  ## Nix cross. The build itself is still attempted in this
  ## derivation — the attribute is informational, surfaced through
  ## `nix eval .#goodnet-darwin-${arch}.skip_reason --raw` from the
  ## CI step before `nix build` runs. The reason is conditional on
  ## the host environment: if `apple-sdk` is reachable via
  ## `requireFile` the operator-staged path makes the gate vacuous.
  passthru.skip_reason =
    "Apple SDK not available in pure Nix cross — operator must stage"
    + " apple-sdk through requireFile (Xcode license). CI skips this"
    + " target gracefully via continue-on-error.";
}
