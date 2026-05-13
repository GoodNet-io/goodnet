# Reproducible Docker image for the static GoodNet binary.
#
# `nix build .#docker-static --print-out-paths` emits a deterministic
# .tar.gz that `docker load -i` consumes into the local daemon.
# Image hash is stable on identical inputs — no apt mirror drift,
# no time-stamped layer surprises.
#
# Base layer is `dockerTools.buildLayeredImage` with debian-slim's
# glibc closure copied from nixpkgs. A musl + scratch base would
# shrink the image to ~5 MiB but needs every plugin's dep closure
# rebuilt under `nixpkgs.pkgsMusl`; not in scope this round.

{ pkgs
, goodnet-core    # the static `goodnet-core` derivation
, name    ? "goodnet"
, tag     ? "nix-static"
}:

pkgs.dockerTools.buildLayeredImage {
  inherit name tag;
  contents = [
    goodnet-core
    pkgs.dockerTools.binSh        # /bin/sh — useful for `docker exec`
    pkgs.dockerTools.usrBinEnv    # /usr/bin/env — same
    pkgs.coreutils-full           # debug-time `ls`/`cat`/`stat`
  ];
  config = {
    Entrypoint = [ "${goodnet-core}/bin/goodnet" ];
    Cmd        = [ "version" ];
    Labels = {
      "org.opencontainers.image.title"       = "GoodNet";
      "org.opencontainers.image.description" =
        "Cross-language networking kernel — static build.";
      "org.opencontainers.image.source" =
        "https://github.com/GoodNet-io/goodnet";
    };
  };
}
