# Peer container: GoodNet kernel + plugins + the host-built
# `peer-harness` binary that drives the cluster-side ICE connect
# dance.
#
# Built atop the static-linked kernel image produced by
# `nix build .#docker-static` in the kernel monorepo
# (loaded into the local docker daemon as `goodnet:nix-static`).
# That image already has `libgoodnet_kernel.so` baked at /lib/ plus
# the runtime dep closure (libsodium, libcrypto, libstdc++, glibc)
# under /nix/store, so the harness binary's nix-store RUNPATH
# resolves at load time.
#
# Plugin .so files and the harness binary are produced by the host
# build (`nix develop --command ninja -C build-release`) and copied
# into the build context by `run_all.sh` next to this Dockerfile.
FROM goodnet:nix-static

# `goodnet:nix-static` ships coreutils-full but no iproute2 and no
# /lib64/ld-linux loader, so the canonical `busybox:latest`
# image — which is a debian-style dynamically-linked PIE — fails
# to exec inside this base. The orchestrator stages a
# statically-linked busybox (musl libc, no interpreter section)
# next to the Dockerfile and we COPY it in directly. Symlinking
# busybox to a handful of applet names gives the entrypoint
# script `ip` for route fix-up (the per-LAN NAT redirect) and
# `grep`/`sed` for any later config-tweak step. ~1.4 MiB.
COPY busybox-static /usr/local/bin/busybox
RUN chmod +x /usr/local/bin/busybox && \
    for applet in ip route grep sed; do \
        ln -sf /usr/local/bin/busybox "/usr/local/bin/${applet}"; \
    done

WORKDIR /work
COPY run.sh /usr/local/bin/peer-run.sh
RUN chmod +x /usr/local/bin/peer-run.sh

# Host-built peer harness. The orchestrator (`run_all.sh`) stages
# `harness` into this directory before invoking `docker compose
# up --build`, so the COPY below resolves at image-build time. The
# binary statically links the kernel archive; its only runtime .so
# deps are libcrypto / libsodium / libstdc++ / libgcc / glibc, all
# of which the base image ships under /nix/store. The plugin .so
# set under /plugins/ is loaded explicitly by
# `gn_core_load_plugins_batch`, not by ld at startup, so missing
# plugins surface as a clean error rather than an unresolved-symbol
# abort.
COPY harness /usr/local/bin/peer-harness
RUN chmod +x /usr/local/bin/peer-harness

# Plugin .so set required by the harness, sourced from
# `build-release/plugins/`. The harness mints SHA-256 over each file
# itself and feeds them to `gn_core_load_plugins_batch`, so the
# image only needs the .so bytes — no separate manifest.
COPY plugins/ /plugins/

ENTRYPOINT ["/usr/local/bin/peer-run.sh"]
