# Peer container: GoodNet kernel + plugins + a small `harness`
# binary that drives the cluster-side ICE connect dance.
#
# Built atop the static-linked kernel image produced by
# `nix build .#docker-static` in the kernel monorepo
# (loaded into the local docker daemon as `goodnet:nix-static`).
# That image already has goodnet + every linked-in plugin
# baked at /usr/local/bin/goodnet.
FROM goodnet:nix-static AS base

# Runtime tooling for the harness: nc for signaling round-trip
# inside the shared volume, ip/ss for live diagnostics.
USER root
RUN if command -v apt-get >/dev/null 2>&1; then \
        apt-get update && apt-get install -y --no-install-recommends \
            netcat-openbsd iproute2 ca-certificates && \
        rm -rf /var/lib/apt/lists/*; \
    fi || true

WORKDIR /work
COPY run.sh /usr/local/bin/peer-run.sh
COPY peer.json.tmpl /etc/goodnet/peer.json.tmpl
RUN chmod +x /usr/local/bin/peer-run.sh

ENTRYPOINT ["/usr/local/bin/peer-run.sh"]
