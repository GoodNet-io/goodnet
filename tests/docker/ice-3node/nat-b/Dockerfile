# NAT-B container — same shape as nat-a, different LAN subnet
# (10.30.0.0/24). See nat-a/init-nat.sh for the mode semantics.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iptables iproute2 conntrack ipset netcat-openbsd nftables \
        miniupnpd-nftables \
    && rm -rf /var/lib/apt/lists/*

# Use the nftables-backed miniupnpd because the docker host kernel
# exposes only nf_tables (not legacy xtables). See nat-a/Dockerfile
# for the rationale.

COPY init-nat.sh /usr/local/bin/init-nat.sh
RUN chmod +x /usr/local/bin/init-nat.sh \
    && mkdir -p /etc/miniupnpd /var/lib/misc /var/log /var/run

ENV NAT_MODE=full_cone
ENV LAN_IFACE=eth0
ENV WAN_IFACE=eth1
ENV LAN_SUBNET=10.30.0.0/24

ENTRYPOINT ["/usr/local/bin/init-nat.sh"]
