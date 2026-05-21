# NAT-A container: a Linux box with two interfaces (lan_a side +
# Internet-side `net`) that forwards traffic between them with
# NAT rules picked at runtime from $NAT_MODE.
#
# The base compose entry sets NAT_MODE=full_cone — every flow from
# 10.20.0.0/24 → outside SNATs to 10.10.0.20 and the kernel
# `conntrack` keeps the reverse mapping permissive (full-cone).
# Scenario overrides flip NAT_MODE to `symmetric` or `shared` and
# init-nat.sh rewrites the iptables ruleset accordingly.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iptables iproute2 conntrack ipset netcat-openbsd nftables \
        python3 miniupnpd-nftables \
    && rm -rf /var/lib/apt/lists/*

# Pick the nftables-backed miniupnpd build because bookworm's
# `iptables` alternative defaults to `iptables-nft` AND the docker
# host kernel here only exposes the nf_tables (not legacy xtables)
# subsystem — `iptables-legacy` aborts with "Table does not exist"
# against this host. miniupnpd-nftables creates + manages its own
# `inet miniupnpd` table at startup, so we don't need to pre-create
# the legacy `MINIUPNPD` chains via iptables in init-nat.sh.

COPY init-nat.sh /usr/local/bin/init-nat.sh
COPY stride-nat.py /usr/local/bin/stride-nat.py
RUN chmod +x /usr/local/bin/init-nat.sh /usr/local/bin/stride-nat.py \
    && mkdir -p /etc/miniupnpd /var/lib/misc /var/log /var/run

# NAT_MODE: full_cone | symmetric | shared | symmetric_stride.
# Compose-override rewrites this env per scenario.
ENV NAT_MODE=full_cone
ENV LAN_IFACE=eth0
ENV WAN_IFACE=eth1
ENV LAN_SUBNET=10.20.0.0/24

ENTRYPOINT ["/usr/local/bin/init-nat.sh"]
