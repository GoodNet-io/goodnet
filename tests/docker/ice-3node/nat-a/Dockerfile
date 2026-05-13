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
        iptables iproute2 conntrack ipset netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY init-nat.sh /usr/local/bin/init-nat.sh
RUN chmod +x /usr/local/bin/init-nat.sh

# NAT_MODE: full_cone | symmetric | shared. Compose-override
# rewrites this env per scenario.
ENV NAT_MODE=full_cone
ENV LAN_IFACE=eth0
ENV WAN_IFACE=eth1
ENV LAN_SUBNET=10.20.0.0/24

ENTRYPOINT ["/usr/local/bin/init-nat.sh"]
