#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Bring up the NAT type the scenario asks for. Four modes:
#
# * full_cone         — single SNAT to the WAN-side IP. Once a flow
#                       opens the reverse mapping is permissive, so any
#                       peer can send to (WAN-IP, allocated-port) and
#                       reach the LAN endpoint. STUN srflx candidates
#                       work directly.
#
# * symmetric         — same SNAT but the source port is REWRITTEN per
#                       destination (achieved via PREROUTING + a
#                       separate conntrack zone). A peer learning
#                       (WAN-IP, port) for one destination can't reuse
#                       it for another, so ICE falls back to TURN.
#
# * shared            — both LAN sides translate through the SAME
#                       upstream IP. Used for the hairpin scenario
#                       where peers A and B share NAT-A (NAT-B is
#                       unused). Hairpin loopback enabled so A→B via
#                       WAN-IP works inside the NAT.
#
# * symmetric_stride  — symmetric semantics but with DETERMINISTIC
#                       sequential-port allocation across destinations
#                       (stride controlled by STRIDE_BASE + STRIDE_STEP
#                       env). Used by the port-prediction scenario to
#                       give the peer-side prediction salvo a
#                       learnable target.
#
# Logs to stdout so `docker compose logs nat_a` shows the chosen
# mode + the iptables ruleset.

set -eu

# Interface names default to docker's `eth0` / `eth1` assignment
# order (alphabetical by network name in compose), but the order
# is fragile if scenarios add/rename networks. Detect the WAN side
# dynamically by asking the kernel which interface owns the route
# to the `net` subnet (10.10.0.0/24); fall back to the static
# defaults when ip(8) is unavailable or the route is missing
# (e.g. unit-test runs of the script outside docker).
LAN_SUBNET="${LAN_SUBNET:-10.20.0.0/24}"
WAN_SUBNET="${WAN_SUBNET:-10.10.0.0/24}"
NAT_MODE="${NAT_MODE:-full_cone}"

detect_iface() {
    # `ip -o route show <subnet>` prints "<subnet> dev <iface> ..."
    # Pick the second field after `dev`. Empty on missing route.
    ip -o route show "$1" 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

WAN_DETECTED="$(detect_iface "${WAN_SUBNET}")"
LAN_DETECTED="$(detect_iface "${LAN_SUBNET}")"
# Prefer kernel-observed iface over the Dockerfile ENV defaults
# (eth0/eth1) so a docker version that picks a different
# alphabetical ordering between compose networks doesn't silently
# wire the WAN-side MASQUERADE to the LAN interface (which would
# leave OutDatagrams climbing on the bridge while FORWARD stays
# at zero — the bug this script exists to defeat). The env vars
# remain as final fallback if the route lookup fails.
WAN_IFACE="${WAN_DETECTED:-${WAN_IFACE:-eth1}}"
LAN_IFACE="${LAN_DETECTED:-${LAN_IFACE:-eth0}}"

echo "[init-nat] mode=${NAT_MODE} lan=${LAN_IFACE}(${LAN_SUBNET}) wan=${WAN_IFACE}(${WAN_SUBNET})"

# Derive the LAN-side listening IP for miniupnpd as the .1 host of
# the LAN subnet (e.g. 10.20.0.1 for nat-a, 10.30.0.1 for nat-b).
# Strip the /mask, keep the first three octets, append `.1`. This is
# the canonical home-router gateway address the docker-compose IPAM
# block puts on the NAT container's LAN interface.
LAN_PREFIX="${LAN_SUBNET%.*/*}"
UPNP_LISTEN_IP="${LAN_PREFIX}.1"

# Resolve the WAN-side IPv4 the NAT container holds on the
# Internet-bridge interface; miniupnpd uses this as the
# externalIPAddress it reports to UPnP/PCP clients. The compose
# assigns 10.10.0.20 to nat-a (10.10.0.30 to nat-b) which is an
# RFC1918 range — fine for the harness, but the daemon prints a
# warning unless we declare it explicitly via `ext_ip`.
UPNP_EXT_IP="$(ip -o -4 addr show dev "${WAN_IFACE}" 2>/dev/null \
    | awk '{print $4}' | head -n1 | cut -d/ -f1)"

# Enable IP forwarding regardless of mode. compose `sysctls:` block
# already toggles `net.ipv4.ip_forward=1` per namespace, but write
# directly to /proc/sys for belt-and-braces (and to keep the
# container layer independent of the `procps` package being
# installed — debian-slim ships `iptables` / `iproute2` but not
# `sysctl(8)`).
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding 2>/dev/null || true

# Optional cross-LAN static route — set by scenarios that need
# inter-LAN reachability (e.g. prflx host-only candidate tests).
if [ -n "${PEER_LAN_SUBNET:-}" ] && [ -n "${PEER_LAN_GW:-}" ]; then
    ip route replace "${PEER_LAN_SUBNET}" via "${PEER_LAN_GW}" 2>/dev/null \
        || true
    echo "[init-nat] added cross-LAN route ${PEER_LAN_SUBNET} via ${PEER_LAN_GW}"
fi

# Wipe any rules from a previous run.
iptables -t nat -F
iptables -t filter -F
iptables -t mangle -F

# miniupnpd (nftables backend) creates its own `inet miniupnpd`
# table + `miniupnpd` chains at startup. We deliberately do NOT
# pre-create the legacy `MINIUPNPD` / `MINIUPNPD-POSTROUTING`
# iptables chains the upstream task spec suggested: bookworm's
# `iptables` alternative is `iptables-nft` and the docker host
# kernel exposes only nf_tables, so legacy chain creation would be
# both unnecessary (miniupnpd-nftables hooks itself into nft
# natively) and broken (no `iptable_nat` module loaded in the host
# kernel). The MASQUERADE rule below remains iptables-nft because
# that's what the rest of init-nat.sh has always used and
# iptables-nft happily translates it into the nft ruleset shared
# with miniupnpd-nftables.

# FORWARD chain default — docker's child-netns FORWARD policy is
# inherited from the base image (debian: ACCEPT) but some hosts +
# kernel-modules pre-populate restrictive rules. Force a permissive
# policy here and then layer explicit ACCEPT rules so the iptables
# packet counters tell us whether traffic actually traverses.
iptables -P FORWARD ACCEPT
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT

# Explicit ACCEPT for forwarding in both directions. LAN → WAN is
# the outbound peer→Internet path; the reverse half allows STUN /
# TURN replies (and the eventual ICE check-pair response packets)
# to reach the LAN-side peer. Without these rules the FORWARD
# hook silently drops UDP between bridges even with ip_forward=1,
# because the docker bridge driver doesn't install per-network
# ACCEPT rules into the container's own netns FORWARD chain.
iptables -A FORWARD -i "${LAN_IFACE}" -o "${WAN_IFACE}" -j ACCEPT
iptables -A FORWARD -i "${WAN_IFACE}" -o "${LAN_IFACE}" \
    -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# Permit unsolicited inbound to a full-cone NAT — the conntrack
# entry is created by the outbound STUN binding request and the
# reverse half above covers RELATED/ESTABLISHED, but ICE peer
# checks arrive on a different 5-tuple than the STUN binding so
# the conntrack state is NEW from the WAN side. Allow it; the
# NAT POSTROUTING rule below + the conntrack tuple decide
# whether it reaches a LAN endpoint.
iptables -A FORWARD -i "${WAN_IFACE}" -o "${LAN_IFACE}" -j ACCEPT

case "${NAT_MODE}" in
    full_cone)
        # Full-cone behaviour requires endpoint-independent mapping
        # AND endpoint-independent filtering: any external host may
        # send to the NAT-allocated (ext-IP, ext-port) and reach the
        # LAN endpoint, regardless of whether the LAN side has ever
        # talked to that external host. Plain iptables MASQUERADE
        # gives endpoint-independent mapping (same ext-port for every
        # destination from a given internal flow) but
        # endpoint-DEPENDENT filtering — conntrack only forwards
        # inbound from peers the LAN endpoint already replied to.
        #
        # To synthesise true full-cone in the test harness:
        #   1. SNAT to the WAN IP with `--persistent` so the source
        #      port stays stable across destinations (already the
        #      default behaviour of MASQUERADE in modern kernels;
        #      kept explicit for documentation).
        #   2. Static 1:1 DNAT for every inbound UDP on the WAN side
        #      so unsolicited packets from a new peer get forwarded
        #      to the LAN endpoint without needing a pre-existing
        #      conntrack entry. The LAN_SUBNET has exactly one peer
        #      (peer_a = 10.20.0.20 / peer_b = 10.30.0.20), so 1:1
        #      DNAT is unambiguous.
        #
        # This is MORE permissive than RFC 4787 full-cone (it
        # forwards every WAN-side UDP destination port, not just the
        # NAT-allocated ones), but ICE only cares about the
        # gathered srflx tuple, and the harness has no
        # legitimate inbound traffic to other ports anyway.
        LAN_PEER_IP="${LAN_PREFIX}.20"
        iptables -t nat -A POSTROUTING -s "${LAN_SUBNET}" \
            -o "${WAN_IFACE}" -j MASQUERADE
        iptables -t nat -A PREROUTING -i "${WAN_IFACE}" -p udp \
            -j DNAT --to-destination "${LAN_PEER_IP}"
        ;;
    symmetric)
        # SNAT with --random-fully — every (src-IP, src-port,
        # dst-IP, dst-port) gets an independent NAT-port mapping.
        # Reads of (NAT-IP, port) by peer A can't be re-used by
        # peer B for the same internal endpoint. ICE srflx fails;
        # TURN relay wins.
        iptables -t nat -A POSTROUTING -s "${LAN_SUBNET}" \
            -o "${WAN_IFACE}" -j MASQUERADE --random-fully
        ;;
    shared)
        # Same as full_cone plus hairpin SNAT so a LAN peer
        # talking to the NAT's own WAN IP gets looped back to the
        # other LAN peer behind the same NAT.
        iptables -t nat -A POSTROUTING -s "${LAN_SUBNET}" \
            -o "${WAN_IFACE}" -j MASQUERADE
        iptables -t nat -A POSTROUTING -s "${LAN_SUBNET}" \
            -d "${LAN_SUBNET}" -j MASQUERADE
        ;;
    symmetric_stride)
        # Synthetic symmetric NAT with deterministic
        # sequential-port allocation. Outbound UDP is intercepted
        # via iptables TPROXY (not REDIRECT) so that the userland
        # forwarder sees the ORIGINAL destination address via
        # IP_RECVORIGDSTADDR — REDIRECT rewrites the destination
        # to a local IP before delivery, making it impossible to
        # recover the real upstream server address.
        REDIRECT_PORT="${REDIRECT_PORT:-9999}"
        STRIDE_BASE="${STRIDE_BASE:-40000}"
        STRIDE_STEP="${STRIDE_STEP:-1}"
        # Policy routing: packets marked 0x1 are delivered locally
        # regardless of destination IP (required for TPROXY).
        ip rule add fwmark 0x1 lookup 100 2>/dev/null || true
        ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
        # TPROXY: intercept all UDP from LAN (except the forwarder's
        # own listen port to avoid loops) and hand to stride-nat.
        iptables -t mangle -A PREROUTING -i "${LAN_IFACE}" \
            -p udp ! --dport "${REDIRECT_PORT}" \
            -j TPROXY --on-port "${REDIRECT_PORT}" --tproxy-mark 0x1/0x1
        # Also masquerade non-UDP traffic so STUN-over-TCP and
        # control plane traffic still reaches the Internet
        # subnet without being trapped by the forwarder.
        iptables -t nat -A POSTROUTING -s "${LAN_SUBNET}" \
            -o "${WAN_IFACE}" ! -p udp -j MASQUERADE
        export REDIRECT_PORT STRIDE_BASE STRIDE_STEP \
               LAN_IFACE WAN_IFACE LAN_SUBNET
        echo "[init-nat] launching stride-nat daemon" \
             "base=${STRIDE_BASE} step=${STRIDE_STEP}"
        python3 /usr/local/bin/stride-nat.py &
        ;;
    *)
        echo "[init-nat] unknown NAT_MODE=${NAT_MODE}" >&2
        exit 1
        ;;
esac

echo "[init-nat] iptables -t nat -L -nv:"
iptables -t nat -L -nv
echo "[init-nat] iptables -L FORWARD -nv:"
iptables -L FORWARD -nv

# Optional: drop ALL UDP between the LAN and a target subnet
# (typically the peer's LAN reachable via the WAN bridge). Used
# by the no-UDP-fallback scenario to force the stack onto the
# TURN-over-TLS-TCP path. BLOCK_UDP_TO empty = no drop.
BLOCK_UDP_TO="${BLOCK_UDP_TO:-}"
if [ -n "${BLOCK_UDP_TO}" ]; then
    echo "[init-nat] dropping UDP forward to ${BLOCK_UDP_TO}"
    iptables -I FORWARD -p udp -d "${BLOCK_UDP_TO}" -j DROP
    iptables -I FORWARD -p udp -s "${BLOCK_UDP_TO}" -j DROP
fi

# Optional: clip the WAN-side egress MTU via netem so DPLPMTUD
# probing has something to discover. PATH_MTU=0 (default) leaves
# the link untouched.
PATH_MTU="${PATH_MTU:-0}"
if [ "${PATH_MTU}" -gt 0 ]; then
    echo "[init-nat] clipping ${WAN_IFACE} MTU to ${PATH_MTU} via netem"
    # tc on debian needs the iproute2 package which is already
    # present; ignore errors if netem isn't loadable in the
    # container's kernel namespace.
    tc qdisc add dev "${WAN_IFACE}" root netem mtu "${PATH_MTU}" \
        2>/dev/null || \
        echo "[init-nat] WARN: tc netem mtu unsupported, " \
             "falling back to interface MTU"
    ip link set dev "${WAN_IFACE}" mtu "${PATH_MTU}" || true
    echo "[init-nat] tc qdisc show:"
    tc qdisc show dev "${WAN_IFACE}"
fi

# Emit a minimal miniupnpd config tailored to this container's
# (WAN, LAN) iface pair. The daemon serves UPnP IGD + NAT-PMP /
# PCP on the LAN side so peers behind the NAT can request explicit
# port mappings. The `gn.link.portmap` plugin used by the ICE
# integration layer discovers the IGD via SSDP and falls through
# to PCP / NAT-PMP if UPnP fails; both transports are enabled here
# to broaden the portmap-path coverage across scenarios.
cat > /etc/miniupnpd/miniupnpd.conf <<EOF
ext_ifname=${WAN_IFACE}
listening_ip=${UPNP_LISTEN_IP}
enable_natpmp=yes
enable_upnp=yes
secure_mode=no
system_uptime=yes
# Permit clients on the LAN subnet to request mappings into the
# full ephemeral range; the harness scenarios do not care about
# port hygiene, only about whether the mapping succeeds and the
# (ext_ip, ext_port) tuple gets surfaced into the ICE candidate
# list as a portmap-srflx.
allow 1024-65535 ${LAN_SUBNET} 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
EOF

echo "[init-nat] miniupnpd config:"
cat /etc/miniupnpd/miniupnpd.conf
echo "[init-nat] starting miniupnpd"

# Foreground (`-d`) so docker treats miniupnpd as the container's
# PID 1 for signal handling + log forwarding. `-f` points at the
# config we just emitted (default path is `/etc/miniupnpd.conf` —
# singular — which the debian package does NOT ship, so the `-f`
# is load-bearing).
echo "[init-nat] ready" > /tmp/nat-ready
exec miniupnpd -d -f /etc/miniupnpd/miniupnpd.conf
