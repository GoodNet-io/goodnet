#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Bring up the NAT type the scenario asks for. Three modes:
#
# * full_cone   — single SNAT to the WAN-side IP. Once a flow opens
#                 the reverse mapping is permissive, so any peer can
#                 send to (WAN-IP, allocated-port) and reach the LAN
#                 endpoint. STUN srflx candidates work directly.
#
# * symmetric   — same SNAT but the source port is REWRITTEN per
#                 destination (achieved via PREROUTING + a separate
#                 conntrack zone). A peer learning (WAN-IP, port) for
#                 one destination can't reuse it for another, so ICE
#                 falls back to TURN relay.
#
# * shared      — both LAN sides translate through the SAME upstream
#                 IP. Used for the hairpin scenario where peers A and
#                 B share NAT-A (NAT-B is unused). Hairpin loopback
#                 enabled so A→B via WAN-IP works inside the NAT.
#
# Logs to stdout so `docker compose logs nat_b` shows the chosen
# mode + the iptables ruleset.

set -eu

# Interface names default to docker's `eth0` / `eth1` assignment
# order (alphabetical by network name in compose), but the order
# is fragile if scenarios add/rename networks. Detect the WAN side
# dynamically by asking the kernel which interface owns the route
# to the `net` subnet (10.10.0.0/24); fall back to the static
# defaults when ip(8) is unavailable or the route is missing
# (e.g. unit-test runs of the script outside docker).
LAN_SUBNET="${LAN_SUBNET:-10.30.0.0/24}"
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
WAN_IFACE="${WAN_DETECTED:-${WAN_IFACE:-eth1}}"
LAN_IFACE="${LAN_DETECTED:-${LAN_IFACE:-eth0}}"

echo "[init-nat] mode=${NAT_MODE} lan=${LAN_IFACE}(${LAN_SUBNET}) wan=${WAN_IFACE}(${WAN_SUBNET})"

# Derive the LAN-side listening IP for miniupnpd as the .1 host of
# the LAN subnet (e.g. 10.20.0.1 for nat-a, 10.30.0.1 for nat-b).
LAN_PREFIX="${LAN_SUBNET%.*/*}"
UPNP_LISTEN_IP="${LAN_PREFIX}.1"
# Resolve the WAN-side IPv4 (the address miniupnpd reports as the
# external IP in UPnP/PCP responses). See nat-a/init-nat.sh.
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
# table + chains. See nat-a/init-nat.sh for why we skip the legacy
# `MINIUPNPD` iptables chain creation in this environment.

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
        # See nat-a/init-nat.sh full_cone branch for the rationale —
        # plain MASQUERADE gives endpoint-independent mapping but
        # endpoint-DEPENDENT filtering, which is address-restricted
        # cone, not full-cone. Adding a static 1:1 DNAT for every
        # inbound UDP packet on the WAN side synthesises full-cone
        # filtering for the single LAN peer.
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
# port mappings. See nat-a/init-nat.sh for the rationale.
cat > /etc/miniupnpd/miniupnpd.conf <<EOF
ext_ifname=${WAN_IFACE}
listening_ip=${UPNP_LISTEN_IP}
enable_natpmp=yes
enable_upnp=yes
secure_mode=no
system_uptime=yes
allow 1024-65535 ${LAN_SUBNET} 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
EOF

echo "[init-nat] miniupnpd config:"
cat /etc/miniupnpd/miniupnpd.conf
echo "[init-nat] starting miniupnpd"

# Foreground (`-d`) so docker treats miniupnpd as the container's
# PID 1. `-f` is load-bearing — the package ships no default
# /etc/miniupnpd.conf.
echo "[init-nat] ready" > /tmp/nat-ready
exec miniupnpd -d -f /etc/miniupnpd/miniupnpd.conf
