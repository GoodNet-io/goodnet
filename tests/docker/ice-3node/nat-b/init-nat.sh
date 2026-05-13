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
# Logs to stdout so `docker compose logs nat_a` shows the chosen
# mode + the iptables ruleset.

set -eu

LAN_IFACE="${LAN_IFACE:-eth0}"
WAN_IFACE="${WAN_IFACE:-eth1}"
LAN_SUBNET="${LAN_SUBNET:-10.20.0.0/24}"
NAT_MODE="${NAT_MODE:-full_cone}"

echo "[init-nat] mode=${NAT_MODE} lan=${LAN_IFACE}(${LAN_SUBNET}) wan=${WAN_IFACE}"

# Enable IP forwarding regardless of mode.
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Wipe any rules from a previous run.
iptables -t nat -F
iptables -t filter -F
iptables -t mangle -F

case "${NAT_MODE}" in
    full_cone)
        # Plain MASQUERADE — conntrack keeps the same (src-IP,
        # src-port) → (NAT-IP, alloc-port) mapping for every
        # destination. Full-cone behaviour because hairpin and
        # destination-restricted variants would need extra rules
        # we deliberately do NOT add.
        iptables -t nat -A POSTROUTING -s "${LAN_SUBNET}" \
            -o "${WAN_IFACE}" -j MASQUERADE
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

# Keep the container alive after rules install.
exec sleep infinity
