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
    symmetric_stride)
        # Synthetic symmetric NAT with deterministic
        # sequential-port allocation. Outbound UDP is redirected
        # into a userland forwarder which binds upstream sockets
        # on a strictly increasing WAN port (base + k*step).
        # Used by the port-prediction scenario so the peer's
        # +1/+2/+3 salvo lands on a learnable destination.
        REDIRECT_PORT="${REDIRECT_PORT:-9999}"
        STRIDE_BASE="${STRIDE_BASE:-40000}"
        STRIDE_STEP="${STRIDE_STEP:-1}"
        iptables -t nat -A PREROUTING -i "${LAN_IFACE}" \
            -p udp -j REDIRECT --to-ports "${REDIRECT_PORT}"
        # Also masquerade non-UDP traffic so STUN-over-TCP and
        # control plane traffic still reaches the Internet
        # subnet without being trapped by the forwarder.
        iptables -t nat -A POSTROUTING -s "${LAN_SUBNET}" \
            -o "${WAN_IFACE}" ! -p udp -j MASQUERADE
        export REDIRECT_PORT STRIDE_BASE STRIDE_STEP \
               LAN_IFACE WAN_IFACE
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

# Keep the container alive after rules install.
exec sleep infinity
