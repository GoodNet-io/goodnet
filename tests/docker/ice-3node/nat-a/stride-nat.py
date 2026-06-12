#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic symmetric NAT with sequential-port stride.

The real symmetric mode uses `iptables MASQUERADE --random-fully`
which scrambles the SNAT port per destination — exactly the
shape that defeats ICE srflx. For the port-prediction scenario
we need the OPPOSITE property: the SNAT port must be picked
DETERMINISTICALLY and sequentially across destinations so the
peer-side port-prediction salvo at `srflx_port + 1, + 2, …`
hits a working pair.

Implementation: a userland UDP forwarder that LAN traffic is
intercepted into via `iptables -t mangle -A PREROUTING -i
$LAN_IFACE -p udp -j TPROXY --on-port $REDIRECT_PORT`. TPROXY
(not REDIRECT) preserves the original destination address so
`IP_RECVORIGDSTADDR` returns the TRUE upstream server address
— REDIRECT rewrites it to the local listener before delivery,
making recovery impossible. For each incoming (lan_addr,
dst_addr) flow, the daemon picks the next sequential WAN port
(starting at STRIDE_BASE, step 1) and binds an upstream socket
to it. Each new destination from the same LAN source gets the
NEXT port — so peer A's first egress lands on port N, the
second on N+1, etc. Peers learn N from STUN against the
coordinator, and the port-prediction code tries N+k against
peer B's destination. Upstream responses are forwarded through
a per-server IP_TRANSPARENT socket so the source address seen
by the LAN peer is the real STUN server, not the forwarder.

This is a synthetic fixture — production NATs do whatever Linux
conntrack chooses. The point is to exercise the prediction
code path in a topology that's deterministic enough to assert
on.
"""

import os
import select
import socket
import struct
import sys
import threading

LAN_IFACE = os.environ.get("LAN_IFACE", "eth0")
WAN_IFACE = os.environ.get("WAN_IFACE", "eth1")
REDIRECT_PORT = int(os.environ.get("REDIRECT_PORT", "9999"))
STRIDE_BASE = int(os.environ.get("STRIDE_BASE", "40000"))
STRIDE_STEP = int(os.environ.get("STRIDE_STEP", "1"))

SOL_IP = 0
IP_RECVORIGDSTADDR = 20
IP_TRANSPARENT = 19


def get_wan_ip(iface: str) -> str:
    """Read the first IPv4 address bound to `iface`."""
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # SIOCGIFADDR
        ifr = struct.pack("256s", iface.encode()[:15])
        info = fcntl.ioctl(s.fileno(), 0x8915, ifr)
        return socket.inet_ntoa(info[20:24])
    finally:
        s.close()


def main() -> int:
    wan_ip = get_wan_ip(WAN_IFACE)
    print(f"[stride-nat] WAN {WAN_IFACE} ip={wan_ip} "
          f"base={STRIDE_BASE} step={STRIDE_STEP}",
          flush=True)

    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.setsockopt(SOL_IP, IP_RECVORIGDSTADDR, 1)
    listener.setsockopt(SOL_IP, IP_TRANSPARENT, 1)  # required for TPROXY delivery
    listener.bind(("0.0.0.0", REDIRECT_PORT))

    # Per (lan_endpoint, dst_endpoint) → bound WAN socket.
    flows: dict = {}
    next_port = STRIDE_BASE
    lock = threading.Lock()

    # Per upstream_addr → transparent reply socket that spoofs
    # the source address of STUN responses back to LAN hosts.
    # Requires CAP_NET_ADMIN (present in nat containers).
    reply_socks: dict = {}
    reply_lock = threading.Lock()

    def get_reply_sock(upstream_addr):
        with reply_lock:
            if upstream_addr not in reply_socks:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.setsockopt(SOL_IP, IP_TRANSPARENT, 1)
                    s.bind(upstream_addr)
                    reply_socks[upstream_addr] = s
                    print(f"[stride-nat] transparent reply socket "
                          f"for {upstream_addr}", flush=True)
                except OSError as exc:
                    print(f"[stride-nat] WARN: transparent bind "
                          f"{upstream_addr}: {exc}", flush=True)
                    reply_socks[upstream_addr] = None
            return reply_socks[upstream_addr]

    def upstream_reader(up_sock: socket.socket,
                        lan_addr) -> None:
        try:
            up_sock.settimeout(30.0)
            while True:
                try:
                    data, peer_addr = up_sock.recvfrom(65535)
                except socket.timeout:
                    return
                if not data:
                    return
                # Forward response appearing to come from the original
                # upstream server so the LAN peer's carrier matches it.
                reply = get_reply_sock(peer_addr)
                if reply is not None:
                    try:
                        reply.sendto(data, lan_addr)
                        continue
                    except OSError:
                        pass
                listener.sendto(data, lan_addr)
        except OSError:
            return

    print(f"[stride-nat] listening :{REDIRECT_PORT}/udp",
          flush=True)

    while True:
        try:
            msg, ancdata, _flags, lan_addr = listener.recvmsg(
                65535, socket.CMSG_SPACE(16))
        except OSError as exc:
            print(f"[stride-nat] recv error: {exc}",
                  file=sys.stderr, flush=True)
            return 1

        # Recover original destination from IP_RECVORIGDSTADDR ancdata.
        # struct sockaddr_in: sin_family(2H), sin_port(2H net), sin_addr(4s), pad(8x)
        orig_dst = None
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == SOL_IP and cmsg_type == IP_RECVORIGDSTADDR:
                orig_port = struct.unpack_from("!H", cmsg_data, 2)[0]
                orig_ip = socket.inet_ntoa(cmsg_data[4:8])
                orig_dst = (orig_ip, orig_port)
                break

        if orig_dst is None:
            print("[stride-nat] WARN: no orig dst, dropping", flush=True)
            continue

        # Key on (src, dst) so each new destination from the same
        # LAN source allocates a fresh sequential WAN port.
        key = (lan_addr, orig_dst)
        with lock:
            entry = flows.get(key)
            if entry is None:
                wan_port = next_port
                next_port += STRIDE_STEP
                up = socket.socket(socket.AF_INET,
                                   socket.SOCK_DGRAM)
                up.bind((wan_ip, wan_port))
                entry = (up, wan_port)
                flows[key] = entry
                t = threading.Thread(
                    target=upstream_reader,
                    args=(up, lan_addr),
                    daemon=True,
                )
                t.start()
                print(f"[stride-nat] flow {lan_addr} -> {orig_dst} "
                      f"via WAN port {wan_port}",
                      flush=True)
            up, _wan_port = entry

        up.sendto(msg, orig_dst)


if __name__ == "__main__":
    sys.exit(main())
