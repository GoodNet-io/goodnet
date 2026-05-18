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

Implementation: a userland UDP forwarder bound on the WAN-side
interface that LAN traffic gets redirected into via
`iptables -t nat -A PREROUTING -i $LAN_IFACE -p udp -j REDIRECT
--to-ports $REDIRECT_PORT`. For each incoming (lan_addr,
dst_addr) flow, the daemon picks the next sequential WAN port
(starting at STRIDE_BASE, step 1) and binds an upstream socket
to it. Each new destination from the same LAN source gets the
NEXT port — so peer A's first egress lands on port N, the
second on N+1, etc. Peers learn N from STUN against the
coordinator, and the port-prediction code tries N+k against
peer B's destination.

This is a synthetic fixture — production NATs do whatever Linux
conntrack chooses. The point is to exercise the prediction
code path in a topology that's deterministic enough to assert
on.
"""

import os
import select
import socket
import sys
import threading

LAN_IFACE = os.environ.get("LAN_IFACE", "eth0")
WAN_IFACE = os.environ.get("WAN_IFACE", "eth1")
REDIRECT_PORT = int(os.environ.get("REDIRECT_PORT", "9999"))
STRIDE_BASE = int(os.environ.get("STRIDE_BASE", "40000"))
STRIDE_STEP = int(os.environ.get("STRIDE_STEP", "1"))


def get_wan_ip(iface: str) -> str:
    """Read the first IPv4 address bound to `iface`."""
    import fcntl
    import struct
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
    # IP_TRANSPARENT-like behaviour isn't available without
    # CAP_NET_ADMIN + the TPROXY target; for the harness we
    # accept REDIRECT semantics where the original dst is read
    # via SO_ORIGINAL_DST.
    listener.bind(("0.0.0.0", REDIRECT_PORT))

    # Per (lan_endpoint, dst_endpoint) → bound WAN socket.
    flows: dict = {}
    next_port = STRIDE_BASE
    lock = threading.Lock()

    SO_ORIGINAL_DST = 80  # netfilter; same value for udp via getsockopt

    def upstream_reader(up_sock: socket.socket,
                        lan_addr) -> None:
        try:
            up_sock.settimeout(30.0)
            while True:
                try:
                    data, _ = up_sock.recvfrom(65535)
                except socket.timeout:
                    return
                if not data:
                    return
                listener.sendto(data, lan_addr)
        except OSError:
            return

    print(f"[stride-nat] listening :{REDIRECT_PORT}/udp",
          flush=True)

    while True:
        try:
            data, lan_addr = listener.recvfrom(65535)
        except OSError as exc:
            print(f"[stride-nat] recv error: {exc}",
                  file=sys.stderr, flush=True)
            return 1

        # REDIRECT for UDP doesn't expose SO_ORIGINAL_DST on
        # connectionless sockets in stock Linux; the harness
        # uses an out-of-band signalling channel (the coordinator
        # publishes the intended dst into the signal volume).
        # For the scaffold path we accept that the destination
        # lookup is left as a TODO and treat each new lan_addr
        # as a fresh flow that needs a fresh WAN port.
        key = lan_addr
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
                print(f"[stride-nat] flow {lan_addr} -> "
                      f"WAN port {wan_port}",
                      flush=True)
            up, wan_port = entry

        # Without SO_ORIGINAL_DST resolution the upstream forward
        # target is unknown; the harness signal-dir hop will
        # carry the intended destination in a follow-up. For
        # now the daemon stays receive-only on this path so the
        # scenario's compose validation + iptables wiring can
        # be verified without panicking. Production-shape
        # implementation lands once the harness binary is in
        # tree and can hand the daemon the connect target.
        _ = data


if __name__ == "__main__":
    sys.exit(main())
