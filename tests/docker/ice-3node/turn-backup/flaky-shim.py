#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Flaky TURN front-end for the multi-TURN failover scenario.

Listens on 0.0.0.0:3478/udp. For the first TURN_FAIL_COUNT
incoming STUN/TURN requests, synthesises a STUN error-response
(class 0b11) with error-code 500 and sends it back to the
client; subsequent requests are forwarded transparently to the
real coturn instance bound to 127.0.0.1:3479, and replies are
proxied back to the original client.

The transition from "fail" to "passthrough" is one-way; once
TURN_FAIL_COUNT requests have arrived, the shim stays in
passthrough mode for the rest of its lifetime. The peer harness
asserts that the failover code path picks the secondary TURN
server only after the primary has failed mid-allocation.

STUN message header (RFC 5389 §6):

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 0|     STUN Message Type     |         Message Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Magic Cookie                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Transaction ID (96 bits)                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Error-Response class flips bits C1=1 C0=1 in the message-type
field; the method bits stay identical so the client matches the
reply against the original transaction. ERROR-CODE attribute
(0x0009) carries class*100 + number — here 5*100 + 0 = 500.
"""

import os
import socket
import struct
import sys
import threading

LISTEN_PORT = 3478
COTURN_ADDR = ("127.0.0.1", 3479)
MAGIC_COOKIE = 0x2112A442
FAIL_COUNT = int(os.environ.get("TURN_FAIL_COUNT", "5"))


def is_stun(pkt: bytes) -> bool:
    """Cheap sniff: STUN/TURN messages start with two zero bits and
    carry the RFC 5389 magic cookie in bytes 4..8.
    """
    if len(pkt) < 20:
        return False
    if pkt[0] & 0xC0:
        return False
    cookie, = struct.unpack("!I", pkt[4:8])
    return cookie == MAGIC_COOKIE


def make_error_500(req: bytes) -> bytes:
    """Build a STUN error response with ERROR-CODE 500 keyed off
    the transaction id of `req`.
    """
    msg_type = struct.unpack("!H", req[0:2])[0]
    # Set class bits C1=1 C0=1 (Error Response). C1 is bit 8,
    # C0 is bit 4 inside the 14-bit type field.
    err_type = msg_type | 0x0110
    txid = req[8:20]
    # ERROR-CODE attribute: type 0x0009, length 4, reserved(3)=0,
    # class=5, number=0, reason="".
    attr = struct.pack("!HHBBBB", 0x0009, 4, 0, 0, 5, 0)
    body_len = len(attr)
    header = struct.pack("!HHI", err_type, body_len, MAGIC_COOKIE) + txid
    return header + attr


def proxy_reply_loop(client_sock: socket.socket,
                     upstream_sock: socket.socket,
                     client_addr) -> None:
    """Forward replies from coturn back to the original client.

    One loop per outstanding client; coturn answers to whichever
    ephemeral port the shim used to upcall, and the reply is
    handed back to `client_addr` on the wildcard listener.
    """
    try:
        upstream_sock.settimeout(30.0)
        while True:
            try:
                data, _ = upstream_sock.recvfrom(65535)
            except socket.timeout:
                return
            if not data:
                return
            client_sock.sendto(data, client_addr)
    except OSError:
        return


def main() -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", LISTEN_PORT))

    seen = 0
    print(f"[flaky-shim] listening :{LISTEN_PORT}/udp "
          f"fail_count={FAIL_COUNT} upstream={COTURN_ADDR}",
          flush=True)

    # Map client address → its dedicated upstream socket so coturn
    # 5-tuples stay stable per peer.
    upstreams: dict = {}

    while True:
        try:
            pkt, addr = listener.recvfrom(65535)
        except OSError as exc:
            print(f"[flaky-shim] recv error: {exc}",
                  file=sys.stderr, flush=True)
            return 1

        if not is_stun(pkt):
            # Not STUN — passthrough unconditionally; relayed data
            # channels use random method bits without the cookie.
            pass
        else:
            seen += 1
            if seen <= FAIL_COUNT:
                reply = make_error_500(pkt)
                listener.sendto(reply, addr)
                print(f"[flaky-shim] req#{seen} -> 500 to {addr}",
                      flush=True)
                continue
            elif seen == FAIL_COUNT + 1:
                print(f"[flaky-shim] threshold crossed, "
                      f"switching to passthrough",
                      flush=True)

        up = upstreams.get(addr)
        if up is None:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstreams[addr] = up
            t = threading.Thread(
                target=proxy_reply_loop,
                args=(listener, up, addr),
                daemon=True,
            )
            t.start()
        up.sendto(pkt, COTURN_ADDR)


if __name__ == "__main__":
    sys.exit(main())
