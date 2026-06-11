# GoodNet Plugin Challenge

Two tracks. One observation.

The observation: every protocol you use today carries the weight of its
substrate. ICE exists because TCP/IP has NAT and uses IP:port addresses —
connectivity checks are IP-specific, STUN candidates are IP-specific,
TURN relays are IP-specific. A file transfer resumes from the last TCP
segment because TCP is the session. A VPN routes packets through a
server because IP routing tables don't know about your public key.

The GoodNet kernel has no IP assumption anywhere. Identity is a
32-byte Ed25519 public key. The carrier is whatever link plugin calls
`notify_inbound_bytes`. The session is `peer_pk`, not a socket. This
is not a detail — it is a different substrate, and a different substrate
means you can solve the same problems without the constraints that made
the original solutions complicated.

---

## Track A — Write what the protocol should have been

Pick something that exists and works — peer discovery, NAT traversal,
file transfer, presence, routing, relay, VPN — and write it again,
freed from the IP-era constraints. The result should work over any
GoodNet link: TCP, IPC, powerline, thermal receipt printer, stellar
photometry. If it only works over IP links, you haven't done Track A.

What "freed from constraints" looks like in practice:

- **Peer discovery** that doesn't require UDP multicast or a bootstrap
  server with a public IP — because peers are found by key, and any
  link that delivers `notify_inbound_bytes` is sufficient to announce
  presence.
- **Path establishment** (the problem ICE solves) without IP:port
  candidates — because two peers that share any common carrier can
  reach each other without ever negotiating an IP address.
- **File transfer** that resumes across complete path changes — not
  just TCP reconnects, but carrier changes: the session was TCP, it
  migrated to IPC, it will finish over whatever link is available —
  because the session is `peer_pk`, not a socket descriptor.
- **Relay** that adds zero permanent infrastructure — a relay is just
  a handler plugin that forwards envelopes by `receiver_pk`; any node
  can be a relay, and the relay operator learns nothing because
  end-to-end identity is preserved through transit.
- **Routing** where the table is `key → key`, not `prefix → gateway` —
  because there are no IP prefixes. A DHT where nodes are keys, paths
  are connections, and the whole table works over any carrier.

The question to answer in one paragraph with your submission: **what
specifically could you not write this cleanly on TCP/IP, and why does
the GoodNet substrate remove that constraint?** Then the code.

What makes a weak submission: wrapping an existing IP-based protocol
behind a GoodNet handler. A TCP-over-GoodNet bridge is a bridge, not
a Track A entry.

Submission: open a PR to a new repo `goodnet-io/<plugin-kind>-<name>`.
Any plugin kind qualifies — link, handler, security, strategy, protocol,
or a multi-plugin combination. The only rule is that it must work over
at least two structurally different link plugins.

---

## Track B — Most unhinged carrier

The kernel is fully agnostic to how a link plugin moves bytes. It
only cares that `gn_link_api_t` is satisfied and
`notify_inbound_bytes` is eventually called with valid data.
"Eventually" is not time-bounded.

Build the most structurally compliant, physically absurd link plugin
that compiles on current `dev`.

Founding entries (from [issue #42](https://github.com/GoodNet-io/goodnet/issues/42)):

| Plugin | Medium | Throughput | Notable property |
|---|---|---|---|
| `link-astronomy-orion` | Betelgeuse magnitude variations | ~1 bit/century | RTT: 1,280 light-years |
| `link-powerline` | 230V AC wiring | 500 Mbit/s | MITM must share your circuit breaker |
| `link-thermal-printer` | 80mm receipt paper + camera | ~15 KB/s | Paper jam = packet loss, not disconnect |
| `link-git-commit` | git commit messages | ~5000 req/hr | Microsoft is an unknowing relay operator |

Submission rules:
- New repo `goodnet-io/link-<your-medium>`
- Full `gn_link_api_t` vtable implemented
- Compiles on current `dev` branch
- `notify_inbound_bytes` called with valid data — "eventually" is not time-bounded
- Performance requirements: none
- CI passing within any reasonable human timeframe: not required

---

## The ideal submission

A Track A plugin that uses a Track B carrier. A file transfer that
resumes over `link-astronomy-orion`. A peer discovery handler that
works over powerline. The combination makes the architectural point
without a single word of explanation: the protocol is correct, the
carrier is absurd, and the kernel didn't notice the difference.

---

## No deadlines. No jury.

The submissions speak for themselves.
