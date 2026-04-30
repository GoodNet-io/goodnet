# Contract: Backpressure

**Status:** active · v1
**Owner:** every transport plugin, `core/registry/connection`,
plugins that push bytes through `host_api->send`
**Last verified:** 2026-04-28
**Stability:** v1.x; watermark thresholds are configuration-driven
and additive event kinds extend `conn-events.md` at the tail.

---

## 1. Purpose

A producer that hands bytes to a transport faster than the
underlying socket drains them must be told to slow down. Without a
contract a slow peer turns into unbounded RAM growth (the kernel
copies every payload into the transport's strand-local write
queue) and eventually OOM. This contract pins the per-connection
queue cap, the soft / clear watermark signal, and the producer's
obligation to honour backpressure.

Three observable layers, in order from immediate to advisory:

1. **Hard cap.** The transport refuses additional bytes once the
   per-connection write queue holds more than
   `gn_limits_t::pending_queue_bytes_hard` bytes. `host_api->send`
   returns `GN_ERR_LIMIT_REACHED`; the producer chooses whether to
   drop, retry, or surface upstream.
2. **Soft watermark.** When the queue crosses
   `pending_queue_bytes_high`, the kernel publishes a
   `GN_CONN_EVENT_BACKPRESSURE_SOFT` event on the
   connection-event channel (`conn-events.md` §2). The signal is
   advisory — `send` keeps succeeding — but producers that ignore
   it walk into the hard cap.
3. **Clear watermark.** When the queue drops back below
   `pending_queue_bytes_low`, the kernel publishes
   `GN_CONN_EVENT_BACKPRESSURE_CLEAR`. Hysteresis between
   `low` and `high` keeps the signal from oscillating on a busy
   connection.

The default thresholds (`limits.md` §2) are 256 KiB low /
1 MiB high / 4 MiB hard. Operators tune the trio per deployment;
the cross-field invariant `0 < low < high ≤ hard` is enforced at
`Config::validate` (`limits.md` §3). `low == 0` is rejected
because the falling-edge `BACKPRESSURE_CLEAR` publisher fires on
`bytes_buffered < low` — with `low == 0` the inequality is never
satisfied and subscribers stay paused after the first soft
signal forever.

---

## 2. Per-connection accounting

Every transport that owns a write queue maintains an atomic
`bytes_buffered` counter — bytes enqueued for send but not yet
consumed by `async_write`. The accounting rules are:

- **enqueue** (`do_send` / `do_send_batch`): add the payload size
  before pushing onto the queue.
- **drain** (write completion handler): subtract the payload size
  once the OS-level write returns.
- **clear** (session shutdown): reset to zero.

The counter is thread-local to the transport's strand and
published through the per-transport extension's `get_stats`
(`transport.md` §8) **and** through the connection-event payload
(`conn-events.md` §2 `pending_bytes` field) when a watermark
event fires.

---

## 3. Send-path flow

```
host_api->send(conn, bytes)
  └── transport.send(conn, bytes)
       │
       │   [check hard cap]
       │   if bytes_buffered + bytes > pending_queue_bytes_hard:
       │       return GN_ERR_LIMIT_REACHED
       │
       │   bytes_buffered += bytes
       │   write_queue.push(bytes)
       │
       │   [check soft watermark — only on rising edge]
       │   if !soft_signaled && bytes_buffered > pending_queue_bytes_high:
       │       fire(BACKPRESSURE_SOFT, pending_bytes = bytes_buffered)
       │       soft_signaled = true
       │
       │   maybe_start_write()

drain (async_write completion)
  └── bytes_buffered -= written
       │
       │   [check clear watermark — only on falling edge]
       │   if soft_signaled && bytes_buffered < pending_queue_bytes_low:
       │       fire(BACKPRESSURE_CLEAR, pending_bytes = bytes_buffered)
       │       soft_signaled = false
```

`soft_signaled` is per-connection state inside the transport's
session record. The single rising / falling edge model suppresses
duplicate signals while the queue oscillates inside the
hysteresis band.

### 3.1 Transport-internal control replies

A transport that replies to peer-initiated control frames (for
example WebSocket pong in response to ping, or a graceful close
echo) shares the per-connection hard-cap budget. The reply path
runs the same cap check as `send`:

```
on peer-initiated control frame:
  reply_size = bytes_of(reply_frame)
  if pending_queue_bytes_hard != 0
     and bytes_buffered + reply_size > pending_queue_bytes_hard:
      disconnect the connection                  # control-flood abuse
  else:
      bytes_buffered += reply_size
      write_queue.push(reply_frame)
```

A control flood — for instance a peer issuing pings faster than the
local socket drains pong replies — is treated as abuse rather than
production traffic. Replying past the cap is a per-RAM amplifier;
disconnect ends the buffer growth and the peer reconnects if the
flood was unintentional. Application data submitted through
`host_api->send` continues to receive `GN_ERR_LIMIT_REACHED` on the
same edge, per §3.

Locally-initiated control frames — for example a host-side
`disconnect` that emits a graceful close — follow the same
drop-on-overflow rule. The frame is omitted when the queue is at
the cap; the socket teardown that follows carries the closure
regardless. Producers do not observe a distinct error for the
dropped echo because the connection terminates anyway.

---

## 4. Producer obligations

A plugin pushing bytes through `host_api->send` **must**:

- Treat `GN_ERR_LIMIT_REACHED` as a real failure, not a transient
  retry — a busy queue means the peer or the network is slow.
  Looping on retry without backoff is a §8 violation in
  `plugin-lifetime.md`.
- Subscribe to `subscribe_conn_state` and react to
  `GN_CONN_EVENT_BACKPRESSURE_SOFT` by pausing fresh enqueues
  for that connection until `BACKPRESSURE_CLEAR` arrives. The
  event is advisory; the kernel does not enforce.
- Keep its own buffering bounded. A plugin that buffers
  upstream of `host_api->send` re-creates the very problem this
  contract closes.

A plugin that explicitly opts out of backpressure (a real-time
voice transport that prefers drop over delay) routes through a
custom `gn.transport.<scheme>` extension's composer slots and
manages its own queue with its own policy. The baseline send path
is the cap-enforcing path.

---

## 5. Datagram transports

UDP and similar datagram transports observe backpressure
**only** at the OS-level send buffer. There is no application
write queue in the v1 baseline UDP transport
(`plugins/transports/udp/`); the kernel-level `send` issues an
immediate `sendto` and the kernel reports `GN_ERR_LIMIT_REACHED`
when the OS reports `EAGAIN` / `EWOULDBLOCK`.

The watermark events are not fired for datagram transports — the
contract is irrelevant when there is no growable queue. A future
QoS layer may attach a per-conn token bucket and fire the events
through it; that lands as a separate spec.

---

## 6. Resource bounds

The watermark trio comes from `gn_limits_t::pending_queue_*`
(`limits.md` §2). The kernel reads them once at startup and the
transport copies them to its session state on accept / connect.
Reload requires kernel restart; transports do not re-read mid-life.

Per-process aggregate caps (e.g. summed `bytes_buffered` across
every connection) are not part of v1.0. A transport that needs a
process-level governor adds it in its own
`gn.transport.<scheme>` extension surface.

---

## 7. Cross-references

- Watermark trio + cross-field validation: `limits.md` §2-§3.
- Event kinds + subscription: `conn-events.md` §2-§3.
- Transport ownership of the write queue: `transport.md` §4.
- Quiescence anchor on event subscriptions: `plugin-lifetime.md`
  §4.

---

## 8. Handshake-phase pending queue

Application data submitted through `host_api->send` while the
connection's `SecuritySession` is still in `Handshake` phase
(`security-trust.md` §3) cannot be encrypted yet — the transport
keys have not been derived. The kernel buffers each framed
plaintext on a per-session pending queue and drains it once the
session reaches `Transport`.

### Cap

`gn_limits_t::pending_handshake_bytes` (default `256 KiB`) caps
the sum of buffered plaintext per connection. Once the cap would
be exceeded, `host_api->send` returns `GN_ERR_LIMIT_REACHED`. A
zero value disables the cap; the reference build wires
`Config::limits` through `limits.md` §2.

### Drain

After every `advance_handshake` call that transitions the session
to `Transport`, the kernel:

1. Resolves the transport vtable for the connection's scheme. If
   the lookup fails (transport plugin unregistered between
   enqueue and drain), the kernel leaves the pending queue
   intact; `SecuritySession::close()` releases it on disconnect
   so producers see a single `GN_CONN_EVENT_DISCONNECTED`
   instead of a silent mid-drain drop.
2. Atomically takes the queued plaintexts via
   `SecuritySession::take_pending()`.
3. Encrypts each one through `encrypt_transport`.
4. Pushes the ciphertext through the resolved transport's `send`
   slot in arrival order, accounting `add_outbound` per byte that
   leaves.

The drain happens both on the responder's first inbound run (the
`notify_inbound_bytes` path that completes XX / IK on the receive
half) and on the initiator's `kick_handshake` for IK-style
patterns that complete on the first message.

### Per-frame failure

A drain may fail mid-loop on either step 3 or step 4 — an
`encrypt_transport` error (provider out of memory, AEAD state
corrupt) or a transport hard-cap rejection
(`GN_ERR_LIMIT_REACHED`). The producer already received `GN_OK`
from `enqueue_pending`; once the AEAD nonce advances on the
first successful encrypt, partial completion is unrecoverable —
the kernel cannot roll the cipher state back to retry the
remaining plaintexts.

The contract: **disconnect the connection on any per-frame
failure during drain.** The peer observes
`GN_CONN_EVENT_DISCONNECTED`; subscribers retry on a fresh
session. Subsequent plaintexts in the same drain are dropped
when the session closes. This is louder than a silent mid-drain
drop and gives producers a single deterministic signal to
recover from.

### Drop on close

`SecuritySession::close()` clears the pending queue. A connection
that disconnects mid-handshake drops every buffered plaintext;
the producer observes the loss through
`GN_CONN_EVENT_DISCONNECTED` (`conn-events.md` §2) and is
responsible for retry semantics at its own layer.

### Why not the transport's queue

Routing handshake-phase plaintext through the transport's write
queue would require encrypting before keys exist — impossible —
or buffering raw application data on the transport, which is the
wrong layer (the transport must remain crypto-agnostic per
`transport.md` §1). The pending queue lives on the security
session because it is the only kernel object that observes both
phase transitions and the encryption primitives.
