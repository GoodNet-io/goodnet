# Contract: Heartbeat handler

**Status:** active · v1
**Owner:** `plugins/handlers/heartbeat/`
**Last verified:** 2026-05-18
**Stability:** v1.x; wire envelope shape is locked (`kFlagPing`,
              `kFlagPong`, 21-byte fixed header). The extension
              vtable (`gn_heartbeat_api_t`) grows through
              size-prefix evolution per `abi-evolution.en.md` §3.

---

## 1. Purpose

A two-way liveness + RTT + STUN-on-the-wire handler. The plugin:

- exchanges PING / PONG envelopes on `msg_id = 0x10`
  ([`system-handlers.en.md`](system-handlers.en.md) §2),
- records the per-connection RTT from the PONG arrival time,
- reflects the peer's observed external endpoint in the PONG
  payload (no separate STUN server),
- exposes aggregate stats + per-conn lookups through the
  `gn.heartbeat` extension surface for in-process consumers.

Strategy plugins (notably `gn.strategy.rtt-optimal`) read the
per-conn RTT to drive multi-path picks. NAT-traversal layers
read the observed endpoint to learn the public address the peer
sees without standing up an external STUN server.

The handler is reactive only — it answers inbound PINGs with
PONGs. Periodic PING emission is left to the consumer (typically
a small operator-side service that pings every live peer at the
configured interval).

---

## 2. Surface

### 2.1 Extension vtable

```c
const void* vt = NULL;
gn_result_t r = host_api->query_extension_checked(
    host_ctx, GN_EXT_HEARTBEAT, GN_EXT_HEARTBEAT_VERSION, &vt);
if (r != GN_OK) return r;
const gn_heartbeat_api_t* api = (const gn_heartbeat_api_t*)vt;

gn_heartbeat_stats_t stats{};
api->get_stats(api->ctx, &stats);   // peer_count + min/avg/max RTT
```

Three function slots:

| Slot | Returns | Notes |
|---|---|---|
| `get_stats(out)` | 0 on success, -1 if `out == NULL` | populates aggregate counters across every peer with at least one PONG observed |
| `get_rtt(conn, out_rtt_us)` | 0 on success, -1 if conn unknown or no PONG yet | value carried by the most recent PONG arrival |
| `get_observed_address(conn, out_buf, buf_size, out_port)` | 0 on success, -1 if conn unknown / no PONG / buf too small | peer's view of the local node's external endpoint, NUL-terminated; truncation leaves the buffer NUL-terminated at the cut |

Plus the `api_size` size-prefix, `ctx` pointer, and `_reserved[4]`
ABI footer.

### 2.2 Wire surface

One envelope on `msg_id = 0x10` under `protocol_id = "gnet-v1"`.
Plugin-registerable; inject-boundary blocked (a bridge plugin
cannot spoof a PING/PONG onto a connection it does not own).

The payload is a fixed 88-byte big-endian frame
(`kPayloadSize = 88`):

| offset | size | field |
|---|---|---|
| 0 | 8 | `timestamp_us` (u64 BE — PING sender's wall-clock, echoed in PONG for RTT) |
| 8 | 4 | `seq` (u32 BE — caller-supplied sequence, echoed back in PONG) |
| 12 | 1 | `flags` (`0x00 = PING`, `0x01 = PONG`) |
| 13 | 3 | reserved (zero) |
| 16 | 64 | `observed_addr` (UTF-8 NUL-terminated address string; empty on PING, populated on PONG, `kObservedAddrBytes = 64`) |
| 80 | 2 | `observed_port` (u16 BE — empty on PING, populated on PONG) |
| 82 | 6 | reserved (zero) |

Layout details live in `plugins/handlers/heartbeat/heartbeat.{hpp,cpp}`
(`HeartbeatPayload`, `kFlagPing`, `kFlagPong`, `kPayloadSize`,
`kObservedAddrBytes`, `serialize_payload`, `parse_payload`).

---

## 3. RTT measurement

The PING sender writes the current wall-clock into `ping_send_us`
before transmission. The receiver echoes the field unchanged in
the PONG payload. The sender computes `rtt_us = now_us -
ping_send_us` on PONG arrival.

The handler stores the RTT per-connection in its internal map
keyed on `gn_conn_id_t`. The map drops the entry when the
connection's `GN_CONN_EVENT_DISCONNECTED` fires (the plugin
subscribes to `subscribe_conn_state` at registration). Strategy
plugins reading through `get_rtt` see the latest value or `-1`
if the conn either has no PONG yet or has already disconnected.

The plugin does NOT smooth RTT (no EWMA, no jitter calculation).
Consumers that want smoothing — notably the
`gn.strategy.rtt-optimal` plugin — apply their own filter on the
raw value `get_rtt` returns. The kernel's own RTT accounting
(`host_api->notify_rtt_sample` + the `gn_path_sample_t::rtt_us`
field) IS smoothed; the two surfaces serve different consumers.

---

## 4. STUN-on-the-wire

The PONG payload carries the receiver's view of the PING
sender's `(address, port)` after the underlying link plugin has
parsed it from the carrier socket. The format is the canonical
IP literal string the link advertises (`192.0.2.1`,
`[2001:db8::1]`, `[::ffff:192.0.2.1]` for v4-mapped) plus the
port in the parallel `observed_port` field.

This gives NAT-traversal layers a STUN-equivalent observation
without a separate STUN server: dial a known peer, send a PING,
the PONG comes back carrying the public `(addr, port)` the peer
saw. The reflected endpoint is unauthenticated — the receiver
must combine it with attestation or out-of-band verification
before trusting it as a fact about its own NAT footprint.

The handler reads the observed endpoint via the kernel's
`host_api->get_endpoint(conn, &out)` slot ([`host-api.en.md`](host-api.en.md)
§Iteration) at PING-receive time and writes it into the PONG
payload before reply.

---

## 5. Liveness semantics

The handler is **reactive** — it does not emit periodic PINGs on
its own. A deployment that wants liveness probing wires a small
operator-side service (a timer in `gn_core_t::set_timer` or a
companion plugin) that walks `for_each_connection` and emits
`host_api->send(conn, 0x10, ping_payload, len)` at the desired
period. The handler responds; consumers read RTT through the
extension surface.

There is no "miss count" or "disconnect on N missed PINGs" logic
inside the plugin. That policy belongs in the periodic-PING
emitter, which can call `host_api->disconnect(conn)` when its
own counter trips. Keeping the policy outside the handler lets
different deployments tune the cadence without forking the plugin.

`GN_CONN_EVENT_DISCONNECTED` evicts the conn from the per-conn
RTT / observed-address maps so a stale entry does not survive
into the next session with the same peer.

---

## 6. Cooperative shutdown

The handler subscribes to `is_shutdown_requested` via the kernel's
shutdown signal. On a shutdown poll returning true, the handler
stops re-arming any per-conn timers (if a future variant adds
them) and the next inbound PING returns the canned PONG without
spawning new work.

---

## 7. Cross-references

- SDK header: [`sdk/extensions/heartbeat.h`](../../sdk/extensions/heartbeat.h)
- Plugin source: [`plugins/handlers/heartbeat/`](../../plugins/handlers/heartbeat/)
- Reserved msg_id table: [`system-handlers.en.md`](system-handlers.en.md) §2
- Handler registration contract: [`handler-registration.en.md`](handler-registration.en.md)
- Strategy consumer (RTT-optimal): [`strategy.en.md`](strategy.en.md)
- Conn-event channel (`DISCONNECTED` eviction): [`conn-events.en.md`](conn-events.en.md)
