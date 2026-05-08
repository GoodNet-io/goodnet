# Contract: Link Layer

**Status:** active · v1
**Owner:** `plugins/links/*`
**Last verified:** 2026-04-28
**Stability:** v1.x; new links plug in without changing this contract.

---

## 1. Purpose

Links move bytes. They do not interpret payloads, do not authenticate
peers (security plugins do that), and do not route messages (the kernel
does that). The contract here pins the C ABI surface, the lifetime model,
the TrustClass declaration responsibilities, and the write-serialisation
guarantee.

The kernel multiplexes many links concurrently — TCP, UDP, IPC, BLE,
BT, WS, ICE, future QUIC. Each implements `gn_link_vtable_t`; the
kernel sees them as interchangeable byte movers identified by a URI scheme.

---

## 2. C ABI

Declared in `sdk/link.h`. Slot list:

| Slot | Direction | Notes |
|---|---|---|
| `scheme(self)` | plugin → kernel | stable lowercase scheme name; `"tcp"`, `"udp"`, `"ws"` |
| `listen(self, uri)` | kernel → plugin | begin accepting connections matching scheme |
| `connect(self, uri)` | kernel → plugin | initiate outbound; link calls back via `host_api->notify_connect` once handshake completes |
| `send(self, conn, bytes, size)` | kernel → plugin | bytes `@borrowed` for the call |
| `send_batch(self, conn, batch, count)` | kernel → plugin | scatter-gather over `gn_byte_span_t batch[count]`; link may use `writev`-style internal multiplex |
| `disconnect(self, conn)` | kernel → plugin | idempotent; second call returns `GN_OK` no-op |
| `extension_name(self)` | plugin → kernel | per-link extension surface, e.g. `"gn.link.tcp"` (see §8) |
| `extension_vtable(self)` | plugin → kernel | extension vtable for stats / runtime tweaks |
| `destroy(self)` | kernel → plugin | called once after `unregister_link` and quiescence |

The vtable starts with `uint32_t api_size` per `abi-evolution.md` §3.

---

## 3. TrustClass declaration

The link **must** call `host_api->notify_connect` with an explicit
`gn_trust_class_t` computed from observable connection properties per
`security-trust.md` §3:

| Connection property | Declared TrustClass |
|---|---|
| AF_UNIX socket | `Loopback` |
| Peer address `127.0.0.1` / `::1` | `Loopback` |
| Public TCP / UDP address | `Untrusted` |
| Intra-process pipe between two plugins | `IntraNode` |

After a security handshake completes, the kernel may upgrade
`Untrusted → Peer`. Links never declare anything stronger than
`Peer`; the upgrade path is the kernel's responsibility.

A link on a loopback path **must** declare `Loopback` regardless
of any opt-in flag in the security configuration; the trust class is
what lets the kernel permit `null+raw` stacks per
`security-trust.md` §4.

A link plugin that accepts hostname URIs runs the resolution
through `dns.md` §2's `resolve_uri_host` at `connect` /
`listen` time. Per `dns.md` §1a the operator-facing recommendation
is to pre-resolve hostnames before configuring the kernel —
production deployments should hand IP literals through; the
hostname path is for dev / test convenience and inherits the OS
resolver's adversarial-DNS exposure.

## 3a. Handshake role declaration

The link **must** declare a `gn_handshake_role_t` on every
`notify_connect`:

| Origin | Declared role |
|---|---|
| Outbound — link's `connect(uri)` returned successfully | `GN_ROLE_INITIATOR` |
| Inbound — accepted on the listen socket | `GN_ROLE_RESPONDER` |

The kernel propagates this to `security_provider->handshake_open` so
the asymmetric handshake state machine drives the correct side of the
pattern. Misreporting the role is a contract violation: a Noise XX
initiator that thinks it is the responder will fail every handshake
silently and produce no actionable diagnostic.

---

## 4. Single-writer invariant on send

**At most one task may be writing to a given underlying socket at a
time.** Concurrent writes to the same socket produce interleaved bytes
on the wire; the contract serialises them so that every link
implementation observes single-writer semantics.

What "task" means is language-specific:

- a thread, or
- an asynchronous coroutine, or
- a single-task executor / strand / actor mailbox / channel reader.

The contract is on the observable behaviour: the operating system never
sees two `send`-class syscalls for the same socket-FD overlapping. How
the language enforces it (mutex, single-task ownership, message-queue
serialisation) is internal to the implementation.

For application-driven sends, the kernel-side `SendQueueManager`
already provides single-writer guarantees on top of the link: at
most one drainer per connection runs at a time, gated by
`PerConnQueue::drain_scheduled` CAS, so `send` / `send_batch` calls
arriving at the link from `host_api->send` never overlap. Link
implementations still **must** uphold the invariant for paths the
kernel does not drive — peer-initiated control replies (WebSocket
pong, graceful close echo per `backpressure.md` §3.1), TLS
renegotiation, link-internal keep-alive — because those go through
the same socket-FD without crossing the kernel queue. A link that
fans out application sends through extra worker threads on top of
the queue must serialise them on its own strand.

The same invariant applies to `send_batch`: the batched scatter-gather
list is one logical write; it may not interleave with other sends on
the same connection.

Reads have no such requirement; a single OS-level reader is the natural
model and no contract is needed.

---

## 5. Async lifetime through reference-counted ownership

Per `plugin-lifetime.md` §4, every async task posted by the link
captures a weak observer of the link's reference-counted handle
and upgrades to a strong reference before dereferencing link
state. A failed upgrade — the last strong reference was dropped — is
a clean no-op exit. Sites that need the check:

| Site | Required |
|---|---|
| async-read completion | yes — may fire after `disconnect` was posted |
| async-write completion | yes |
| reconnect timer | yes |
| idle timer | yes |
| peer-discovery callback (BLE / BT / ICE) | yes |
| synchronous constructor / destructor | no |

The link never captures a raw pointer to itself in an async
context. Captured strong references kept beyond the synchronous
boundary defeat the contract — they keep the link alive past its
intended lifetime.

---

## 6. Link registration

Links register through the universal `register_vtable` slot in
`host_api_t`; see `host-api.md` §2 for the canonical signature.
The link-specific shape:

- `kind = GN_REGISTER_LINK`
- `meta->name`        — URI scheme (e.g. `"tcp"`, `"udp"`, `"ws"`)
- `meta->msg_id`      — ignored
- `meta->priority`    — ignored
- `meta->protocol_id` — `@borrowed` for the call. Declares the
  mesh-framing layer this link's connections route through per
  `protocol-layer.en.md` §4. NULL or empty selects the kernel
  default `gnet-v1`. The kernel resolves the id against the
  `ProtocolLayerRegistry` at `notify_connect` time; an
  unregistered id surfaces the connect-side trust-mask gate as
  permissive (no layer, no mask) and the connection is
  accepted, then the dispatch sites (`send`,
  `notify_inbound_bytes`, `inject`) return `GN_ERR_NOT_IMPLEMENTED`
  on first use. Operators that want the connect to fail loudly
  on a missing layer register the layer before
  `notify_connect` ever fires.
- `vtable`            — `const gn_link_vtable_t*`
- `self`              — per-link instance state, opaque to the kernel
- `*out_id`           — populated on success; encodes the
  `GN_REGISTER_LINK` tag in its top 4 bits so a later
  `unregister_vtable(id)` routes back to `LinkRegistry`
  without naming the kind a second time.

Rules from `host-api.md` §2 apply:

- Only inside `gn_plugin_register` (phase 5 per `plugin-lifetime.md` §2).
- `scheme` is unique across loaded links; duplicate scheme returns
  `GN_ERR_LIMIT_REACHED`.
- `vtable` is `@borrowed` for the lifetime, valid until
  `unregister_vtable(id)` returns.

A plugin may register multiple schemes through multiple calls. Pre-RC
convention is to fold IPv6 into a single `tcp` scheme — the URI carries
the address (`tcp://[::1]:9000`).

The pure-C convenience wrapper `gn_register_link` in
`sdk/convenience.h` keeps the historical 5-argument shape and
expands to `register_vtable(GN_REGISTER_LINK, &meta, …)`.

---

## 7. ConnectionContext accessors

The protocol-layer plugin reads connection state through helper
functions declared in `sdk/connection.h`. The C ABI surface:

| Function | Returns |
|---|---|
| `gn_ctx_local_pk(ctx)` | borrowed pointer to local node pk (32 bytes) |
| `gn_ctx_remote_pk(ctx)` | borrowed pointer to peer pk (32 bytes) |
| `gn_ctx_conn_id(ctx)` | `gn_conn_id_t` |
| `gn_ctx_trust(ctx)` | `gn_trust_class_t` |
| `gn_ctx_plugin_state(ctx)` | opaque per-plugin scratch slot |
| `gn_ctx_set_plugin_state(ctx, ptr)` | set scratch slot |

These are stable across kernel minor versions. They are the only reads
the protocol layer performs on the context.

---

## 8. Per-link extensions

The `extension_name` and `extension_vtable` slots in §2 expose a
per-link extension surface. Every baseline link publishes
the same shape under the convention prefix `gn.link.<scheme>`
— `gn.link.tcp`, `gn.link.udp`, `gn.link.ipc`. The
shape is declared in `sdk/extensions/link.h` as
`gn_link_api_t` together with capability flags
(`GN_LINK_CAP_*`), counter struct `gn_link_stats_t`, and
the receive-callback type `gn_link_data_callback_t`.

`gn_link_api_t` carries every slot needed for an L2-over-L1
composition (WSS-over-TCP, TLS-over-TCP, ICE-over-UDP):

| Group | Slot | Direction | Notes |
|---|---|---|---|
| Steady | `get_stats` | producer → consumer | snapshot of monotonic counters |
| Steady | `get_capabilities` | producer → consumer | static descriptor; cache once |
| Steady | `send` / `send_batch` | consumer → producer | bytes on a kernel-managed `gn_conn_id_t` |
| Steady | `close` | consumer → producer | idempotent; same shape as `disconnect` |
| Composer | `listen` | consumer → producer | bind without engaging `notify_connect` |
| Composer | `connect` | consumer → producer | open an L1 conn whose lifecycle the consumer owns |
| Composer | `subscribe_data` / `unsubscribe_data` | consumer → producer | install a pull-style receive callback for L2 framing |

Steady slots are functional in every baseline plugin in v1.0.x. The
composer slots are reserved for the L2 family — WSS, TLS, ICE — and
return `GN_ERR_NOT_IMPLEMENTED` on baseline links until the
first L2 composer plugin lands and the contract is exercised
end-to-end. Implementations always provide every slot pointer;
unimplemented behaviour surfaces through the return code, never
through a NULL slot.

The plugin returns its `(name, vtable)` pair from the two
`extension_*` slots in §2; the kernel publishes them through
`register_extension`. Consumers query through
`query_extension_checked(name, version, &out_vtable)` per
`host-api.md` §2 and call `unregister_extension(name)` to release.

Capability flags (low byte values, OR-able):

| Flag | Meaning |
|---|---|
| `GN_LINK_CAP_STREAM` | unframed byte stream; consumer imposes message boundaries |
| `GN_LINK_CAP_DATAGRAM` | OS preserves each `send` as one delivery |
| `GN_LINK_CAP_RELIABLE` | OS-level reliability (retransmit + ack) |
| `GN_LINK_CAP_ORDERED` | OS-level ordering across the connection |
| `GN_LINK_CAP_ENCRYPTED_PATH` | producer asserts the wire bytes are already encrypted |
| `GN_LINK_CAP_LOCAL_ONLY` | producer refuses public addresses regardless of URI |

Baseline assignments: TCP and IPC publish `Stream | Reliable |
Ordered`; IPC adds `LocalOnly`. UDP publishes `Datagram` and a
non-zero `max_payload` that mirrors the configured MTU. Composer
plugins (WSS, TLS) compose by ORing into the producer's flags.

---

## 9. Shutdown release

A link's own shutdown path **must** fire `host_api->notify_disconnect`
synchronously for every session that was published through
`notify_connect`, before tearing down the executor that owns the
session strands. Asynchronously-posted close handlers are dropped
when the executor stops, so any cleanup that relied on a pending
strand-bound continuation (the read-completion path, idle timers,
reconnect timers) never runs once the io_context is stopped.

The set of ids on which shutdown emits is the set of all ids the
link ever published through `notify_connect`, not the set still
live in the link's session map. A worker callback that observed
EOF before shutdown started has already fired its own
`notify_disconnect` on the worker thread; the kernel resolves the
second emit through `GN_ERR_NOT_FOUND` without re-firing
`DISCONNECTED`, so the caller-thread emit on shutdown is benign
for already-disconnected sessions and required for those still
live.

The canonical sequence inside a baseline link's `shutdown`:

1. Close the acceptor.
2. Take the sessions lock and atomically: latch the shutdown
   flag, drain the append-only published-ids list, close every
   live session's socket, clear the live session map. The
   ordering inside one critical section blocks worker callbacks
   from racing past the flag check, and draining the published
   ids preserves the kernel-observable release for sessions a
   worker callback already removed from the live map.
3. Walk the drained ids and call `host_api->notify_disconnect(
   host_ctx, id, GN_OK)` for every id while still on the
   shutdown caller's thread.
4. Stop the executor and join the worker thread.

Implementation pattern lives in
[`docs/impl/cpp/concurrency.md`](../impl/cpp/concurrency.ru.md).

Without step 3 the kernel-side `ConnectionRegistry` keeps the
records past link shutdown. Per `plugin-lifetime.md` §4 those
records hold the security plugin's lifetime anchor —
`PluginManager::drain_anchor` then blocks for the full quiescence
budget while the anchor refuses to expire, and the manager logs
a leak warning rather than completing the unload cleanly.

`disconnect(conn)` keeps its async semantics — a single peer
walk-out continues to drain through the strand. The synchronous
release applies only to whole-link shutdown, where the executor
is about to disappear.

---

## 10. Cross-references

- Plugin lifetime + liveness probe rules: `plugin-lifetime.md`.
- TrustClass policy: `security-trust.md`.
- Connection registration semantics: `registry.md`.
- Host API entries used: `host-api.md` §2.
- Extension query semantics: `host-api.md` §2 (`query_extension_checked`).
