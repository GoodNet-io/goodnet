# Contract: Connection Events

**Status:** active · v1
**Owner:** `core/kernel`, every plugin that observes connection state
**Last verified:** 2026-04-28
**Stability:** v1.x; the event-kind enum grows additively at the tail.

---

## 1. Purpose

Plugins that need to react to connection lifecycle changes — relay
handler reaping its forwarding tables when a peer drops, autonat
re-running its probe when a fresh connection is made, a metrics
plugin counting per-event totals — observe a kernel-fanned signal
channel rather than poll the registry.

The kernel publishes one event whenever a connection changes
status it considers worth surfacing: connected, disconnected, the
one-way trust upgrade from `Untrusted` to `Peer`, and the
backpressure soft / clear watermarks once the send-queue layer
emits them.

The same channel also enables `for_each_connection` (synchronous
iteration over the registry under a brief read lock), which closes
the observability gap of "what is currently connected" without
forcing every plugin to maintain a parallel set.

---

## 2. Event kinds

```c
typedef enum gn_conn_event_kind_e {
    GN_CONN_EVENT_CONNECTED            = 1,
    GN_CONN_EVENT_DISCONNECTED         = 2,
    GN_CONN_EVENT_TRUST_UPGRADED       = 3,
    GN_CONN_EVENT_BACKPRESSURE_SOFT    = 4,
    GN_CONN_EVENT_BACKPRESSURE_CLEAR   = 5,
} gn_conn_event_kind_t;

typedef struct gn_conn_event_s {
    uint32_t              api_size;       /* sizeof(gn_conn_event_t) */
    gn_conn_event_kind_t  kind;
    gn_conn_id_t          conn;
    gn_trust_class_t      trust;          /* current trust at the event */
    uint8_t               remote_pk[GN_PUBLIC_KEY_BYTES];
    uint64_t              pending_bytes;  /* used by BACKPRESSURE_* */
    void*                 _reserved[4];
} gn_conn_event_t;
```

Semantics:

- `CONNECTED` — fired by `notify_connect`. `remote_pk` may be all-
  zero when the responder side has not yet observed a public key
  through the security handshake.
- `DISCONNECTED` — fired by `notify_disconnect`. The kernel has
  already removed the conn from its registry by the time
  subscribers run.
- `TRUST_UPGRADED` — fired when a connection transitions from
  `Untrusted` to `Peer` (see `security-trust.md` §3 one-way upgrade).
- `BACKPRESSURE_SOFT` — fired when a transport's send-queue
  crosses `pending_queue_bytes_high` (see
  `limits.md` §6, future `backpressure.md`). Subscribers should
  slow down their producers; the kernel does not enforce.
- `BACKPRESSURE_CLEAR` — fired when the queue drops below
  `pending_queue_bytes_low`.

The `BACKPRESSURE_*` event kinds are reserved at v1.0 but emit only
once the send-queue layer ships (Phase 5.C). Until then no plugin
will observe them; consumers can still subscribe and the channel
ignores never-fired kinds.

`pending_bytes` carries the current queued byte count for the
backpressure events; ignored (zero) for the lifecycle kinds.

---

## 3. Subscription model

```c
typedef void (*gn_conn_event_cb_t)(void* user_data,
                                    const gn_conn_event_t* event);

typedef uint64_t gn_subscription_id_t;
#define GN_INVALID_SUBSCRIPTION_ID ((gn_subscription_id_t)0)

gn_result_t (*subscribe_conn_state)(void* host_ctx,
                                     gn_conn_event_cb_t cb,
                                     void* user_data,
                                     gn_subscription_id_t* out_id);

gn_result_t (*unsubscribe_conn_state)(void* host_ctx,
                                       gn_subscription_id_t id);
```

Every subscription carries a weak observer of the calling plugin's
quiescence sentinel (`plugin-lifetime.md` §4); a callback whose
plugin already unloaded is dropped silently. `unsubscribe` is
idempotent — calling on an already-removed id returns `GN_OK`.

Subscribers run on the **publishing thread** — typically the
transport's strand for `CONNECTED` / `DISCONNECTED`, the kernel's
service executor for trust upgrades, the transport's strand again
for backpressure events. Subscribers must be cheap; long work is
posted back through `host_api->post_to_executor`
(`timer.md` §2).

Re-entry is permitted: a callback may call `subscribe_conn_state`
or `unsubscribe_conn_state` against the same channel without
deadlocking. The channel snapshots subscribers under a shared
lock and fires outside the lock (`signal_channel.hpp` semantics).

---

## 4. Iteration

```c
typedef int (*gn_conn_visitor_t)(void* user_data,
                                  gn_conn_id_t conn,
                                  gn_trust_class_t trust,
                                  const uint8_t remote_pk[GN_PUBLIC_KEY_BYTES],
                                  const char* uri);

gn_result_t (*for_each_connection)(void* host_ctx,
                                    gn_conn_visitor_t visitor,
                                    void* user_data);
```

Visitor returns `0` to continue iteration, non-zero to stop.
Iteration takes a per-shard read lock; the visitor must not block
or call back into `register/unregister` paths on the same kernel
instance (it would deadlock against the shard lock). For long-
running side effects, snapshot ids inside the visitor, return,
then process the snapshot outside.

`uri` lives in the kernel's connection record and is borrowed for
the duration of the visitor call only — copy if retained.

---

## 5. Ordering and dropped events

- The channel is fire-and-forget: a subscriber that throws or
  blocks does not cause re-delivery.
- Multiple subscribers see events in subscription order.
- The kernel does not enforce a global event order across
  connections; events from one conn arrive in their natural
  causal order (connect before disconnect), but events from two
  different conns can interleave arbitrarily.

The channel does **not** guarantee at-least-once delivery: an
event published before a subscriber's `subscribe` call is missed.
Plugins that need a complete picture of current state subscribe
**then** call `for_each_connection` to bootstrap.

---

## 6. Error returns

| Slot | `GN_OK` | `GN_ERR_NULL_ARG` | `GN_ERR_LIMIT_REACHED` |
|---|---|---|---|
| `subscribe_conn_state` | subscribed | host_ctx / cb / out_id null | per-kernel cap exceeded |
| `unsubscribe_conn_state` | removed or already gone | host_ctx null, id == `GN_INVALID_SUBSCRIPTION_ID` | — |
| `for_each_connection` | iteration ran | host_ctx / visitor null | — |

The subscription cap defaults to `gn_limits_t::max_extensions` —
the same registry pool that bounds extension entries. A plugin
must not subscribe more than once per topic; the typical pattern
is one subscription per plugin instance.

---

## 7. Cross-references

- Quiescence anchor: `plugin-lifetime.md` §4.
- Service executor for deferred work: `timer.md`.
- Trust upgrade rule: `security-trust.md` §3.
- Backpressure watermarks: `limits.md` §6 (future
  `backpressure.md`).
