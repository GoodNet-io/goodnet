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
- `DISCONNECTED` — fired by `notify_disconnect` when the call
  removes a real registry record. Full specification in §2a.
- `TRUST_UPGRADED` — fired when a connection transitions from
  `Untrusted` to `Peer` (see `security-trust.md` §3 one-way upgrade).
- `BACKPRESSURE_SOFT` — fired when a transport's send-queue
  crosses `pending_queue_bytes_high` (see `limits.md` §2 watermark
  rows and `backpressure.md` §3 for the rising-edge model).
  Subscribers should slow down their producers; the kernel does
  not enforce.
- `BACKPRESSURE_CLEAR` — fired when the queue drops below
  `pending_queue_bytes_low`.

The `BACKPRESSURE_*` event kinds are reserved at v1.0 but the
producer ships in `backpressure.md`. Subscribers register a single
callback that demultiplexes on `event->kind`; until the producer
fires those kinds, subscribers simply never see them.

`pending_bytes` carries the current queued byte count for the
backpressure events; ignored (zero) for the lifecycle kinds.

---

## 2a. `DISCONNECTED` — specification

**Producer.** `notify_disconnect(host_ctx, conn, reason)` is the
single legitimate publisher. No other host-API slot, no internal
cleanup path, and no plugin code constructs a DISCONNECTED event.

**Effect.** Drops the security session for `conn`, blocking
until any in-flight session handle has been released, then
removes the registry record for `conn` atomically with the
payload snapshot (`registry.md` §4a), then publishes one
DISCONNECTED event whose payload reflects the captured
pre-removal record state. Subscriber callbacks fire
synchronously on the calling thread before the call returns;
`GN_OK` means every subscriber registered before the registry
critical section started has been invoked exactly once. A
subscriber that registers after the publish does not receive a
synthetic re-delivery.

**Returns.**

| Status | Meaning | Side effects |
|---|---|---|
| `GN_OK` | record removed and event published | security session destroyed; record erased from all three keys (`registry.md` §1); every existing subscriber invoked once before return |
| `GN_ERR_NOT_FOUND` | no record matched `conn` at the moment the registry critical section started; also returned when `conn == GN_INVALID_ID` | session-destroy attempt is idempotent; no event published; no registry state changed |
| `GN_ERR_NULL_ARG` | `host_ctx == NULL` | none |
| `GN_ERR_NOT_IMPLEMENTED` | calling plugin's kind is not `GN_PLUGIN_KIND_TRANSPORT` (`sdk/plugin.h` `gn_plugin_kind_t`); `GN_PLUGIN_KIND_UNKNOWN` is permitted as a legacy carve-out for descriptors that predate the `kind` field | none |

No other return code is legal; an implementation that emits one
is non-conformant.

**`reason` parameter.** Reserved at v1: ignored by the kernel,
not surfaced to subscribers, not logged. All bit patterns are
legal at v1. Future versions may route it into the event payload
or a kernel-side log without an ABI break.

**Payload.**

| Field | Value |
|---|---|
| `kind` | `GN_CONN_EVENT_DISCONNECTED` |
| `conn` | the input `conn` |
| `trust` | the conn's trust class captured at removal |
| `remote_pk` | the last public key the security handshake observed for `conn`; all-zero on responders that completed the call before any handshake message arrived |
| `pending_bytes` | zero (used only by `BACKPRESSURE_*`) |
| `_reserved[*]` | zero |

The per-connection counters from `registry.md` §8 are not
surfaced through this event. Consumers that need them read
`get_endpoint` while the conn is alive; after removal, the conn
is gone by design and the counters with it.

**Concurrency.**

- Concurrent `notify_disconnect(_, conn, _)` against the same
  `conn`: at most one call returns `GN_OK` and publishes the
  event; the rest return `GN_ERR_NOT_FOUND` and publish
  nothing.
- Between the snapshot capture inside the registry critical
  section and the event publish, no other observer finds the
  record under any of the three keys (`registry.md` §1).
  Readers whose lookup completed before the critical section
  return their captured snapshot normally.
- A subscriber callback may invoke `notify_disconnect` against
  the same `conn` re-entrantly. The re-entrant call observes
  the record already removed and returns
  `GN_ERR_NOT_FOUND` without publishing a second event.

**Delivery.** Per §5 (Ordering and dropped events): one event
per real removal, fire-and-forget, no synthetic re-delivery for
subscribers that register after the publish.

---

## 3. Subscription model

```c
typedef void (*gn_conn_event_cb_t)(void* user_data,
                                    const gn_conn_event_t* event);

typedef uint64_t gn_subscription_id_t;
#define GN_INVALID_SUBSCRIPTION_ID ((gn_subscription_id_t)0)
/* Allocated ids are monotonically increasing starting at 1; 0 is
   reserved as the unset sentinel.  Reuse is structurally
   impossible across realistic kernel runtimes per
   signal-channel.md §3. */

gn_result_t (*subscribe_conn_state)(void* host_ctx,
                                     gn_conn_event_cb_t cb,
                                     void* user_data,
                                     gn_subscription_id_t* out_id);

gn_result_t (*unsubscribe_conn_state)(void* host_ctx,
                                       gn_subscription_id_t id);
```

Every subscription carries a weak observer of the calling plugin's
lifetime anchor (`plugin-lifetime.md` §4); a callback whose
plugin already unloaded is dropped silently. `unsubscribe` is
idempotent — calling on an already-removed id returns `GN_OK`.

Subscribers run on the **publishing thread**, which is **not the
same thread for every event kind**:

- `CONNECTED` / `DISCONNECTED` — the transport's strand (the same
  thread that called `notify_connect` / `notify_disconnect`).
- `TRUST_UPGRADED` — the thread that drove the security
  handshake completion (typically the transport's strand again,
  since the upgrade is fired from inside `notify_inbound_bytes`).
- `BACKPRESSURE_SOFT` / `BACKPRESSURE_CLEAR` — the transport's
  strand for the affected connection (`backpressure.md` §3).

A subscriber that maintains state across event kinds **must**
guard it with a lock or post every event through
`host_api->post_to_executor` (`timer.md` §2) to serialise
processing on the kernel's service executor. The kernel does not
synthesise a unified order across publishing threads.

Subscribers must be cheap; long work is posted back through
`post_to_executor`. Re-entry is permitted under the
`signal-channel.md` snapshot rule: a callback that calls
`subscribe_conn_state` or `unsubscribe_conn_state` while a fire
is in progress runs to completion against the snapshot taken
before the change — newly-added subscribers do not see the
in-flight event, newly-removed subscribers still see it.

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
Iteration takes a per-shard read lock; the visitor **must not
call any host_api slot that mutates the connection registry**
(`notify_connect`, `notify_disconnect`, `disconnect`,
`inject_external_message`, `inject_frame`) — every such slot
re-acquires the shard mutex and self-deadlocks. The visitor may
read counters off the record, copy the id / pk / uri, and append
to its own scratch storage. For everything else (sending,
subscribing, scheduling timers), snapshot ids inside the visitor,
return, then post-process the snapshot.

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

The subscription cap reuses the `gn_limits_t::max_extensions`
**numeric default** (256) so operators do not have to tune yet
another knob. The two pools are separate — extension entries
live in `ExtensionRegistry`, conn-event subscriptions live on
the `SignalChannel` token list — but they share the same default
ceiling. A plugin must not subscribe more than once per topic;
the typical pattern is one subscription per plugin instance.

---

## 7. Cross-references

- Quiescence anchor: `plugin-lifetime.md` §4.
- Service executor for deferred work: `timer.md`.
- Trust upgrade rule: `security-trust.md` §3.
- Backpressure watermarks: `limits.md` §2 (future
  `backpressure.md`).
