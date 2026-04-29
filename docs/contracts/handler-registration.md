# Contract: Handler Registration

**Status:** active · v1
**Owner:** `core/registry/handler.hpp`, `core/signal/pipeline.hpp`
**Last verified:** 2026-04-27
**Stability:** v1.x

---

## 1. Purpose

Handlers consume envelopes. The kernel routes by `(receiver_pk, msg_id)`
and dispatches the matching envelope down a priority-ordered chain of
handlers. This contract pins the registration semantics, the priority
rules, the chain depth limit, and the pin-handler fast-path.

---

## 2. Registration

```c
gn_result_t (*register_handler)(void* host_ctx,
                                const char* protocol_id,   /* e.g. "gnet-v1" */
                                uint32_t   msg_id,         /* per-protocol */
                                uint8_t    priority,       /* 0..255 */
                                const gn_handler_vtable_t* vtable,
                                void* handler_self,
                                gn_handler_id_t* out_id);
```

Rules:

- `protocol_id` is a non-empty string scoping the dispatch
  namespace; a registration against an unloaded protocol is
  accepted but its handlers never receive envelopes. An empty
  string is rejected with `GN_ERR_NULL_ARG`. Chain capacity
  exhaustion returns `GN_ERR_LIMIT_REACHED`; `msg_id == 0` is
  reserved as the unset sentinel and rejected with
  `GN_ERR_INVALID_ENVELOPE`.
- `msg_id` is the per-protocol identifier; namespaces are isolated. The
  same `msg_id = 0x42` under `"gnet-v1"` and a future `"mesh-v2"` are
  unrelated.
- `priority` orders the dispatch chain: higher priority first. Default
  range:
  - `255` — pin-eligible critical paths (gaming, real-time RPC)
  - `128` — application default
  - `64`  — observability / metrics-only handlers
  - `0`   — fallback / catch-all
- Multiple handlers may share `(protocol_id, msg_id, priority)`; insertion
  order resolves ties.
- Maximum chain length per `(protocol_id, msg_id)` is `Limits::max_handlers_per_msg_id`
  (default 8). Exceeding returns `GN_ERR_LIMIT_REACHED`.

The returned `gn_handler_id_t` is opaque, stable until `unregister_handler`.
Plugins keep it for their own bookkeeping; the kernel does not require it
back during dispatch.

---

## 2a. Reserved msg_id values

Some msg_ids are reserved for kernel-internal dispatch and may not
be registered through this surface. `register_handler` rejects
registrations against these ids with `GN_ERR_INVALID_ENVELOPE`;
the failed call has no effect on registry state.

| msg_id | Reserved for | Specification |
|---|---|---|
| `0x00` | unset sentinel | this section |
| `0x11` | attestation dispatcher | `attestation.md` §3 |

Kernel-internal handlers do not use the registry described in this
contract. Their dispatch path runs ahead of the registry chain
lookup — the kernel intercepts envelopes carrying a reserved
msg_id after the protocol layer's `deframe` step and routes them
directly to the owning subsystem (`attestation.md` §3 specifies
the interception point for `0x11`). A plugin handler accidentally
chained against a reserved msg_id, were the registration not
rejected at registration time, would never see traffic — the
rejection here gives the plugin author a loud, immediate signal.

---

## 3. Dispatch chain

```cpp
void Pipeline::dispatch(const ConnectionContext& ctx,
                        const gn_message_t&      env)
{
    auto chain = handler_registry_.lookup(env.protocol_id, env.msg_id);
    for (auto* h : chain /* priority-descending */) {
        const Propagation r = h->vtable->handle_message(h->self, &env);
        h->vtable->on_result(h->self, &env, /* result */ r);   // §6 — never skipped
        if (r == Propagation::Consumed) break;
        if (r == Propagation::Reject)   { close_conn(ctx); break; }
        // Continue: next handler
    }
}
```

The dispatch chain is materialised once at envelope arrival — handler
registration during the chain is a no-op for that envelope (visible from
the next dispatch). This eliminates races between dispatch and
(un)registration.

The lookup itself is RCU-driven: registry mutations publish a new
read-only chain snapshot, dispatchers read whichever snapshot was current
when they entered. Per `fsm-events.md` §6, the snapshot generation is
64-bit.

---

## 4. Priority semantics

Three rules:

1. **Higher priority sees the envelope first.** A `priority=255` handler
   that returns `Consumed` denies lower-priority handlers any view of the
   envelope.
2. **Equal priority sees in registration order.** Older registrations
   come first; this ordering is stable to plugin authors who care.
3. **Pin-handler fast-path** can elide the lookup entirely (§5).

Priority is a hint, not enforcement; an application can register a
`priority=0` handler that watches every message for metrics without
risking that it intercepts traffic.

---

## 5. Pin-handler fast-path

A connection may **pin** a handler — calling
`host_api->pin_handler(conn, handler_id)` — bypassing chain lookup for
matching envelopes. Used by latency-sensitive applications (gaming,
real-time RPC) to remove the per-dispatch hash-lookup.

Rules:

- Pin is per-`(conn_id, msg_id)`. Different connections may pin
  different handlers for the same `msg_id`.
- The pinned handler **must still receive `on_result`**. The fast-path
  mirrors slow-path callbacks; skipping `on_result` would silently lose
  message-completion notifications.
- Pinning a non-existent handler returns `GN_ERR_UNKNOWN`.
- Unpin via `host_api->unpin_handler(conn, msg_id)`. Default pin slot
  is `INVALID_HANDLER_ID`; the slow-path lookup runs.

```cpp
void Pipeline::dispatch_with_pin(...) {
    if (auto pinned = ctx.pinned_handler(env.msg_id);
        pinned != INVALID_HANDLER_ID)
    {
        auto* h = handler_registry_.get(pinned);
        const Propagation r = h->vtable->handle_message(h->self, &env);
        h->vtable->on_result(h->self, &env, r);
        return;     // intentional: pin elides the chain
    }
    dispatch(ctx, env);   // §3 — full chain
}
```

A pinned handler that returns `Continue` does **not** fall through to
the chain. Pin is a unilateral substitute, not a chain prefix; if the
caller wants chain plus pin, they register the same handler at
`priority=255` and skip the pin.

---

## 6. `on_result` is mandatory in the call chain

The pipeline calls `on_result` after every `handle_message` regardless
of outcome, with the `Propagation` value as argument. Handlers that
don't care implement an empty default `on_result`; handlers that do
(relay-counter increment, DHT-bucket refresh) get reliable callback
ordering. The `Propagation` return value must never be discarded by
the dispatcher.

`on_result` must not throw across the C ABI; if a handler's
implementation lets an exception escape, the kernel treats it as a fatal
bug and aborts. Handlers that want lossy behaviour swallow inside their
own implementation.

---

## 7. Unregistration semantics

```c
gn_result_t (*unregister_handler)(void* host_ctx, gn_handler_id_t id);
```

- Removes the handler from the chain immediately for **future** dispatches.
- In-flight dispatches that already materialised a chain snapshot complete
  against the old chain (the handler vtable remains valid because the
  plugin's `dlclose` has not run yet — `plugin-lifetime.md` §6 quiescence
  wait).
- After `unregister`, the kernel reuses the `gn_handler_id_t` value for a
  future registration. Plugin code that retains old ids must not use
  them; the kernel does not validate stale ids past their lifetime
  (this is consistent with file-descriptor reuse semantics in POSIX).

---

## 8. Cross-references

- The vtable plugin-side: `protocol-layer.md` §3.
- The C ABI declaration: `host-api.md` §2 (`register_handler`).
- Quiescence wait between unregister and dlclose: `plugin-lifetime.md` §6.
- Generation counter: `fsm-events.md` §6.
- Chain depth limit: `limits.md` §7.
