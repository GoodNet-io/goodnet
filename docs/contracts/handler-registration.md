# Contract: Handler Registration

**Status:** active · v1
**Owner:** `core/registry/handler.hpp`, `core/signal/pipeline.hpp`
**Last verified:** 2026-04-29
**Stability:** v1.x

---

## 1. Purpose

Handlers consume envelopes. The kernel routes by `(receiver_pk, msg_id)`
and dispatches the matching envelope down a priority-ordered chain of
handlers. This contract pins the registration semantics, the priority
rules, the chain depth limit, and the pin-handler fast-path.

---

## 2. Registration

Handlers register through the universal `register_vtable` slot in
`host_api_t`; see `host-api.md` §2 for the canonical signature.
The handler-specific shape:

- `kind = GN_REGISTER_HANDLER`
- `meta->name`     — protocol id (e.g. `"gnet-v1"`)
- `meta->msg_id`   — per-protocol message id
- `meta->priority` — 0..255 dispatch priority
- `vtable`         — `const gn_handler_vtable_t*`
- `self`           — per-handler state, opaque to the kernel
- `*out_id`        — populated on success; encodes the
  `GN_REGISTER_HANDLER` tag in its top 4 bits so a later
  `unregister_vtable(id)` routes back to `HandlerRegistry`
  without naming the kind a second time.

The pure-C convenience wrapper `gn_register_handler` in
`sdk/convenience.h` keeps the historical 7-argument shape and
expands to `register_vtable(GN_REGISTER_HANDLER, &meta, …)`.

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

The returned `gn_handler_id_t` is opaque, stable until `unregister_vtable(id)`.
Plugins keep it for their own bookkeeping; the kernel does not require it
back during dispatch.

### 2.1 `gn_handler_vtable_t` layout

The vtable carried by `register_vtable(GN_REGISTER_HANDLER)`. Begins with `api_size`
for size-prefix evolution per `abi-evolution.md` §3; the kernel
rejects a registration whose `api_size < sizeof(gn_handler_vtable_t)`
with `GN_ERR_VERSION_MISMATCH` per §3a. Every remaining slot is a
function pointer that the kernel invokes with the plugin-supplied
`self` argument. NULL is permitted on the optional lifecycle
hooks; the mandatory slots (`protocol_id`, `supported_msg_ids`,
`handle_message`) are non-NULL.

```c
typedef struct gn_handler_vtable_s {
    uint32_t         api_size;          /* sizeof(gn_handler_vtable_t) at producer build time */
    const char*      (*protocol_id)(void* self);
    void             (*supported_msg_ids)(void* self,
                                          const uint32_t** out_ids,
                                          size_t* out_count);
    gn_propagation_t (*handle_message)(void* self,
                                       const gn_message_t* envelope);
    void             (*on_result)(void* self,
                                  const gn_message_t* envelope,
                                  gn_propagation_t result);
    void             (*on_init)(void* self);
    void             (*on_shutdown)(void* self);
    void* _reserved[4];
} gn_handler_vtable_t;
```

| Slot | Required | Lifetime / ownership |
|---|---|---|
| `protocol_id` | yes | returned `const char*` outlives the plugin |
| `supported_msg_ids` | yes | `*out_ids` borrowed for the plugin lifetime; kernel queries once at registration |
| `handle_message` | yes | `envelope->payload` borrowed until return; copy on retention |
| `on_result` | no (NULL OK) | called after every `handle_message`; pinned fast-path invokes identically per §6 |
| `on_init` | no | called once after the kernel admits the registration |
| `on_shutdown` | no | called once during teardown after every in-flight dispatch returns |
| `_reserved[4]` | — | NULL on init; size-prefix evolution per `abi-evolution.md` §3a |

The struct does **not** carry an `api_size` first field (§3a marks
this vtable as fixed-shape at v1; growth happens through
`_reserved` slot promotion).

---

## 2a. Reserved msg_id values

Some msg_ids are reserved for kernel-internal dispatch and may not
be registered through this surface. `register_vtable(GN_REGISTER_HANDLER)` rejects
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

A dispatcher that wants the chain alongside the generation counter
the registry observed under the same shared lock calls
`lookup_with_generation(protocol_id, msg_id)`, which returns
`{ chain, generation }` atomically. Returning the pair without a
TOCTOU window — the lookup-side `find` and the
`generation()` read both run inside one shared-lock acquire —
matters for any future caller that wants to compare the recorded
counter against the live `generation()` post-walk to surface a
"dispatch on stale chain" rate. The split-call alternative
(`lookup` then a separate `generation()`) lets a writer slip an
in-between bump past the caller and corrupts that signal.

In v1 the kernel router consults `lookup_with_generation` and
walks the snapshot's chain to completion; the recorded generation
is observability surface, not a mid-walk abort signal. The
snapshot's `lifetime_anchor` strong refs keep every entry's
vtable valid for the entire walk, so concurrent unregistration
turns into a possibly-stale dispatch on entries the new
generation no longer wants — never a use-after-free.

---

## 4. Priority semantics

Three rules:

1. **Higher priority sees the envelope first.** A `priority=255` handler
   that returns `Consumed` denies lower-priority handlers any view of the
   envelope.
2. **Equal priority sees in registration order.** Older registrations
   come first; this ordering is stable to plugin authors who care.
Priority is a hint, not enforcement; an application can register a
`priority=0` handler that watches every message for metrics without
risking that it intercepts traffic.

---

## 5. `on_result` is mandatory in the call chain

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

## 6. Unregistration semantics

```c
gn_result_t (*unregister_vtable)(void* host_ctx, uint64_t id);
/* `gn_handler_id_t` and the universal id share the uint64_t shape;
   the kind tag in the top 4 bits routes back to HandlerRegistry. */
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

## 7. Cross-references

- The vtable plugin-side: `protocol-layer.md` §3.
- The C ABI declaration: `host-api.md` §2 (`register_vtable` family).
- Quiescence wait between unregister and dlclose: `plugin-lifetime.md` §6.
- Generation counter: `fsm-events.md` §6.
- Chain depth limit: `limits.md` §7.
