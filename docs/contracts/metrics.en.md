# Contract: Metrics

**Status:** active · v1
**Owner:** `core/kernel/metrics_registry`, every plugin
**Last verified:** 2026-04-29
**Stability:** stable for v1.x; counter set is additive

---

## 1. Purpose

Operators need a single observable surface for kernel-internal
events — every router drop, every quota refusal, every plugin-side
counter — so an out-of-tree exporter can serve a consolidated view
to the operator's monitoring stack.

The kernel keeps a flat map of named monotonic 64-bit counters.
That is the entire surface. Wire format, scrape protocol, label
semantics, gauge / histogram / summary primitives all live in
plugins; the kernel never carries an HTTP server or a wire-format
renderer. Keeping the kernel's surface that small is what lets a
single deployment swap Prometheus for OpenMetrics for statsd
without recompiling the kernel.

---

## 2. Counter store

```c
typedef int32_t (*gn_counter_visitor_t)(void* user_data,
                                         const char* name,
                                         uint64_t value);

void     (*emit_counter)(void* host_ctx, const char* name);
uint64_t (*iterate_counters)(void* host_ctx,
                              gn_counter_visitor_t visitor,
                              void* user_data);
```

| Property | Specification |
|---|---|
| Producer | every plugin (via `emit_counter`) and the kernel itself (built-in counters) |
| Effect | bump the counter at @p name by one. First write at a previously-unseen name lazily creates the slot. |
| Returns (`emit_counter`) | none |
| Returns (`iterate_counters`) | number of counters visited; visitor returning non-zero stops the walk early |
| Name | NUL-terminated UTF-8; the kernel does not validate shape or charset. Convention: `<subsystem>.<event>.<reason>` |
| Concurrency | safe from any thread. The implementation pairs a `shared_mutex` with per-slot atomic increments — readers never block readers, and an existing-counter increment never blocks a reader |
| Delivery | best-effort; the counter is observable to subsequent reads but not flushed to any external sink — that is exporter business |
| Truncation | none. 64-bit counters wrap after 2^64 events; no realistic deployment hits this in v1.x |

Empty or NULL @p name on `emit_counter` is dropped silently. NULL
visitor on `iterate_counters` returns zero.

### 2.1 Cardinality cap

The map is bounded by `gn_limits_t::max_counter_names` (default
`8192`, `sdk/limits.h:131`). Past the cap, `emit_counter` on a
**previously-unseen** name is rejected and bumps the
always-present `metrics.cardinality_rejected` sentinel slot
(pre-created at registry construction, so the counter is
observable as `=0` on a healthy registry rather than
"missing-because-zero"). Existing counters keep incrementing
across the cap — only the slot allocation is gated. Setting the
limit to zero disables the cap.

The reject-new-past-cap policy (vs. LRU eviction) keeps
established counters stable: an exporter scraping
`drop.queue_hard_cap` mid-incident will not see the value silently
disappear because a hostile peer minted 8192 fresh dynamic names.

---

## 3. Built-in counters

The kernel emits these on its own dispatch paths. Plugins do not
have to opt in — the names appear in `iterate_counters` output as
soon as the corresponding event fires.

### Router outcomes (`route.outcome.*`)

Every envelope routed through `Router::route_inbound` emits one
counter increment named after its `RouteOutcome`:

| RouteOutcome | Metric name |
|---|---|
| `DispatchedLocal` | `route.outcome.dispatched_local` |
| `DispatchedBroadcast` | `route.outcome.dispatched_broadcast` |
| `DeferredRelay` | `route.outcome.deferred_relay` |
| `DroppedZeroSender` | `route.outcome.dropped_zero_sender` |
| `DroppedInvalidMsgId` | `route.outcome.dropped_invalid_msg_id` |
| `DroppedUnknownReceiver` | `route.outcome.dropped_unknown_receiver` |
| `DroppedNoHandler` | `route.outcome.dropped_no_handler` |
| `Rejected` | `route.outcome.rejected` |

Operators compute drop rates as the sum of `dropped_*` and
`rejected_*` counters over time.

### Drop reasons (`drop.*`)

Each `gn_drop_reason_t` enum value pairs with a metric name; the
kernel-internal pipelines that surface a specific drop reason emit
the corresponding counter. The mapping is enumerated in
`core/kernel/metrics_registry.cpp::drop_reason_metric_name`. New
enum values land alongside their metric name in one place — the
external surface stays stable across releases.

#### Drop counter discipline

`drop.*` is the operator-facing namespace for "the kernel
declined this byte sequence on the inbound path". Every reason
surfaces through exactly one counter; a reason without an
emitter is a contract bug, not an enum quietly waiting for
v1.1. The currently-emitting reasons:

| Counter | Emitter | Trigger |
|---|---|---|
| `drop.frame_too_large` | `notify_inbound_bytes` thunk | `parse_header` returns `GN_ERR_FRAME_TOO_LARGE` (length past `kMaxFrameBytes`) — hostile-peer signal |
| `drop.deframe_corrupt` | `notify_inbound_bytes` thunk | `parse_header` returns `GN_ERR_DEFRAME_CORRUPT` — magic / version drift |
| `drop.queue_hard_cap` | per-link `send` / `send_batch` (TCP / WS / IPC / TLS) | per-conn pending queue past `pending_queue_bytes_hard` |
| `drop.trust_class_mismatch` | `notify_connect` thunk | declared trust not in `protocol_layer().allowed_trust_mask()` (protocol-side gate, `host_api_builder.cpp:1067`) **or** not in the security provider's `allowed_trust_mask` (security-side gate, `host_api_builder.cpp:1130` after `SessionRegistry::create` returns `INVALID_ENVELOPE`); same counter for both per `security-trust.md` §4 |
| `drop.attestation_bad_size` / `_replay` / `_parse_failed` / `_bad_signature` / `_expired_or_invalid` / `_identity_change` | `attestation_dispatcher` via `MetricsRegistry::increment_drop_reason` | `attestation.md` §5 step failures — one counter per `gn_drop_reason_t` enum value, sharing the kernel's `drop.*` namespace so operators scrape every rejection class together |

`route.outcome.*` is the **routing-pipeline** namespace ("a
deframed envelope reached the dispatch chain — what happened
next?"). The two namespaces are orthogonal: a payload that
the kernel refused at deframe never reaches a `route.outcome.*`
counter, and a payload that the chain rejected after a handler
ran does not bump a `drop.*` counter. Operators sum
`drop.* + route.outcome.dropped_* + route.outcome.rejected_*`
to get the full bytes-not-delivered surface; the per-namespace
breakdown answers the next question (where in the pipeline did
the loss happen).

Plugin counters never use the `drop.` prefix — the namespace is
reserved for the kernel-internal mapping above so a single
exporter scrape names every reason at the same level. Plugins
that surface their own dropped-frame metrics use their
subsystem prefix (`gnet.drop.reserved_bit`, etc.) — the plugin
author owns name collisions inside their prefix.

### Plugin counters

Plugins own their `<subsystem>.*` namespace. The kernel does not
arbitrate between plugins; two plugins emitting the same name share
the same slot. Plugin authors prefix counter names with their own
identifier (`relay.forward.ok`, `heartbeat.tick`) to avoid
collisions.

---

## 4. Exporter pattern

A plugin that serves a wire format reads the counter set through
`iterate_counters`:

```c
static int32_t accumulate(void* ud, const char* name, uint64_t v) {
    /* render `name = v` into the exporter's buffer */
    return 0;
}

static void scrape(const host_api_t* api) {
    api->iterate_counters(api->host_ctx, &accumulate, /*ud*/ nullptr);
}
```

The visitor borrows `name` for the duration of the call; an
exporter that buffers names for later (e.g. async write to an
HTTP socket) copies them into its own storage.

There is no kernel-side scrape interval. Exporters drive their own
cadence.

---

## 5. What is **not** in the kernel

These responsibilities belong to exporter plugins, not the kernel:

- **Wire format.** Prometheus-text, OpenMetrics, statsd UDP, JSON,
  protobuf — the kernel does not render any of them.
- **Scrape protocol.** HTTP `/metrics`, push gateways, multicast
  beacons — the kernel does not carry any network code for
  exposition.
- **Label semantics.** v1 counters are flat names. An exporter
  plugin that wants Prometheus-style labels parses them out of
  the dotted name itself.
- **Aggregation primitives.** Gauges, histograms, summaries — out
  of scope. Plugins compose them on top of monotonic counters.
- **Reset / decrement.** Counters are monotonic. An exporter that
  needs a rate computes deltas across scrapes.

A future revision may add a single `gauge` slot for absolute
values that can decrease (active connection count, queue depth);
v1 ships counters only.

---

## 6. Cross-references

- Implementation: `core/kernel/metrics_registry.{hpp,cpp}` and
  thunks in `core/kernel/host_api_builder.cpp`.
- SDK header: `sdk/metrics.h` (visitor type) and `sdk/host_api.h`
  (`emit_counter`, `iterate_counters` slots).
- Router outcomes: `core/kernel/router.hpp` (`RouteOutcome` enum).
- Drop reasons: `sdk/types.h` (`gn_drop_reason_t`).
- Logging surface: `host-api.md` §11 (`log` slot — separate from
  metrics; the two live independently).
