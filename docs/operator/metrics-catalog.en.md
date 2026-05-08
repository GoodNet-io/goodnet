# Metrics catalogue

Operator-side reference for every counter the GoodNet kernel and
its bundled static plugins expose through the `iterate_counters`
slot. An out-of-tree exporter plugin (Prometheus, OpenMetrics,
statsd, ...) reads this same surface and renders it on whatever
endpoint the operator picks. The kernel never carries a wire-format
renderer — see [metrics](../contracts/metrics.en.md) §1.

This page enumerates the **kernel-emitted** and
**static-plugin-emitted** names. Counters from loadable plugins
(handler-heartbeat, link-tcp, link-ws, link-ipc, link-tls,
security-noise, security-null, ...) live in each plugin's own
repository — see §7.

## Contents

- [1. Conventions](#1-conventions)
- [2. Router-outcome counters](#2-router-outcome-counters)
- [3. Drop-reason counters](#3-drop-reason-counters)
- [4. Plugin-lifecycle counters](#4-plugin-lifecycle-counters)
- [5. Static protocol counters](#5-static-protocol-counters)
- [6. Configuration / metrics-store counters](#6-configuration--metrics-store-counters)
- [7. SLI category mapping](#7-sli-category-mapping)
- [8. Loadable-plugin counters](#8-loadable-plugin-counters)
- [9. Plugin-author convention](#9-plugin-author-convention)
- [10. Cross-references](#10-cross-references)

---

## 1. Conventions

Names are flat, NUL-terminated UTF-8 strings, lowercase, dot-separated.
The shape is `<subsystem>.<event>` for the base counter and
`<subsystem>.<event>.<reason>` when a reason breakdown applies.

| Property | Value |
|---|---|
| Type | monotonic `uint64_t` |
| Producer | every plugin via `emit_counter`; the kernel itself for built-ins |
| Reset semantics | none; counters wrap at 2^64 |
| Cardinality cap | `gn_limits_t::max_counter_names`, default `8192` |
| Reserved namespaces (kernel-only) | `route.outcome.*`, `drop.*`, `metrics.*` |

A plugin that emits a name inside a kernel-reserved namespace
shares the slot with the kernel-side increment — the result is
operator-confusing and a contract bug per
[metrics](../contracts/metrics.en.md) §3.

Past the cardinality cap, `emit_counter` on a previously-unseen
name is rejected and bumps `metrics.cardinality_rejected` instead.
Existing counters keep incrementing across the cap.

---

## 2. Router-outcome counters

Every envelope routed through `Router::route_inbound` increments
exactly one of these. The mapping is enumerated in
`core/kernel/metrics_registry.cpp::route_outcome_metric_name` and
the increment fires from `host_api_builder.cpp::dispatch_inbound`.

| Counter | Producer | Meaning |
|---|---|---|
| `route.outcome.dispatched_local` | kernel router | envelope delivered to a locally-registered handler chain |
| `route.outcome.dispatched_broadcast` | kernel router | envelope fanned out to every locally-registered handler for the msg_id |
| `route.outcome.deferred_relay` | kernel router | envelope held for relay forwarding (TTL not exhausted, dedup not triggered) |
| `route.outcome.dropped_zero_sender` | kernel router | inbound envelope carried `sender_id == 0` outside its allowed window |
| `route.outcome.dropped_invalid_msg_id` | kernel router | `msg_id` outside the registered range |
| `route.outcome.dropped_unknown_receiver` | kernel router | `receiver_id` does not match a known local node |
| `route.outcome.dropped_no_handler` | kernel router | no handler registered for the matching msg_id and the chain rejected the envelope |
| `route.outcome.rejected` | kernel router | a handler in the chain returned the REJECT verdict |

Operators sum `route.outcome.dropped_* + route.outcome.rejected`
to get the routing-side loss count. The deframe-side equivalent
is the `drop.*` family below — see
[metrics](../contracts/metrics.en.md) §3.

---

## 3. Drop-reason counters

Each `gn_drop_reason_t` enum value maps to one counter name. The
mapping lives in
`core/kernel/metrics_registry.cpp::drop_reason_metric_name` so a
new enum value lands alongside its metric name in one place. The
increment fires from the kernel pipeline that surfaces the reason —
the emitter column lists the call site.

| Counter | Producer | Trigger |
|---|---|---|
| `drop.frame_too_large` | `host_api_builder.cpp::notify_inbound_bytes`; `inject` thunk | `parse_header` returns `GN_ERR_FRAME_TOO_LARGE`; injected payload above `limits.max_frame_bytes` |
| `drop.payload_too_large` | `host_api_builder.cpp::inject` thunk | injected payload above `limits.max_payload_bytes` |
| `drop.queue_hard_cap` | TCP / WS / IPC / TLS link plugins | per-connection pending queue past `pending_queue_bytes_hard` |
| `drop.deframe_corrupt` | `host_api_builder.cpp::notify_inbound_bytes` | `parse_header` returns `GN_ERR_DEFRAME_CORRUPT` (magic / version drift) |
| `drop.rate_limited` | `host_api_builder.cpp::inject` thunk | per-source token bucket ran dry |
| `drop.trust_class_mismatch` | `host_api_builder.cpp::notify_connect` thunk (protocol gate); same thunk after `SessionRegistry::create` returns `INVALID_ENVELOPE` (security gate) | declared trust outside the plugin's `allowed_trust_mask`, see [security-trust](../contracts/security-trust.en.md) §4 |
| `drop.attestation_bad_size` | `core/kernel/attestation_dispatcher.cpp` | attestation envelope size below the wire minimum |
| `drop.attestation_replay` | `core/kernel/attestation_dispatcher.cpp` | nonce already seen for the same identity |
| `drop.attestation_parse_failed` | `core/kernel/attestation_dispatcher.cpp` | TLV parse error inside the attestation envelope |
| `drop.attestation_bad_signature` | `core/kernel/attestation_dispatcher.cpp` | Ed25519 verification failed |
| `drop.attestation_expired_or_invalid` | `core/kernel/attestation_dispatcher.cpp` | issued-at / not-after window violation |
| `drop.attestation_identity_change` | `core/kernel/attestation_dispatcher.cpp` | per-connection identity rotated mid-session |

The following enum values exist in `gn_drop_reason_t` but the
kernel does not currently emit a counter increment for them. The
mapping in `drop_reason_metric_name` returns the canonical string
so a future emitter lands without an exporter-visible rename.

| Counter | Producer | Status |
|---|---|---|
| `drop.none` | (none) | sentinel; never emitted |
| `drop.reserved_bit_set` | TBD | enum value present, no kernel emitter — relay-side filter not yet wired |
| `drop.zero_sender` | (router covers this via `route.outcome.dropped_zero_sender`) | enum value retained for relay-pipeline use; not currently emitted |
| `drop.unknown_receiver` | (router covers this via `route.outcome.dropped_unknown_receiver`) | enum value retained; not currently emitted |
| `drop.relay_ttl_exceeded` | TBD | relay forwarding plugin owns the emit site |
| `drop.relay_loop_dedup` | TBD | relay forwarding plugin owns the emit site |
| `drop.unknown` | (none) | fallthrough sentinel for an enum value past the switch |

Plugin counters never use the `drop.` prefix — that namespace is
kernel-reserved. A plugin that surfaces its own dropped-frame
metric uses its own subsystem prefix; see §9.

---

## 4. Plugin-lifecycle counters

| Counter | Producer | Meaning | When |
|---|---|---|---|
| `plugin.leak.dlclose_skipped` | `core/plugin/plugin_manager.cpp::unload` | plugin teardown deferred `dlclose` because at least one anchor (handler / extension / subscription / config-snapshot) is still live | indicates a plugin failed to release every host_api anchor before its `gn_plugin_unregister` returned; the `.so` stays mapped until anchors drop. See [plugin-lifetime](../contracts/plugin-lifetime.en.md) §6 |

Per-name plugin load / unload counters
(`plugin.load.success`, `plugin.load.fail`,
`plugin.unload.drain_timeout`) are not currently emitted. The
kernel logs every load / unload but the metric surface for those
events is reserved for a later v1.x increment — see
[plugin-lifetime](../contracts/plugin-lifetime.en.md) §3.

---

## 5. Static protocol counters

The two protocol layers compiled into the kernel binary
(`plugins/protocols/gnet/`, `plugins/protocols/raw/`) do not
currently emit any plugin-side counters. Their drop paths surface
through the kernel's `drop.*` namespace
(`drop.frame_too_large`, `drop.deframe_corrupt`) because the
deframe call lives in `host_api_builder.cpp::notify_inbound_bytes`,
upstream of the protocol layer.

A future revision may add `gnet.frame.malformed` /
`gnet.frame.size_exceeded` / `raw.frame.size_exceeded` counters
once protocol-side validation grows beyond the deframe envelope.
For v1.0 the operator reads the deframe outcome through `drop.*`.

---

## 6. Configuration / metrics-store counters

| Counter | Producer | Meaning |
|---|---|---|
| `metrics.cardinality_rejected` | `core/kernel/metrics_registry.cpp::increment` | `emit_counter` rejected a previously-unseen name because `gn_limits_t::max_counter_names` was exhausted. Pre-created at registry construction so the slot is always observable, even at value `0` on a healthy registry. See [metrics](../contracts/metrics.en.md) §2.1 and [limits](../contracts/limits.en.md) §3a |

`config.reload.success` / `config.reload.fail` are not currently
emitted as counters — the kernel logs every reload outcome through
the `kernel.reload_config` log line. A future revision may
promote the reload outcome to a counter pair; until then the
operator alerts on the log stream. See
[config](../contracts/config.en.md) §6.

---

## 7. SLI category mapping

For an operator wiring a Prometheus rule file or an alerting
runbook, every counter prefix maps to one SLI category. The
mapping below follows the standard four-window approach
(availability, latency, errors, saturation) plus a fifth bucket
for capacity-planning telemetry.

| Counter prefix | SLI category | Typical alerting shape |
|---|---|---|
| `route.outcome.dispatched_*` | availability (success counter) | rate-of-change positive on a healthy node; flat-line is the alert signal |
| `route.outcome.dropped_*` | errors | rate above threshold per envelope class; sustained increase = handler-registration drift or hostile-peer flood |
| `route.outcome.rejected` | errors | handler-side rejection rate; sustained increase = config / policy mismatch |
| `route.outcome.deferred_relay` | capacity | relay-queue depth proxy; sustained growth indicates a relay-plugin keeping up |
| `drop.frame_too_large`, `drop.payload_too_large` | errors (input-validation) | hostile-peer signal at sustained rate; one-off spikes are benign noise |
| `drop.queue_hard_cap` | saturation | per-connection backpressure cliff; sustained increase = downstream consumer stalled, see [backpressure](../contracts/backpressure.en.md) §4 |
| `drop.deframe_corrupt` | errors (wire-integrity) | protocol drift / version mismatch on a peer link |
| `drop.rate_limited` | errors (policy) | per-source token bucket exhaustion; expected under load shed, alert on sustained rate against a single source |
| `drop.trust_class_mismatch` | errors (policy) | declared trust outside `allowed_trust_mask`; sustained rate = config drift between peers |
| `drop.attestation_*` | errors (security) | signature / replay failures; any sustained rate is a security-investigation trigger |
| `plugin.leak.dlclose_skipped` | capacity (resource hygiene) | non-zero value indicates a plugin failed to release every anchor before unload; counter growth = library memory pressure over time |
| `metrics.cardinality_rejected` | capacity (observability hygiene) | sustained increase = a plugin is minting unbounded names; raise the cap or tighten the plugin's name set |

The kernel never auto-applies these bands. An exporter plugin
copies the table into the operator's monitoring stack as alerting
rules.

---

## 8. Loadable-plugin counters

Each loadable plugin (handler-heartbeat, link-tcp, link-udp,
link-ws, link-ipc, link-tls, security-noise, security-null) owns
a `<plugin>.*` namespace and emits its own counters through
`host_api->emit_counter`. The catalogue for those names lives in
each plugin's own repository under `docs/metrics.en.md` (or its
README's metrics section). The kernel does not enumerate them —
the `iterate_counters` slot returns whatever set the loaded
plugins minted.

Common patterns operators see in a deployed kernel with the
default plugin set loaded:

| Prefix | Owner repository | Typical events |
|---|---|---|
| `link_tcp.*` | `goodnet-io/link-tcp` | `link_tcp.dial.success`, `link_tcp.dial_fail.timeout`, `link_tcp.dial_fail.refused`, `link_tcp.dial_fail.unreachable` |
| `link_udp.*` | `goodnet-io/link-udp` | dial / receive outcomes mirroring TCP |
| `link_ws.*` | `goodnet-io/link-ws` | handshake, upgrade, disconnect reasons |
| `link_ipc.*` | `goodnet-io/link-ipc` | accept / connect outcomes for AF_UNIX peers |
| `link_tls.*` | `goodnet-io/link-tls` | TLS handshake outcomes, alert codes |
| `security_noise.*` | `goodnet-io/security-noise` | handshake state transitions, decrypt failures |
| `security_null.*` | `goodnet-io/security-null` | session lifecycle for the no-op provider |
| `heartbeat.*` | `goodnet-io/handler-heartbeat` | `heartbeat.ping`, `heartbeat.pong`, `heartbeat.miss` |

The exact name set per plugin is the plugin owner's contract; the
kernel-side guarantee is only that any name a plugin emits is
visible to every exporter that calls `iterate_counters`.

---

## 9. Plugin-author convention

A plugin minting its own counter follows three rules:

1. **Stay inside your prefix.** Pick `<plugin>.<event>` or
   `<plugin>.<event>.<reason>`. Never emit inside `route.outcome.*`,
   `drop.*`, `metrics.*` — those are kernel-reserved.
2. **Use a closed set of reasons.** A reason field must enumerate
   to a small fixed set the operator can put on a dashboard.
   Per-peer or per-connection-id names exhaust the cardinality cap
   in minutes under load. Per-peer detail goes through the log
   surface, not the counter store.
3. **Document every name.** Every counter the plugin emits lives
   in the plugin's own `docs/metrics.en.md`, with one row per
   counter naming the event and the SLI category. The kernel-side
   exporter reads this catalogue plus the plugin-side ones to
   build the operator-facing monitoring surface.

See [metrics](../contracts/metrics.en.md) §3 for the cardinality
budget and the naming-collision policy, and the
`docs/recipes/instrument-with-metrics.ru.md` recipe for a
worked example.

---

## 10. Cross-references

- Contract: [metrics](../contracts/metrics.en.md) — counter store
  semantics, cardinality cap, exporter pattern.
- Contract: [limits](../contracts/limits.en.md) §3a —
  `max_counter_names` field and tuning notes.
- Contract: [host-api](../contracts/host-api.en.md) §6 —
  `emit_counter` / `iterate_counters` slots.
- Contract: [plugin-lifetime](../contracts/plugin-lifetime.en.md) —
  anchor / dlclose semantics behind `plugin.leak.dlclose_skipped`.
- Contract: [backpressure](../contracts/backpressure.en.md) —
  pending-queue policy behind `drop.queue_hard_cap`.
- Contract: [security-trust](../contracts/security-trust.en.md) —
  trust-mask gate behind `drop.trust_class_mismatch`.
- Contract: [attestation](../contracts/attestation.en.md) — TLV
  pipeline behind the `drop.attestation_*` family.
- Implementation: `core/kernel/metrics_registry.{hpp,cpp}` —
  enum-to-name mapping for `route.outcome.*` and `drop.*`.
- Implementation: `core/kernel/host_api_builder.cpp` —
  `thunk_emit_counter` and the kernel-side increment sites.
- SDK header: `sdk/metrics.h` (visitor type), `sdk/host_api.h`
  (slot declarations), `sdk/types.h` (`gn_drop_reason_t`).
