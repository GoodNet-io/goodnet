# Contract: Strategy extension

**Status:** active · v1
**Owner:** `plugins/strategies/`
**Last verified:** 2026-05-18
**Stability:** v1.x; vtable shape grows through size-prefix
              evolution per `abi-evolution.en.md` §3. The
              `gn_path_event_t` enum admits new tail values; the
              `gn_path_sample_t` struct grows through its
              `_reserved` tail.

---

## 1. Purpose

A strategy plugin picks one connection from a candidate set when an
outbound message has multiple eligible conns to the same peer. The
kernel does not embed any picker policy: every multi-conn decision
flows through whichever `gn.strategy.*` extension is registered.

A node with no strategy registered routes every outbound `send_to`
to the head of the candidate set — the same shape a no-strategy
deployment had before this contract existed.

A node with one strategy registered runs that strategy on every
`send_to`. A node with several strategies registered (e.g. a
primary RTT-optimal picker plus a cost-aware fallback) walks them
in registration order on every call and takes the first non-empty
pick — §6.

The strategy SDK header is [`sdk/extensions/strategy.h`](../../sdk/extensions/strategy.h);
the reference plugin is `plugins/strategies/float_send_rtt/`.

---

## 2. Surface

### 2.1 Extension vtable

```c
gn_strategy_api_t* api = host_api->query_extension_checked(
    "gn.strategy.<plugin-name>",
    GN_EXT_STRATEGY_VERSION,
    sizeof(gn_strategy_api_t));
```

Two function slots:

| Slot | Direction | Lifetime |
|---|---|---|
| `pick_conn(ctx, peer_pk, candidates, count, out_chosen)` | kernel → plugin | `candidates` borrowed for the call; `*out_chosen` written on `GN_OK`; ids in `candidates` valid until the call returns |
| `on_path_event(ctx, peer_pk, event, sample)` | kernel → plugin | `sample` borrowed; nullable for `CONN_DOWN` and `CAPABILITY_REFRESH`; the slot is always non-null in the vtable (the C++ macro fills a no-op stub if the plugin's class does not implement it) |

Plus the `api_size` size-prefix, `ctx` pointer, and `_reserved[4]`
ABI footer.

### 2.2 Wire surface

None. The strategy extension is in-process only — the kernel
reaches it through `host_api->query_extension_checked` and calls
its slots synchronously. Strategy plugins do not expose any
on-wire envelope ids.

---

## 3. `pick_conn` semantics

The kernel calls `pick_conn` from inside `host_api->send_to` for
every outbound message with more than one eligible conn to the
peer.

### 3.1 Return contract

| Return | Effect |
|---|---|
| `GN_OK` + `*out_chosen` ∈ `candidates` | kernel sends on the chosen conn |
| `GN_ERR_NOT_FOUND` | strategy has no opinion; kernel walks to the next registered strategy. When every strategy passes, the kernel falls back to the head of `candidates` |
| `GN_OK` + `*out_chosen == GN_INVALID_ID` | treated identically to `GN_ERR_NOT_FOUND` for compatibility; plugins should return `GN_ERR_NOT_FOUND` explicitly |
| `GN_ERR_NULL_ARG` | any input pointer NULL or `count == 0` |
| any other `gn_result_t` | aborts the strategy chain and surfaces back to the `send_to` caller |

### 3.2 Synchronous and bounded

`pick_conn` runs on the kernel's `send_to` call stack. The kernel
holds no locks across the call but expects the plugin to return
inside a few hundred microseconds. A strategy that needs heavier
work caches state across calls and queues the work to its own
executor.

The kernel does not retry a strategy: a slow strategy slows every
multi-conn `send_to`.

### 3.3 Candidate snapshot

`candidates` is a freshly-filled array of `gn_path_sample_t`
(§4). The strategy must NOT cache pointers to the array or to
individual samples past the call. The same `conn` id may appear
across calls — strategies maintain their own per-conn state map
keyed on `gn_conn_id_t`.

---

## 4. `gn_path_sample_t` layout

The kernel fills this struct fresh on every call from its current
accounting.

| Field | Type | Notes |
|---|---|---|
| `conn` | `gn_conn_id_t` | connection id valid for the duration of this call |
| `rtt_us` | `uint64_t` | smoothed RTT in microseconds; `0` means "no sample yet" |
| `loss_pct_x100` | `uint16_t` | packet-loss percentage × 100 — `1234` ≈ 12.34 % |
| `caps` | `uint32_t` | capability flags from the link plugin's `get_capabilities` |
| `_reserved_pad`, `_reserved[3]` | bytes | size-prefix evolution tail; readers ignore |

`rtt_us == 0` ranks worse than any measured value — a strategy
picking by RTT should not preempt a slow-but-observed conn for an
unknown-RTT one.

---

## 5. `gn_path_event_t` enum

The kernel fires per-path lifecycle events into `on_path_event`.
Strategies use these to update internal models (RTT EWMA, loss
smoothing, capability deltas) and may choose to reroute in-flight
traffic on receipt.

| Value | Meaning | `sample` |
|---|---|---|
| `GN_PATH_EVENT_CONN_UP` (1) | new conn opened to this peer; the strategy may immediately consider it for outbound routing | non-null; `rtt_us == 0` until the first probe |
| `GN_PATH_EVENT_CONN_DOWN` (2) | conn closed; strategy must drop it from its candidate set and stop returning it from `pick_conn` | nullable (no live sample remains) |
| `GN_PATH_EVENT_RTT_UPDATE` (3) | new RTT sample for an existing conn | non-null |
| `GN_PATH_EVENT_LOSS_DETECTED` (4) | packet-loss spike crossed the kernel's loss-detector threshold | non-null; `sample.loss_pct_x100` carries the smoothed percentage |
| `GN_PATH_EVENT_CAPABILITY_REFRESH` (5) | link plugin re-advertised its capabilities (TLS handshake completion, QUIC ALPN negotiation, ICE nomination flip, etc.) | nullable (caps carried via the prior call's snapshot) |

The kernel coalesces frequent events into the latest sample so a
strategy that takes longer than a few hundred microseconds in
`on_path_event` does not impose unbounded backlog.

---

## 6. Multi-strategy chain

The kernel admits multiple `gn.strategy.*` extensions
simultaneously and walks them in registration order on every
`pick_conn` invocation:

```
for strat in extensions.query_prefix("gn.strategy."):
    rc = strat.pick_conn(...)
    if rc == GN_OK and *out_chosen != GN_INVALID_ID: return chosen
    if rc == GN_ERR_NOT_FOUND: continue   # try next strategy
    if rc != GN_OK: return rc             # abort the chain
# every strategy passed → fall back to candidates[0]
```

Implementation: `core/kernel/host_api/messaging.cpp::send_to`.

Walk order is the same order
`host_api->query_extension_checked` returns — the registration
order on the `ExtensionRegistry`. Operators compose strategies
deliberately (e.g. `gn.strategy.rtt-optimal` as the primary +
`gn.strategy.cost-aware` as the fallback). Registration order
is the policy.

---

## 7. Reserved namespaces

`GN_EXT_STRATEGY_PREFIX = "gn.strategy."` is the canonical prefix.
Per-plugin names extend the prefix (`gn.strategy.rtt-optimal`,
`gn.strategy.cost-aware`, …).

Three additional namespaces are reserved for future SDK
expansions; the kernel does not consume them today, and plugins
that register under them must coexist with the `gn.strategy.*`
chain:

| Namespace | Reserved for |
|---|---|
| `gn.dht.<strategy>` | distributed routing / key-to-peer lookup |
| `gn.relay.<strategy>` | multi-hop forwarding |
| `gn.discovery.<strategy>` | peer finding (mDNS scan, bootstrap list, …) |

Design rationale lives in
[`docs/architecture/strategies.ru.md`](../architecture/strategies.ru.md).

---

## 8. Plugin authoring shape

Strategy plugins use the C++ SDK macro
`GN_STRATEGY_PLUGIN(Class, plugin_name, version)` from
[`sdk/cpp/strategy_plugin.hpp`](../../sdk/cpp/strategy_plugin.hpp).
The macro emits the five `gn_plugin_*` extern "C" entry points
plus the optional `gn_plugin_descriptor` symbol with
`kind = GN_PLUGIN_KIND_STRATEGY`.

The Class concept requires:

- `static const char* extension_name() noexcept` — the full
  `gn.strategy.<name>` string the kernel registers
- `static uint32_t extension_version() noexcept` — packed semver
  per `gn_version_pack`
- `gn_result_t pick_conn(const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES], const gn_path_sample_t* candidates, size_t count, gn_conn_id_t& out)` — the picker entry point
- Optional `gn_result_t on_path_event(const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES], gn_path_event_t ev, const gn_path_sample_t* sample) noexcept` — event handler

Reference: `plugins/strategies/float_send_rtt/float_send_rtt.{hpp,cpp}`
and `plugin_entry.cpp`.

---

## 9. Cross-references

- SDK header: [`sdk/extensions/strategy.h`](../../sdk/extensions/strategy.h)
- C++ macro: [`sdk/cpp/strategy_plugin.hpp`](../../sdk/cpp/strategy_plugin.hpp)
- Reference plugin: [`plugins/strategies/float_send_rtt/`](../../plugins/strategies/float_send_rtt/)
- Architecture rationale:
  [`docs/architecture/strategies.ru.md`](../architecture/strategies.ru.md)
- Kernel dispatch site:
  [`core/kernel/host_api/messaging.cpp`](../../core/kernel/host_api/messaging.cpp)
  `send_to()`
- Registry shape (including `ExtensionRegistry`):
  [`registry.en.md`](registry.en.md)
- ABI evolution rules: [`abi-evolution.en.md`](abi-evolution.en.md)
