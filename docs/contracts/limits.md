# Contract: Limits

**Status:** active · v1
**Owner:** `core/types/limits.h`, every code path that enforces a bound
**Last verified:** 2026-04-27
**Stability:** v1.x; new fields added at the end of the struct.

---

## 1. Purpose

Resource bounds in the kernel and plugins live in **one** struct,
validated **once** at config load. Multiple sources for the same
bound diverge over time — a deframer that allows 16 MiB while the
public API accepts 256 KiB ends up exploitable through whichever
path the attacker reaches first.

This contract pins the structure and the validation rules.

---

## 2. The `gn_limits_t` struct

Declared in `sdk/types.h` (additions in Phase 3). Fields, all unsigned
integers in network byte order on the C ABI:

| Field | Width | Default | Purpose |
|---|---|---|---|
| `max_connections` | 32 | 4096 | total inbound + outbound |
| `max_outbound_connections` | 32 | 1024 | subset of `max_connections` |
| `pending_queue_bytes_high` | 32 | 1 MiB | backpressure trigger (per conn) |
| `pending_queue_bytes_low` | 32 | 256 KiB | backpressure release (per conn) |
| `pending_queue_bytes_hard` | 32 | 4 MiB | disconnect threshold (per conn) |
| `max_payload_bytes` | 32 | 64 KiB − header | per-message payload ceiling |
| `max_frame_bytes` | 32 | 64 KiB | total wire-frame ceiling |
| `max_handlers_per_msg_id` | 32 | 8 | dispatch chain length |
| `max_relay_ttl` | 32 | 4 | forwarded message hop count |
| `max_plugins` | 32 | 64 | dlopen ceiling |
| `max_extensions` | 32 | 256 | extension registry size |
| `max_timers` | 32 | 4 096 | active one-shot timers (`timer.md` §6) |
| `max_pending_tasks` | 32 | 4 096 | queued `post_to_executor` tasks |
| `max_storage_table_entries` | 64 | 10 000 | storage handler bound |
| `max_storage_value_bytes` | 64 | `max_payload_bytes` | per-entry size |
| `_reserved[8]` | 32×8 | 0 | size-prefix evolution |

The struct is loaded from `Config::limits` at kernel startup. After
construction it is **read-only** for the kernel's lifetime; reload of
limits requires a kernel restart, since most fields determine
at-startup allocations.

---

## 3. Cross-field validation

`Config::validate` runs before the kernel reaches `Wire` phase and
rejects:

| Invariant | What it catches |
|---|---|
| `max_outbound_connections ≤ max_connections` | misconfigured outbound limit |
| `pending_queue_bytes_low < pending_queue_bytes_high` | watermark inversion |
| `pending_queue_bytes_high ≤ pending_queue_bytes_hard` | hard cap below soft cap |
| `max_payload_bytes + sizeof(GnetHeader) ≤ max_frame_bytes` | frame ceiling shorter than payload |
| `max_relay_ttl > 0 && max_relay_ttl ≤ 8` | infinite relay loop OR amplification |
| `max_storage_value_bytes ≤ max_payload_bytes` | storage entry won't fit a single frame |

Failure is fail-fast: `gn_core_init` returns `GN_ERR_INVALID_CONFIG`
with the offending field name in the error message. There is no
"best effort" mode — a misconfigured `gn_limits_t` is a misconfigured
deployment.

---

## 4. Single source per code path

Every check-site reads from the live `gn_limits_t` reference exposed
through `host_api->limits()`. A code path that hard-codes a ceiling
parallel to a `gn_limits_t` field is a code-review failure pre-RC.

Compile-time constants are still appropriate for layout-fixed values
(`GN_PUBLIC_KEY_BYTES = 32`); those are facts about wire format,
not bounds about resources.

---

## 5. Drop semantics

Limit violations must be visible. Every limit-rejection path **must**
record the reason in metrics:

```
on limit exceeded:
    metrics.drop(reason)
    return GN_ERR_PAYLOAD_TOO_LARGE | GN_ERR_LIMIT_REACHED | …
```

Drop reasons live in the `gn_drop_reason_t` enum (`sdk/types.h` Phase 3),
with one metric counter per value. Operators reading `/metrics` see
the per-reason breakdown — limit drops do not blend into a generic
`errors_total` bucket.

Silent `break` or `continue` on limit violation is a code-review
failure pre-RC.

---

## 6. Per-connection counters in O(1)

Every per-connection bound is enforced via an O(1) atomic counter
maintained at enqueue / dequeue. Walking the queue to compute total
bytes would be O(N) per enqueue under a global lock and is forbidden:

```
enqueue(frame):
    new_total = bytes_buffered.load() + frame.size
    if new_total > limits.pending_queue_bytes_hard:
        return false                                # disconnect
    queue.push(frame)
    bytes_buffered.fetch_add(frame.size)
    return true
```

The counter is observable through the per-connection metrics surface
exported by the registry (`registry.md` §8). No separate aggregation
pass is needed.

---

## 7. Handler chain depth

`max_handlers_per_msg_id` bounds the dispatch chain length. Default
8. Hitting the limit fails the registration with `GN_ERR_LIMIT_REACHED`;
the kernel does not silently drop registrations.

This bound combined with `max_relay_ttl` defends against
amplification: a malicious relay node cannot trigger a chain of N
handlers each re-broadcasting because the receiver chain caps before
the relay path.

---

## 8. Cross-references

- TrustClass policy gates which limits apply to which connections:
  `security-trust.md`.
- Backpressure callback triggered by watermark crossings:
  `fsm-events.md` §4.2.
- Per-protocol payload max declared by the protocol implementation:
  `protocol-layer.md` §3.
