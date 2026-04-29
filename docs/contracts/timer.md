# Contract: Timer & Executor

**Status:** active · v1
**Owner:** `core/kernel/timer_registry`, every plugin that schedules
async work
**Last verified:** 2026-04-29
**Stability:** v1.x; `set_timer`, `cancel_timer`, and
`post_to_executor` are stable; periodic timer support ships as an
opt-in extension once a producer needs it.

---

## 1. Purpose

Plugins that need to act on a clock — heartbeat, retry, idle
timeout, NAT keep-alive, DHT republish — must run that work on a
kernel-managed executor rather than spawn private threads. Private
threads outlive `gn_plugin_shutdown` and dereference unmapped `.text`
on the next firing.

The kernel owns a dedicated **service executor** (one
`asio::io_context` plus one worker thread) reserved for timers and
ad-hoc tasks. Plugins reach it through three host-API slots:
`set_timer`, `cancel_timer`, `post_to_executor`.

The service executor is **separate** from any executor a transport
plugin runs internally for socket I/O. Transports keep their own
strand-per-session pattern; the service executor is the kernel's
own runtime for plugin-scheduled work.

---

## 2. Slots

```c
typedef void (*gn_task_fn_t)(void* user_data);
typedef uint64_t gn_timer_id_t;

#define GN_INVALID_TIMER_ID  ((gn_timer_id_t)0)

gn_result_t set_timer(void* host_ctx,
                      uint32_t delay_ms,
                      gn_task_fn_t fn,
                      void* user_data,
                      gn_timer_id_t* out_id);

gn_result_t cancel_timer(void* host_ctx,
                         gn_timer_id_t id);

gn_result_t post_to_executor(void* host_ctx,
                             gn_task_fn_t fn,
                             void* user_data);
```

`set_timer` schedules `fn(user_data)` to run after `delay_ms`
milliseconds. The returned id is monotonically increasing and
unique within the kernel's lifetime — `gn_timer_id_t` is 64 bits
and reuse is structurally impossible across realistic process
runtimes. `0` is reserved as `GN_INVALID_TIMER_ID`. Returning
`GN_OK` does not guarantee the callback fires — see §4 for the
cancellation and quiescence rules.

`delay_ms == 0` is permitted and behaves as "post on the next
service-executor tick"; the callback runs serialised with every
other queued task per §3, never synchronously on the calling
thread. Producers that want a synchronous callback are misusing
the slot — `post_to_executor` is the same machinery without the
zero-delay misdirection.

Delays are measured against a monotonic clock (`steady_clock` on
glibc-class platforms); system time changes do not advance or
delay scheduled callbacks.

`cancel_timer` removes a still-pending timer. Returns `GN_OK`
whether the timer was alive, already fired, never existed, or had
been cancelled previously. The "not found" case collapses to
success so plugins do not race against the self-cleanup that fires
a natural completion. `GN_ERR_NULL_ARG` is returned only for
`GN_INVALID_TIMER_ID`.

`post_to_executor` runs `fn(user_data)` on the service executor at
the next available point. Useful for handing back work from a
transport's strand into the kernel's serialised loop.

---

## 3. Threading

The service executor runs on **exactly one thread**. Callbacks
posted through `set_timer` and `post_to_executor` are serialised:
two callbacks never run concurrently. Plugins that need parallelism
post each unit of work as a separate task and rely on the
serialisation only for ordering, not for throughput.

Single-thread is the v1 baseline. Future minor releases may scale
the executor to a thread pool; the contract keeps the
serialisation guarantee by switching to a strand internally.

`fn(user_data)` runs on the service-executor thread, **not** on
the thread that called `set_timer`. Plugins must not assume any
thread-local state survives the dispatch.

---

## 4. Lifetime safety

Every scheduled task carries a **weak observer** of the calling
plugin's quiescence sentinel (`plugin-lifetime.md` §4). Registry
entries hold the sentinel through a strong reference (the
"lifetime anchor"); async tasks like timers and posted callbacks
hold the matching weak observer so a stale callback cannot extend
the plugin's effective lifetime. Before invoking `fn(user_data)`,
the kernel opens a cancellation gate: it upgrades the observer to
a strong reference and inspects the sentinel's `shutdown_requested`
flag. The dispatch is dropped — `fn` is not called — when either
check fails (anchor expired, or rollback already requested
shutdown for the calling plugin). On a successful gate the strong
reference is held for the duration of `fn(user_data)`, so the
plugin's `.text` cannot be unmapped while the callback is in
flight.

Concrete properties:

1. A timer that fires after the calling plugin's `gn_plugin_unregister`
   has run is observed and dropped — `fn` is not called.
2. A timer that fires after rollback published `shutdown_requested`
   but before the anchor's last reference dropped is also observed
   and dropped, even though the anchor is still live for the
   duration of registry-entry teardown.
3. `cancel_timer` from inside a plugin's callback chain is
   permitted; the kernel handles re-entry on the same thread by
   deferring the erase until the current callback returns.
4. `PluginManager::rollback` cancels every still-pending timer
   whose weak observer matches the plugin being unloaded before
   draining the lifetime anchor (`plugin-lifetime.md` §4
   quiescence). This keeps the drain loop fast: in-flight timers
   do not extend the plugin's effective lifetime.

A plugin **must not** spawn its own threads to back periodic work.
The contract is "post your task to the service executor"; everything
else is a §9 violation in `plugin-lifetime.md`. Periodic plugins
poll `is_shutdown_requested` (`host-api.md` §10) at the top of
each tick and stop re-arming once the flag flips, so the kernel's
drain wait completes ahead of the bounded timeout.

---

## 5. Periodic work

The v1 surface is one-shot only. Plugins that need a repeating
heartbeat re-arm at the end of each callback:

```c
void on_tick(void* self) {
    /* …work… */
    gn_timer_id_t id;
    api->set_timer(host_ctx, kHeartbeatIntervalMs,
                   &on_tick, self, &id);
    /* store id if cancellation is desired */
}
```

The pattern is deliberate: a periodic primitive opens an extra
contract surface (drift, missed-tick policy, catch-up semantics)
that the baseline does not need. A future `gn.timer` extension may
publish a richer API once a producer drives the design.

---

## 6. Resource bounds

The kernel caps active timers at `gn_limits_t::max_timers`
(default `4096`) and queued executor tasks at
`gn_limits_t::max_pending_tasks` (default `4096`). `set_timer`
and `post_to_executor` return `GN_ERR_LIMIT_REACHED` past the cap;
the caller back-pressures by cancelling stale entries or dropping
the task.

Per-plugin sub-quotas are not enforced at the v1 baseline — the
kernel trusts plugins to behave inside their declared role. A
later contract revision may carve per-plugin slots if real
deployments expose abuse.

---

## 7. Error returns

| Slot | `GN_OK` | `GN_ERR_NULL_ARG` | `GN_ERR_LIMIT_REACHED` | `GN_ERR_INVALID_STATE` |
|---|---|---|---|---|
| `set_timer` | scheduled | host_ctx / fn / out_id null | quota hit | registry already shut down |
| `cancel_timer` | cancelled or already gone | host_ctx null, id == `GN_INVALID_TIMER_ID` | — | — |
| `post_to_executor` | enqueued | host_ctx / fn null | quota hit | registry already shut down |

`cancel_timer` collapses "not found" into `GN_OK` so plugins do not
race against the self-cleanup path on natural firing.

---

## 8. Cross-references

- Reference-counted ownership rule: `plugin-lifetime.md` §4.
- Cooperative cancellation: `plugin-lifetime.md` §8,
  `host-api.md` §10.
- Resource limits: `limits.md` §2.
- Host-API surface: `host-api.md` §9 (this section is the
  authoritative semantics; host-api.md cites here).
