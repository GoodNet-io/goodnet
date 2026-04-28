# Contract: Timer & Executor

**Status:** active · v1
**Owner:** `core/kernel/timer_registry`, every plugin that schedules
async work
**Last verified:** 2026-04-28
**Stability:** v1.x; one-shot timer + post_to_executor are stable;
periodic timer ride opt-in extension once a producer needs them.

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
milliseconds. The returned id is unique within the kernel's
lifetime; `0` is reserved as `GN_INVALID_TIMER_ID`. Returning
`GN_OK` does not guarantee the callback fires — see §4 for the
cancellation and quiescence rules.

`cancel_timer` removes a still-pending timer. Returns
`GN_OK` on success, `GN_ERR_UNKNOWN_RECEIVER` when the timer has
already fired or never existed. The contract is idempotent:
cancelling an already-cancelled timer is success.

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
plugin's quiescence sentinel (`plugin-lifetime.md` §4) — the same
anchor that handler / transport / extension entries inherit.
Before invoking `fn(user_data)`, the kernel upgrades the observer
to a strong reference; failure to upgrade is a clean exit, the
callback is dropped silently.

Concrete properties:

1. A timer that fires after the calling plugin's `gn_plugin_unregister`
   has run is observed and dropped — `fn` is not called.
2. `cancel_timer` from inside a plugin's callback chain is
   permitted; the kernel handles re-entry on the same thread by
   deferring the erase until the current callback returns.
3. `PluginManager::rollback` cancels every still-pending timer
   whose anchor matches the plugin being unloaded before draining
   the lifetime anchor (`plugin-lifetime.md` §4 quiescence). This
   keeps the drain loop fast: in-flight timers do not extend the
   plugin's effective lifetime.

A plugin **must not** spawn its own threads to back periodic work.
The contract is "post your task to the service executor"; everything
else is a §8 violation in `plugin-lifetime.md`.

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

| Slot | `GN_OK` | `GN_ERR_NULL_ARG` | `GN_ERR_LIMIT_REACHED` | `GN_ERR_UNKNOWN_RECEIVER` |
|---|---|---|---|---|
| `set_timer` | scheduled | host_ctx / fn / out_id null | quota hit | — |
| `cancel_timer` | cancelled or already gone | host_ctx null, id == `GN_INVALID_TIMER_ID` | — | — |
| `post_to_executor` | enqueued | host_ctx / fn null | quota hit | — |

`cancel_timer` collapses "not found" into `GN_OK` so plugins do not
race against the self-cleanup path on natural firing.

---

## 8. Cross-references

- Reference-counted ownership rule: `plugin-lifetime.md` §4.
- Resource limits: `limits.md` §2.
- Host-API surface: `host-api.md` §11 (this section is the
  authoritative semantics; host-api.md cites here).
