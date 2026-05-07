# Contract: FSM Events

**Status:** active · v1
**Owner:** `core/kernel`, `core/signal`
**Last verified:** 2026-04-27
**Stability:** v1.x

---

## 1. Purpose

Every state transition in the kernel is observable. Subscribers learn
that state X happened by getting a callback. Three rules pin the
ordering and the consumption of those callbacks:

1. **Commit before notify.** A subscriber sees the new state only after
   the transition has succeeded.
2. **Every callback return is consumed.** No dispatch result is
   discarded; either it propagates or its enum value is removed entirely.
3. **Idempotent transitions use compare-and-exchange, not a plain
   store.** Two concurrent callers converge to one execution.

---

## 2. Kernel FSM phases

```
        Load → Wire → Resolve → Ready → Running → PreShutdown → Shutdown → Unload
```

Phases are linear; backward transitions are forbidden. Each transition
is a compare-and-exchange on the kernel state atomic; the loser of the
race observes the winner's end state and returns success without firing
duplicate notifications.

| Phase | What completes here |
|---|---|
| Load | plugin shared objects mapped, version-checked |
| Wire | host vtable fully populated, host context allocated |
| Resolve | service-graph toposort over plugin descriptors |
| Ready | all plugins past `init_all`, registry tables empty but live |
| Running | all plugins past `register_all`, dispatch open |
| PreShutdown | new connections refused; existing dispatches drained |
| Shutdown | all transports disconnected, handlers torn down |
| Unload | shared objects unmapped, host vtable invalidated |

---

## 3. Commit-then-notify

Subscribers must see the new state when the callback fires. If the
event fired before the state field was written, a subscriber that
read the kernel's current phase from inside the callback would see
the **old** state.

The contract:

```
advance_to(next):
    prev = state.exchange(next)        # commit by atomic exchange
    if prev == next: return            # idempotent: no notification
    on_phase_change.fire(prev, next)   # subscribers observe truth
```

Equivalent rule for any FSM in the codebase: **the public state
field is written first, the event fires second.** No exceptions.

---

## 4. Callback returns

Two current callback families return values. The contract is the
same for each: **either the value is consumed at every call site,
or the value is removed from the type.**

### 4.1 `gn_propagation_t` from `handle_message`

| Value | Meaning |
|---|---|
| `GN_PROP_CONTINUE` | pass envelope to next handler in priority order |
| `GN_PROP_CONSUMED` | stop dispatch chain — envelope handled |
| `GN_PROP_REJECT` | drop envelope; close connection; metrics increment |

Pre-RC review fails on any dispatch invocation whose return is not
used. Discarding `Propagation` is a contract violation.

### 4.2 `gn_backpressure_t` (queue-pressure signal — reserved)

| Value | Meaning |
|---|---|
| `GN_BP_OK` | accepted, no pressure |
| `GN_BP_SOFT_LIMIT` | past low watermark — caller should slow down |
| `GN_BP_HARD_LIMIT` | dropped — caller must back off, not retry tight |
| `GN_BP_DISCONNECT` | connection gone — caller should stop |

`host_api->send` itself returns `gn_result_t`; on a hard-cap drop
the result is `GN_ERR_LIMIT_REACHED` per `backpressure.md` §1. The
`gn_backpressure_t` enum is the wire shape reserved for the
per-connection pressure channel once it ships in a v1.x minor —
plugins that subscribe to that future channel **must** branch on
the value, since `BACKPRESSURE_HARD_LIMIT` arrives as a discrete
event and ignoring it would tight-loop on `send`.

---

## 5. Idempotent operations use compare-and-exchange

Operations that may race-call themselves (`stop`, `disconnect(conn)`,
`reload`) **must** elect a single executor through compare-and-exchange,
not a plain store.

```
stop():
    if not stopping.compare_exchange(expected=false, desired=true):
        return                          # someone else is stopping
    # ... do the actual stop here, exactly once ...
```

A plain store on a guard flag lets two callers both pass and run
shutdown twice. The compare-and-exchange pattern is mandatory for
every idempotent entry point.

---

## 6. Generation counter

The pipeline dispatch generation is a 64-bit unsigned atomic that
increments on every plugin (un)register. Subscribers cache `(handler_ptr,
generation_at_lookup)`; a cached pointer is valid only while the live
generation equals the cached value.

A 32-bit counter would wrap after a few days of hot-reloads in
stress tests, falsely matching a cached slot against a current
vtable and producing a use-after-free on dispatch. 64 bits makes
wraparound a non-concern across any realistic deployment lifetime.

---

## 7. State observation

Kernel phase is observed kernel-internally through
`Kernel::current_phase()` (atomic load) and
`Kernel::subscribe(weak_ptr<IPhaseObserver>)`. Observers are
stored as weak references and pruned at fire time. The kernel
itself owns these — they are not part of the plugin-facing C ABI;
plugins that need to react to phase transitions wire through the
`SignalChannel<PhaseEvent>` (per `signal-channel.md`) the kernel
publishes during transitions.

A plugin that forgets to clean up a subscription before
`gn_plugin_shutdown` does not crash the kernel — the weak observer
expires automatically when the plugin's liveness probe goes "dead"
(`plugin-lifetime.md` §4).

---

## 8. Cross-references

- Plugin lifecycle that reads phases: `plugin-lifetime.md`.
- Quiescence wait that uses generation counter: `plugin-lifetime.md` §6.
- Per-call-site error propagation rules: `host-api.md` §5.
- Backpressure semantics that surface through callback returns:
  `limits.md` §5.
