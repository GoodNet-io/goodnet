# Contract: Plugin Lifetime

**Status:** active · v1
**Owner:** `core/plugin/manager`, every plugin
**Last verified:** 2026-04-29
**Stability:** v1.x; lifecycle phases stable, hooks are size-prefix-evolvable

---

## 1. Purpose

A plugin's lifetime is bounded by the kernel's. Wrong sequencing
between plugin construction, registration in dispatch tables, and
unmapping of the shared object surfaces as use-after-free in async
callbacks. This contract pins the sequencing.

Two ideas drive the design:

1. **Two-phase activation.** All plugins are constructed first; only
   after every construction succeeds does the kernel register them in
   dispatch tables. A failure at construction time tears down the
   partial set without ever exposing handlers/transports to live
   traffic.
2. **Reference-counted ownership with weak observers.** Async work
   captures weak observers of the plugin's reference-counted handle.
   Dispatching after the plugin's last strong reference is dropped is
   structurally impossible because the observer fails to upgrade.

---

## 2. Phases

```
                   ┌────────────────────────────────────────┐
                   │            PluginManager               │
                   └────────────────────────────────────────┘
                                      │
                                      ▼
        ┌─────────────────────────────────────────────────────┐
        │   1. discover    plugin manifests → load order      │
        │   2. dlopen      .so files, resolve entry symbols   │
        │   3. version     gn_plugin_sdk_version() check      │
        │   4. init_all    construct every plugin instance    │
        │   5. register_all  install handler/transport vtables│
        │   6. on_running  steady state                       │
        │   7. pre_shutdown  drain in-flight dispatches       │
        │   8. unregister_all  remove from dispatch tables    │
        │   9. shutdown_all   plugin teardown callbacks       │
        │  10. dlclose      unmap shared objects              │
        └─────────────────────────────────────────────────────┘
```

Phases 4–5 are the **two-phase activation**. Phases 7–9 mirror in reverse;
phase 8 must complete before phase 9 to avoid dispatching into a torn-down
plugin.

---

## 3. Plugin entry symbols

Every plugin shared object exports five C symbols, all with the `gn_`
prefix. Unprefixed entry points (`handler_init`, `transport_init`)
are forbidden.

| Symbol | Phase | Purpose |
|---|---|---|
| `gn_plugin_sdk_version(major*, minor*, patch*)` | 3 | report build-time SDK version triple; no side effects |
| `gn_plugin_init(host_api*, host_ctx, out_self*)` | 4 | construct internal state; **must not** register anything |
| `gn_plugin_register(self)` | 5 | call `host_api->register_vtable(KIND, …)` / `register_extension` |
| `gn_plugin_unregister(self)` | 8 | undo every registration done in phase 5 |
| `gn_plugin_shutdown(self)` | 9 | release internal state; **must not** call `host_api` after return |

Full signatures live in `sdk/plugin.h` (Phase 3). Plugins written in any
FFI-capable language export these symbols with C linkage.

---

## 4. Reference-counted ownership with weak observers

Every transport, handler, and security provider that posts asynchronous
work owns itself through a **reference-counted handle** and captures a
**weak observer** of that handle in every async callback. Before
dereferencing plugin memory in the callback, the weak observer is
**upgraded** to a strong reference; failure to upgrade — meaning the
last strong reference was already dropped — is a clean exit.

The reference count IS the liveness signal. There is no separate
flag, no atomic boolean. Adding a parallel "is-alive" bit on top of
the reference count would double-track the same fact and is
forbidden.

Three observable properties:

1. The plugin object lives behind a counted handle. While at least one
   strong reference exists, the object is alive.
2. Async callbacks capture **only** weak observers, never raw pointers
   to the plugin object.
3. Every callback that needs to touch plugin state begins with a weak
   upgrade. A null result is the clean exit; a non-null result is held
   for the duration of the callback so the object cannot be destroyed
   during use.

The kernel applies the same pattern at registry granularity. Every
registry entry — handler, transport, extension, security — carries a
**lifetime anchor**: a strong reference to the registering plugin's
lifetime anchor. Dispatch-time snapshots (`HandlerRegistry::lookup`,
`LinkRegistry::find_by_*`, `SecurityRegistry::current`,
`ExtensionRegistry::query_prefix`) are returned by value, so the
snapshot's anchor copy keeps the sentinel's reference count above zero
for the duration of the call.

`PluginManager` observes the sentinel through a weak observer between
the start of teardown and `dlclose`:

1. **Publish `shutdown_requested = true` on the sentinel.** The flag is
   visible to two consumers: async-callback gates inside the kernel (a
   gate that observes the flag refuses the dispatch instead of entering
   plugin code), and the plugin itself through the
   `is_shutdown_requested` host_api slot (§ Cooperative cancellation).
   Publishing the flag first lets cooperating plugins finish work
   early; it does not by itself wait for anything.
2. `gn_plugin_unregister` — registry entries drop their anchor copies.
3. Cancel still-pending timers and posted tasks for this anchor so the
   drain wait is not extended by entries the plugin did not cooperatively
   cancel itself (`timer.md` §4 #3).
4. `gn_plugin_shutdown` — plugin's `self` is destroyed.
5. Manager promotes its strong ref to a weak observer and drops the
   ref, leaving only in-flight dispatch snapshots and not-yet-released
   gate guards holding anchors.
6. Wait until the weak observer reports the sentinel has expired
   (bounded; default 1s).
7. `dlclose` — safe; no snapshot is dereferencing plugin .text and no
   async callback is in plugin code.

The sentinel carries a counter the kernel maintains for diagnostics:
every async callback gate increments on entry and decrements on exit,
so the count of callbacks still inside plugin code at the drain
deadline is observable and logged alongside the timeout warning.

On timeout — a plugin that spawned a worker outlasting `shutdown` per
§ "What plugins must not do", or a long-running async loop that did
not poll `is_shutdown_requested` — the manager logs a warning that
includes the in-flight count and **leaks the dlclose handle**. The
.so stays mapped; the leftover work dereferences live code rather than
unmapped memory. Loud accounting (`PluginManager::leaked_handles()`)
makes the leak observable instead of silent.

The contract describes the invariant in terms any FFI-capable language
can satisfy. The C++ binding uses the standard reference-counted
pointer pair; Rust uses `Arc` / `Weak`; Swift uses `weak self` capture
in closures; Python uses `weakref`. Each language idiomatic-ally meets
the same observable contract.

The two-step check (acquire shared observer, then upgrade to strong)
is what closes the UAF window. A single-step check that captures the
strong reference directly keeps the object alive past its intended
lifetime; using a raw weak observer without upgrading lets a
destructor that ran during callback execution surface a dangling
pointer.

---

## 5. Two-phase activation in detail

The `PluginManager::activate` operation runs in two passes:

```
Pass 1 — init_all
    for each descriptor in load_order:
        call descriptor.init(host_api, host_ctx, out: self)
        if it fails, run rollback_init and return

Pass 2 — register_all
    for each descriptor in load_order:
        call descriptor.register(self)
        if it fails, run rollback_register and return

rollback_register:
    for each descriptor that already registered, call unregister
    fall through to rollback_init

rollback_init:
    for each descriptor that already inited, call shutdown
    return the original failure code
```

Without two-phase activation, a partial init failure could run
`dlclose` on a sibling plugin's library while a dispatch into one of
its handlers is still in flight. The two-phase split keeps every
handler unreachable from dispatch until **every** init succeeded, so
the rollback path can run cleanly.

---

## 6. Hot-reload

Hot-reload is supported but constrained:

- A plugin descriptor declares `hot_reload_safe`. Most plugins do;
  transports with kernel-bound state in flight do not.
- Reload sequence: `unregister → quiescence wait → shutdown → dlclose
  → dlopen → version check → init → register`.
- The quiescence wait observes the dispatch generation counter
  (`fsm-events.md` §6) reach a value past every in-flight read of the
  old vtable. A 64-bit counter is used; wraparound across realistic
  deployment lifetimes is not a concern.
- During quiescence the plugin's registry entry is removed from
  the dispatch table; new lookups miss and return
  `GN_ERR_NOT_FOUND`. In-flight dispatches that captured a
  snapshot before removal complete against their captured vtable
  copy and the matching `lifetime_anchor` keeps the `.so` mapped
  past the last call.

The race between `dlclose` and pending dispatch is closed by this
generation-quiescence wait.

---

## 7. Ownership annotation at the C ABI

Every pointer that crosses the plugin boundary carries one of the four
ownership tags from `abi-evolution.md` §6. The most common cases:

| Site | Direction | Tag |
|---|---|---|
| `gn_message_t::payload` in `handle_message` | kernel → plugin | `@borrowed` for the dispatch call |
| Frame bytes returned from `frame()` | plugin → kernel | `@owned` — paired with `out_free` |
| `host_api_t` itself | kernel → plugin | `@borrowed` for the plugin's lifetime |
| Vtable registered via `register_vtable(KIND_HANDLER, …)` | plugin → kernel | `@borrowed` until `unregister` |
| Extension vtable from `query_extension_checked` | provider → consumer | `@borrowed` while the provider is loaded |

Omitting an ownership tag is a code-review failure pre-RC.

---

## 8. Cooperative cancellation

A plugin that schedules long-running async work — a periodic timer
that re-arms itself, a multi-step posted task — observes shutdown
through `host_api->is_shutdown_requested(host_ctx)`. The slot
returns non-zero as soon as the kernel begins teardown for this
plugin, and stays non-zero through the drain.

The plugin polls the slot from inside the loop and exits early when
the flag is set:

- Periodic timers stop re-arming.
- Posted multi-step tasks return without scheduling the next step.
- Stateful workers that drain a queue treat the flag as the loop's
  exit predicate.

Cooperation is observable. A plugin that polls the flag drains in
microseconds because the kernel is not waiting for anything; a
plugin that ignores it consumes the bounded drain budget and, on
timeout, costs the kernel one leaked `dlclose` handle plus a logged
in-flight-count. The flag is the contract between the plugin and
the kernel for "you have until the drain deadline; please return
yourself".

The flag is **advisory**, not mandatory. Async callbacks that arrive
after the flag was published are dropped by the kernel-side gate
before they enter plugin code, so a plugin that never polls the flag
is still safe — it just costs more on shutdown. The point of polling
is to be a good neighbour, not to be correct.

For in-tree fixtures whose context has no anchor the slot always
returns 0; the plugin's logic is exercised the same way under test
as under a live kernel.

---

## 9. What plugins must **not** do

- Spawn a worker that outlives `gn_plugin_shutdown`. The kernel does
  not know about it; `dlclose` will yank the code under it.
- Capture `host_api` or `host_ctx` in a process-global. Plugins are
  designed to reload; globals tie into the old image.
- Call `host_api->register_*` outside `gn_plugin_register`. The
  dispatch table is locked during dispatch; out-of-phase mutation
  has undefined ordering.
- Construct objects that depend on extensions in `gn_plugin_init`.
  The extension provider may not have registered yet (toposort runs
  at phase 5). Move dependent construction into `gn_plugin_register`,
  after `query_extension_checked` succeeds.

---

## 10. Cross-references

- C ABI evolution: `abi-evolution.md` §3.
- The host vtable used at registration: `host-api.md`.
- Quiescence wait mechanics: `fsm-events.md` §6 (generation counter).
- Handler ordering and priority: `handler-registration.md`.
