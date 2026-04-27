# Contract: Plugin Lifetime

**Status:** active · v1
**Owner:** `core/plugin/manager`, every plugin
**Last verified:** 2026-04-27
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
| `gn_plugin_register(self)` | 5 | call `host_api->register_handler` / `register_transport` / `register_extension` |
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
- During quiescence the plugin's slot in the dispatch table holds a
  tombstone vtable that returns `GN_ERR_NOT_IMPLEMENTED` — better than
  UAF and observable through metrics.

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
| Vtable registered via `register_handler` | plugin → kernel | `@borrowed` until `unregister` |
| Extension vtable from `query_extension_checked` | provider → consumer | `@borrowed` while the provider is loaded |

Omitting an ownership tag is a code-review failure pre-RC.

---

## 8. What plugins must **not** do

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

The plugin lint pass (TBD) catches the first three statically.

---

## 9. Cross-references

- C ABI evolution: `abi-evolution.md` §3.
- The host vtable used at registration: `host-api.md`.
- Quiescence wait mechanics: `fsm-events.md` §6 (generation counter).
- Per-language liveness probe idioms: `docs/impl/<lang>/` (TBD).
- Handler ordering and priority: `handler-registration.md`.
