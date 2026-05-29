# Contract: Plugin lifecycle

**Status:** active · v1
**Owner:** `core/plugin/manager`, every plugin author
**Last verified:** 2026-05-25
**Stability:** v1.x; phase table and shutdown ordering are stable.

---

## 1. Purpose

Every plugin (LINK / SECURITY / HANDLER / PROTOCOL / STRATEGY)
follows the same lifecycle. The kernel calls a fixed sequence of
`gn_plugin_*` entry points; the plugin MUST honour the ordering
invariants below. Failure to honour the shutdown invariants is the
root cause of every race we have shipped — see #100, the TCP plugin
shutdown vs in-flight `async_accept` race.

This document is the canonical ordering contract. It complements
`plugin-lifetime.en.md` (which specifies the kernel-side teardown
protocol, two-phase activation, weak-observer ownership, and
hot-reload) by pinning down the plugin-side six-step shutdown
sequence as a hard invariant.

---

## 2. Phase table

| Phase | Kernel call | Plugin obligation |
|---|---|---|
| **install** | `gn_plugin_describe` → `gn_plugin_init(host_api, ctx, out_self)` | Register vtables. Allocate internal state. No threads spawned. |
| **start** | `gn_plugin_register(self)` (kernel-side phase 5; see `plugin-lifetime.en.md` §2) | Allowed to spawn worker threads, open sockets, bind file descriptors. Set the `started_` flag last. |
| **running** | Per-op vtable calls — `link->connect`, `handler->handle_message`, etc. | Operations from arbitrary threads. Worker threads run callbacks back into kernel via `host_api`. |
| **shutdown** | `gn_plugin_shutdown(self)` (per-instance) and the link/security `shutdown()` member that runs underneath it | See §3 — strict ordering. |
| **destroy** | `gn_plugin_shutdown(self)` returning, followed by `dlclose` / sentinel expiry | Free all memory. After this point no callback may fire. |

The phase names in this table align with the kernel-side phases in
`plugin-lifetime.en.md` §2:

- **install** ↔ phases 1–4 (discover / dlopen / version / init).
- **start** ↔ phase 5 (`register_all`).
- **running** ↔ phase 6 (`on_running`).
- **shutdown** ↔ phases 7–9 (`pre_shutdown` → `unregister_all`
  → `shutdown_all`).
- **destroy** ↔ phase 10 (`dlclose`).

---

## 3. Initialization invariants

(a) `gn_plugin_init` MUST complete synchronously. No async setup.

(b) `gn_plugin_init` MAY return `GN_OK` without spawning threads.
    Thread spawning happens in `gn_plugin_register` so a config-only
    validation pass can `init → describe → shutdown` without touching
    the OS scheduler.

(c) Plugin MUST tolerate `init → shutdown` with no `register` in
    between. This is how the manager rolls back a failed two-phase
    activation (`plugin-lifetime.en.md` §5).

(d) `gn_plugin_init` MUST NOT call `host_api->register_vtable` /
    `register_extension`. Those are register-phase only
    (`plugin-lifetime.en.md` §9).

---

## 4. Shutdown ordering — the contract

The per-instance teardown (the `shutdown()` member on link /
security / handler / protocol / strategy types, called directly from
`gn_plugin_shutdown` or by the kernel ahead of it) MUST execute in
this order:

```
1. shutdown_flag.exchange(true, std::memory_order_acq_rel);
2. CANCEL all background async ops (close acceptors, cancel timers).
3. CLOSE every owned file descriptor / socket / pipe.
4. JOIN every worker thread (or stop the io_context and join its threads).
5. NOTIFY upstream subscribers via host_api (notify_disconnect, etc.).
6. Return GN_OK.
```

**Reason for order.** If `shutdown_flag` is set AFTER step 2 or 3,
a worker thread completing an in-flight callback can re-arm a
closed resource (re-call `async_accept` on a nulled acceptor,
re-call `async_read_some` on a closed socket) — that's exactly the
#100 race in TCP plugin pre-fix. UDP plugin
(`plugins/links/udp/udp.cpp` `UdpLink::shutdown()`, the
`shutdown_.exchange(true, …)` at line 835) got it right by
exchange-true-first.

**Notify last, not first.** Steps 5 (`notify_disconnect`) runs
AFTER cancel / close / join so that:

- Subscribers see a single, terminal disconnect per connection id
  (a callback that fired `notify_disconnect` on its own thread
  before shutdown ran is reconciled via the append-only
  `published_ids_` drain — TCP plugin pattern,
  `plugins/links/tcp/tcp.cpp::TcpLink::shutdown()`).
- The kernel cannot dispatch back into a plugin that is mid-teardown
  on the same thread the notify call returns to.

**Reference implementations (canonical):**

- `plugins/links/udp/udp.cpp::UdpLink::shutdown()` (line 834) — UDP pattern.
- `plugins/links/tcp/tcp.cpp::TcpLink::shutdown()` (line 1035) — TCP
  pattern (post-#100 fix; the in-source comment above the
  `exchange(true)` documents why it MUST come first).
- `plugins/security/noise/noise.cpp::gn_plugin_shutdown` (line 498) — stateless-provider
  pattern (no async work; trivial teardown).

A new link / security / handler / protocol / strategy plugin SHOULD
mirror one of these.

---

## 5. Reentry / cancellation

After step 1 of §4 (`shutdown_flag = true`), every vtable entry
point MUST short-circuit:

```cpp
gn_result_t MyLink::connect(...) {
    if (shutdown_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }
    // ...
}
```

This check is mandatory on every entry point that may dispatch
io_context work. Callbacks scheduled by asio (`async_accept`,
`async_read_some`, timer expiries) MUST re-check the same flag at
the top of the callback body — see `on_accept` / `on_read_complete`
patterns in any link plugin.

The kernel-side gate described in `plugin-lifetime.en.md` §4 is a
second line of defence: even a plugin that forgets the in-callback
short-circuit will not have new dispatches enter its code once the
sentinel publishes `shutdown_requested = true`. The plugin-side
short-circuit is still required because:

- In-flight callbacks already past the kernel gate enter plugin code.
- The plugin holds resources (acceptors, sockets) the kernel does
  not see; re-arming those from a stale callback is the race.

---

## 6. Lifecycle anti-patterns

| Anti-pattern | Why broken | Fix |
|---|---|---|
| Setting `shutdown_flag` AFTER acceptor close / reset | Worker observes flag=false, re-arms `async_accept` on the freed resource → null deref / segfault. The #100 TCP race. | Flag FIRST, then cancel / close. |
| Joining worker thread BEFORE cancelling its work | `join()` blocks forever waiting for an op nothing told to stop. | Cancel async ops first, then join. |
| Notifying upstream from `gn_plugin_shutdown` (or from a dtor) instead of from the per-instance `shutdown()` member | Subscribers may have torn down by the time the destructor runs; kernel may have unregistered the host_api slot. | Notify in step 5 of §4 (still inside the `shutdown()` member, before returning). |
| Allocating new resources inside `shutdown()` | Race against destroy / dlclose. The allocation may outlive plugin .text. | `shutdown()` only releases. Never allocates. |
| Spawning a worker that outlives `gn_plugin_shutdown` | `dlclose` unmaps the .text the worker is executing → SIGSEGV in unmapped memory, often invisible in core files. | Every worker MUST be joined in step 4. See `plugin-lifetime.en.md` §9. |
| Capturing `host_api` / `host_ctx` in a process-global | Globals tie into the old image after hot-reload. | Capture into `self` only. See `plugin-lifetime.en.md` §9. |

---

## 7. Test recipe

A plugin's standard test set MUST include a shutdown-during-inflight
test. The minimum shape:

```cpp
TEST(MyLink, ShutdownDuringInflightOp) {
    // SetUp: listen on an ephemeral port; arm a connect from another fixture.
    auto link = MakeLink();
    link->listen("tcp://127.0.0.1:0");

    // Race the shutdown against in-flight accepts.
    std::thread t([&]{ link->shutdown(); });

    // Fire a burst of connects to maximise in-flight callbacks.
    for (int i = 0; i < 100; ++i) {
        (void)link->connect("tcp://127.0.0.1:<port>");
    }
    t.join();

    // Assert no UAF / null deref / leak in the destroyed state.
    // Under ASan/TSan this catches the #100 class of race.
}
```

For datagram plugins (UDP / ICE) the equivalent test races
`shutdown()` against in-flight `recv` callbacks rather than
`accept`. The bench gauntlet's
`TearDown → listen → connect → shutdown` loop counts as one such
test.

Mandatory under ASan and TSan in CI.

---

## 8. Cross-references

- `plugin-lifetime.en.md` — kernel-side teardown protocol, two-phase
  activation, weak-observer ownership, hot-reload, cooperative
  cancellation via `is_shutdown_requested`. This document
  (`lifecycle.en.md`) is the plugin-side complement that pins the
  six-step shutdown ordering as a hard invariant.
- `abi-evolution.en.md` §3 — `gn_plugin_*` entry-point ABI.
- `host-api.en.md` — the vtable the plugin uses for notify /
  register / extension calls.
- `link.en.md` — link-specific lifecycle and write-serialisation
  rules layered on top of this contract.
- `plugins/links/udp/`, `plugins/links/tcp/`,
  `plugins/security/noise/` — canonical reference implementations.
- #100 — TCP shutdown race fix as the motivating example.
