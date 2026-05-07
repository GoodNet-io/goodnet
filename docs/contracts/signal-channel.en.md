# Contract: SignalChannel

**Status:** active · v1
**Owner:** `core/signal/`
**Header:** `core/signal/signal_channel.hpp`
**Stability:** stable for v1.x.

---

## 1. Purpose

Typed publish/subscribe primitive for non-FSM kernel events. The
kernel's eight-phase FSM transitions flow through
`Kernel::subscribe` per `fsm-events.md` §7; everything else — config
reload, plugin loaded / unloaded, connection state changes,
extension lifecycle — uses one `SignalChannel<Event>` per event
type.

The channel is internal to the kernel. Plugins do not see it
directly; cross-plugin notifications are mediated through extension
vtables or through the host API entries in `host-api.md` §2.

---

## 2. Surface

```cpp
template <class Event>
class SignalChannel {
public:
    using Handler = std::function<void(const Event&)>;
    using Token   = std::uint64_t;

    [[nodiscard]] Token subscribe(Handler handler);
    void                unsubscribe(Token token);
    void                fire(const Event& event);

    [[nodiscard]] std::size_t subscriber_count() const;
};
```

Move-only by deletion of copy operations; default-constructible.

---

## 3. Token semantics

- `subscribe` returns a `Token` the caller hands back to
  `unsubscribe`. Tokens are monotonically issued from a per-channel
  counter starting at 1; reuse of a freed token does not happen
  inside realistic lifetimes (`uint64_t` exhaustion takes geological
  time).
- `unsubscribe` is **idempotent** — calling with an already-removed
  or unknown token is a no-op. Plugins that want to drop a
  subscription on shutdown call unsubscribe unconditionally.

---

## 4. Reentrancy

`fire()` snapshots the current subscriber list under a shared lock,
releases the lock, then invokes handlers from the unlocked
snapshot. Consequences:

- A handler **may** call `subscribe` or `unsubscribe` against the
  same channel from within its own callback — no deadlock; the
  edit lands in the underlying list and shows up on the next
  `fire`.
- Subscribers added during a `fire` invocation do **not** receive
  the in-flight event. They start receiving from the next `fire`.
- Subscribers removed during a `fire` invocation **do** still see
  the in-flight event because the snapshot was already taken.

This is the same mechanism the kernel's FSM uses: snapshot under
lock, dispatch outside lock — so handlers and callbacks compose
without ordering hazards.

---

## 5. Thread safety

`subscribe` and `unsubscribe` take an exclusive `unique_lock`.
`fire` and `subscriber_count` take a shared `shared_lock`. Multiple
fires from different threads run concurrently; one subscribe / one
unsubscribe blocks all others on the same channel for the duration
of the list edit.

The channel does **not** queue events — `fire` is synchronous.
Cross-thread asynchronous delivery is the caller's job; for that
shape, hand handlers an enqueueing wrapper that posts onto a
chosen executor.

---

## 6. Subscriber failure modes

### 6.1 NULL handler

`subscribe` rejects a handler that is empty (default-constructed
`std::function`, or a `nullptr` C function pointer wrapped through
the C ABI bridge). The rejection returns an invalid token (zero,
matching the `GN_INVALID_SUBSCRIPTION_ID` sentinel from
`conn-events.md` §3) and does not append to the subscriber list.
Plugins that pass NULL get a no-op subscription rather than a
fire-time crash.

### 6.2 Handler raises during `fire`

A handler that raises an exception during `fire` is caught by the
channel; the remaining subscribers in the snapshot still receive
the event. The channel discards the exception silently — no
re-throw past the `fire` call boundary, no kernel state mutation
beyond what the handler had already done before raising.

C ABI plugin authors **must not** allow C++ exceptions to escape
their callback through the C ABI boundary; the catch inside
`fire` is a kernel-side defence, not a contract that plugins may
raise. A C callback that wraps a higher-level language with an
exception model owns the catch and translates the exception into
a return code or a logged error.

### 6.3 Handler mutates other kernel state

A handler is free to call back into kernel registries
(`ConnectionRegistry`, `HandlerRegistry`, etc.) during `fire`;
those have their own locks and admit re-entry by design. The
exception is `for_each_connection` (`conn-events.md` §4): the
visitor holds a per-shard read lock and self-deadlocks on any
mutating call to the connection registry.

### 6.4 Handler blocks

`fire` is synchronous (§5) — a blocking handler holds up every
subscriber that follows it in the snapshot. Subscribers that
need to defer slow work hand `fire` an enqueueing wrapper; the
contract here pins fire-and-forget delivery, not bounded
runtime per handler.

---

## 7. Cross-references

- FSM phase events that do **not** flow through `SignalChannel`:
  `fsm-events.md` §7.
- Extension surfaces a plugin would use instead:
  `host-api.md` §2 (`register_extension`, `query_extension_checked`).
- C ABI vtable size validation: `abi-evolution.md` §3 (consumer
  responsibility) and §3a (kernel-side defensive check).
