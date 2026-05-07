# Contract: Clock Injection

**Status:** active · v1
**Owner:** every time-dependent component in `core/` and `plugins/`
**Last verified:** 2026-04-27
**Stability:** v1.x

---

## 1. Purpose

Tests must be able to advance time without busy-waiting on real clocks.
A component that hard-codes a read of the system monotonic clock makes
its own tests dependent on physical wall time — flake under sanitizers,
slow under load, indistinguishable from a real correctness defect.

This contract states the invariant: **every time-dependent component
accepts its time source as an explicit input.** How each language
idiomatically satisfies it lives in the per-language guide for that
binding (currently
[`docs/impl/cpp/clock.ru.md`](../impl/cpp/clock.ru.md); per-language
guides for Rust / Python / Zig / Go land alongside their
`bridges-<lang>` repos).

---

## 2. Invariant

**Every component that observes time accepts its time source as an
explicit input** — not by reading a global function inline. The same
component, instantiated with a controllable mock, runs deterministically
in tests; instantiated with the production monotonic clock, performs
identically to a hand-rolled `clock_gettime` call.

The invariant covers two aspects:

1. **Source.** The component does not call `now()` on a process-global
   singleton. The time source is supplied at construction or per call.
2. **Type.** The time source provides a strictly monotonic, non-decreasing
   point-in-time reading. Wall-clock sources (which can jump under NTP)
   are inappropriate for this contract; they have their own contract for
   logging timestamps.

---

## 3. Scope

Mandatory injection:

- token-bucket rate limiters (relay, MQTT bridge)
- backoff policies (DHT bootstrap retry, plugin reload)
- per-connection timer registries
- health and heartbeat sampling cadences
- session expiry and rekey schedulers

Exempt — these read time but not for behaviour-correctness:

- structured-log timestamping
- one-shot RNG seeding at process start
- diagnostic counters that record a creation moment

The exempt list is short by design. The default is "inject"; an exemption
needs an argument.

---

## 4. Production semantics

The production time source is the platform's monotonic clock, available
under `clock_gettime(CLOCK_MONOTONIC, ...)` on POSIX, equivalent on
other platforms. The injected source returns a 64-bit nanosecond
timestamp; older systems with coarser granularity round up.

The cost over reading the global function inline is zero on every
language: a default-bound input that compiles to the same syscall.
Languages with virtual-call overhead (Java, Python) use idiomatic
zero-cost bindings — the contract does not require a specific dispatch
mechanism.

---

## 5. Test semantics

Tests pass a controllable source that:

- starts at a fixed point (e.g. the unix epoch).
- advances **only** when the test calls an explicit `advance(duration)`
  function.
- under concurrent access from the component under test, returns a
  consistent monotonically-increasing reading without holding a lock on
  the read path.

Tests for components that race their own time-driven work (timer
firing during a posted callback) also need a deterministic scheduler;
that is out of scope here and lives alongside the test harness.

---

## 6. Wall-clock vs monotonic

The contract covers monotonic time. Components that need wall-clock
time — UTC midnight rotation of a key, ISO 8601 timestamps in audit
logs — take a separate wall-clock input alongside the monotonic one.
A component that requires both has two inputs, not one.

---

## 7. Cross-references

- Test infrastructure (mock implementations per language): the SDK
  language bindings and the per-language guide
  ([`impl/cpp/clock.ru.md`](../impl/cpp/clock.ru.md) currently;
  Rust / Python / Zig / Go follow alongside their bindings).
- Timer ownership invariant (one timer per slot, cancel before replace):
  `fsm-events.md` §3 and §5.
- Generation counter (logical clock for dispatch quiescence; not real
  time): `fsm-events.md` §6.
