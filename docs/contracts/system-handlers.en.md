# Contract: System handlers

**Status:** active · v1
**Owner:** `core/kernel/system_handlers.{hpp,cpp}` + per-handler subsystems
**Last verified:** 2026-06-15
**Stability:** v1.x; the `msg_id` range is locked, individual handler
              wire formats evolve through their own contracts.

---

## 1. Purpose

The kernel reserves the `msg_id` range `0x10..0x1F` for
identity-bearing transport. The kernel is itself the **first
handler** on each reserved id: it registers priority=255 handlers
at `gn_core_start()` under every active protocol, implemented in
`core/kernel/system_handlers.{hpp,cpp}`. This makes the kernel's
dispatch role auditable through the topology snapshot and composable
with the regular handler chain.

Two dispatch outcomes:

- **CONSUMED** (`0x11` attestation) — kernel handler absorbs the
  envelope; lower-priority handlers never see it.
- **CONTINUE** (`0x12` rotation, `0x13` capability blob) — kernel
  handler processes the payload first, then propagates. Plugins
  that register on these ids at priority < 255 observe the
  envelope *after* the kernel handler has already applied the
  state change or fanned to the bus.

The range itself, the inject-boundary gate, and the registration
gate are spec'd in [`handler-registration.en.md`](handler-registration.en.md) §2a.
Priority=255 within the identity range is kernel-reserved per
[`handler-registration.en.md`](handler-registration.en.md) §4.
Kernel system handlers are re-registered on every `build_topology()` call
so newly added protocol layers are covered without requiring a restart.
The on-disk identifier the helpers act under
(`gn_key_purpose_t`, sub-key registry, on-disk file) lives in
[`identity.en.md`](identity.en.md).

---

## 2. The handler table

| `msg_id` | Handler | Surface | Kernel implementation | Outcome | Spec |
|---|---|---|---|---|---|
| `0x10` | heartbeat (PING/PONG) | plugin-registerable; inject-boundary blocked | `plugins/handlers/heartbeat/` | — (no kernel handler) | extension surface `gn.heartbeat` per [`sdk/extensions/heartbeat.h`](../../sdk/extensions/heartbeat.h) |
| `0x11` | attestation | kernel-only (priority=255, registration blocked for plugins) | `core/kernel/system_handlers.cpp::KernelAttestationHandler` → `attestation_dispatcher.on_inbound` | CONSUMED | [`attestation.en.md`](attestation.en.md) |
| `0x12` | identity rotation announce | kernel priority=255 + plugin-observable at < 255 | `core/kernel/system_handlers.cpp::KernelRotationHandler` → verify + apply_rotation + CONN_EVENT_IDENTITY_ROTATED | CONTINUE (on success; CONSUMED on invalid/replay) | [`identity.en.md`](identity.en.md) §10 |
| `0x13` | capability blob distribution | kernel priority=255 + plugin-observable at < 255 | `core/kernel/system_handlers.cpp::KernelCapabilityBlobHandler` → `CapabilityBlobBus::on_inbound` | CONTINUE | [`capability-tlv.en.md`](capability-tlv.en.md) |
| `0x14` | user-level 2FA challenge | plugin-registerable; inject-boundary blocked | apps register handlers on this `msg_id` | — | [`identity.en.md`](identity.en.md) §6 |
| `0x15` | user-level 2FA response | plugin-registerable; inject-boundary blocked | apps register handlers on this `msg_id` | — | [`identity.en.md`](identity.en.md) §6 |
| `0x16..0x1F` | reserved | — | — | — | future expansion |

Three access classes share the range:

- **Kernel-first, registration blocked (`0x11`).** The kernel
  registers a priority=255 handler for attestation at
  `gn_core_start()`. Plugins cannot register on `0x11`
  (`GN_ERR_INVALID_ENVELOPE`). The kernel handler returns CONSUMED
  so no lower-priority handler ever sees attestation bytes.
- **Kernel-first, plugin-observable (`0x12`, `0x13`).** The kernel
  registers priority=255 handlers at `gn_core_start()`. Plugins
  may additionally register at priority 0–254. On a valid rotation
  (`0x12`) the kernel handler applies the state change, fires
  `GN_CONN_EVENT_IDENTITY_ROTATED`, then returns CONTINUE so
  observing plugins receive the envelope with `conn_id` stamped.
  On invalid proof or replay, the kernel handler returns CONSUMED
  (drops silently). For capability blobs (`0x13`) the kernel
  always fans to `CapabilityBlobBus` then returns CONTINUE.
- **Plugin-registerable (`0x10`, `0x14`, `0x15`).** No kernel
  handler. Apps and bundled plugins register normally. The
  inject-boundary rejects all identity-range ids so a bridge
  plugin cannot spoof an identity event onto a foreign connection.

All three classes fall under `is_identity_range_msg_id()` per
[`handler-registration.en.md`](handler-registration.en.md) §2a.
`is_reserved_system_msg_id()` is narrower: only `0x11` (registration
blocked for plugins). `0x12` and `0x13` are plugin-registerable at
priority < 255; `0x10`, `0x14`, `0x15` are unconstrained in the chain.

---

## 3. Plugin-side typed slots that bypass the `msg_id`

Some system handlers carry typed `host_api_t` slots so plugin
authors do not write raw `msg_id` framing. These slots compose
the wire envelope internally and route through the same kernel
intercept paths.

| Typed slot | Composes | Spec |
|---|---|---|
| `host_api->present_capability_blob` | `0x13` payload + 8-byte BE expiry prefix | [`capability-tlv.en.md`](capability-tlv.en.md) |
| `host_api->subscribe_capability_blob` | receiver-side fan-out from `0x13` intercept | [`capability-tlv.en.md`](capability-tlv.en.md) |
| `host_api->announce_rotation` | `0x12` proof signing + send to live conns | [`identity.en.md`](identity.en.md) §10 |

The typed slots are not strictly necessary — apps could send raw
bytes under `0x12` / `0x13` through the regular `host_api->send`
— but they handle the wire envelope (expiry prefix, signature,
counter bump) inside the kernel so the plugin keeps no
crypto-touching code.

The 2FA pair (`0x14` / `0x15`) is intentionally not behind a
typed slot: app-level UX and threat model (which factor, how to
prompt the user, what fallback) drive the challenge / response
logic, and the kernel only provides the underlying signing
primitive `host_api->sign_local`. See
[`identity.en.md`](identity.en.md) §6 for the recommended
challenge-response pattern.

---

## 4. Adding a new system handler

A new handler in the `0x16..0x1F` slot lands across:

1. `core/kernel/system_handler_ids.hpp` — declare the new
   `constexpr` msg_id. Update `is_reserved_system_msg_id()` if
   plugins must not register on this id (attestation model);
   leave it as-is for plugin-observable ids (rotation model).
2. `core/kernel/system_handlers.{hpp,cpp}` — implement the
   kernel handler struct (vtable + `handle_message` logic).
   Register it via `register_kernel_handler()` alongside the
   existing three handlers in `register_kernel_system_handlers`.
3. The owning subsystem under `core/kernel/` or `core/identity/`
   — implementation details, with private types in their own
   header pair.
4. Wire-format spec — its own contract under
   `docs/contracts/<name>.md` linked from the §2 table here.
5. ABI layout pin — `tests/abi/test_layout.c` if the handler
   adds typed `host_api_t` slots.
6. Conformance test — under `tests/unit/kernel/` or
   `tests/integration/` covering the dispatch, the kernel
   handler's state mutation, and the CONTINUE/CONSUMED outcome.

Each row of §2 above is the documentation contract; adding a
handler without filling the row is a contract bug.

---

## 5. Cross-references

- Reserved-id semantics + register / inject gates:
  [`handler-registration.en.md`](handler-registration.en.md) §2a.
- Identity primitives the handlers act on:
  [`identity.en.md`](identity.en.md).
- Per-handler wire formats: rows of §2 above.
- Capability-blob transport surface: [`capability-tlv.en.md`](capability-tlv.en.md).
- Attestation cert + dispatcher: [`attestation.en.md`](attestation.en.md).
