# Contract: System handlers

**Status:** active · v1
**Owner:** `core/kernel/` interception sites + per-handler subsystems
**Last verified:** 2026-05-08
**Stability:** v1.x; the `msg_id` range is locked, individual handler
              wire formats evolve through their own contracts.

---

## 1. Purpose

The kernel reserves the `msg_id` range `0x10..0x1F` for
identity-bearing transport. Every handler in the range either
runs **inside the kernel** (intercepted in `notify_inbound_bytes`
ahead of the regular handler chain) or has the kernel block
inject-boundary spoofing. This document is the navigation index;
each handler's authoritative wire format and behaviour live in
the spec column below.

The range itself, the inject-boundary gate, and the registration
gate are spec'd in [`handler-registration.md`](handler-registration.en.md) §2a.
The on-disk identifier the helpers act under
(`gn_key_purpose_t`, sub-key registry, on-disk file) lives in
[`identity.md`](identity.en.md).

---

## 2. The handler table

| `msg_id` | Handler | Surface | Kernel implementation | Spec |
|---|---|---|---|---|
| `0x10` | reserved | — | — | reserved for future system handler |
| `0x11` | attestation | hard-reserved (kernel intercepts; plugins cannot register) | `core/kernel/attestation_dispatcher.cpp::on_inbound` | [`attestation.md`](attestation.en.md) |
| `0x12` | identity rotation announce | hard-reserved (kernel intercepts) | `core/kernel/host_api_builder.cpp` rotation branch in `notify_inbound_bytes` + `core/identity/rotation.cpp` (verify) + `core/registry/connection.cpp::apply_rotation` | [`identity.md`](identity.en.md) §10 |
| `0x13` | capability blob distribution | hard-reserved (kernel intercepts) | `core/kernel/host_api_builder.cpp` capability branch in `notify_inbound_bytes` + `core/kernel/capability_blob.cpp` (`CapabilityBlobBus`) | [`capability-tlv.md`](capability-tlv.en.md) |
| `0x14` | user-level 2FA challenge | plugin-registerable; inject-boundary blocked | apps register handlers on this `msg_id` | [`identity.md`](identity.en.md) §6 |
| `0x15` | user-level 2FA response | plugin-registerable; inject-boundary blocked | apps register handlers on this `msg_id` | [`identity.md`](identity.en.md) §6 |
| `0x16..0x1F` | reserved | — | — | future expansion |

Two access classes share the range:

- **Hard-reserved (`0x11..0x13`).** The kernel intercepts the
  envelope after the protocol layer's `deframe` step and routes
  it directly to the owning subsystem; the regular handler
  chain never sees the bytes. Plugin attempts to register a
  handler on these ids are rejected by `HandlerRegistry` with
  `GN_ERR_INVALID_ENVELOPE`.
- **Plugin-registerable (`0x14`, `0x15`).** Apps register
  handlers normally and drive challenge / response logic
  themselves. The kernel does not intercept these ids — but
  `host_api->inject(LAYER_MESSAGE)` rejects them through the
  identity-range gate so a bridge plugin cannot spoof a 2FA
  event onto a connection it does not own.

Both classes live under `is_identity_range_msg_id()` per
[`handler-registration.md`](handler-registration.en.md) §2a; the
distinction between hard-reserved and plugin-registerable is
made by `is_reserved_system_msg_id()` (only `0x11..0x13` qualify
today).

---

## 3. Plugin-side typed slots that bypass the `msg_id`

Some system handlers carry typed `host_api_t` slots so plugin
authors do not write raw `msg_id` framing. These slots compose
the wire envelope internally and route through the same kernel
intercept paths.

| Typed slot | Composes | Spec |
|---|---|---|
| `host_api->present_capability_blob` | `0x13` payload + 8-byte BE expiry prefix | [`capability-tlv.md`](capability-tlv.en.md) |
| `host_api->subscribe_capability_blob` | receiver-side fan-out from `0x13` intercept | [`capability-tlv.md`](capability-tlv.en.md) |
| `host_api->announce_rotation` | `0x12` proof signing + send to live conns | [`identity.md`](identity.en.md) §10 |

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
[`identity.md`](identity.en.md) §6 for the recommended
challenge-response pattern.

---

## 4. Adding a new system handler

A new handler in the `0x16..0x1F` slot lands across:

1. `core/kernel/system_handler_ids.hpp` — declare the new
   `constexpr` and update `is_reserved_system_msg_id()` if the
   handler is hard-reserved (kernel intercepts) versus
   plugin-registerable (only inject-blocked).
2. `core/kernel/host_api_builder.cpp` — add an interception
   branch in `notify_inbound_bytes` if hard-reserved; route
   the verified payload to the subsystem.
3. The owning subsystem under `core/kernel/` or `core/identity/`
   — implementation, with private types in their own header
   pair.
4. Wire-format spec — its own contract under
   `docs/contracts/<name>.md` linked from the §2 table here.
5. ABI layout pin — `tests/abi/test_layout.c` if the handler
   adds typed `host_api_t` slots.
6. Conformance test — under `tests/unit/kernel/` or
   `tests/integration/` covering both intercept and reject
   paths.

Each row of §2 above is the documentation contract; adding a
handler without filling the row is a contract bug.

---

## 5. Cross-references

- Reserved-id semantics + register / inject gates:
  [`handler-registration.md`](handler-registration.en.md) §2a.
- Identity primitives the handlers act on:
  [`identity.md`](identity.en.md).
- Per-handler wire formats: rows of §2 above.
- Capability-blob transport surface: [`capability-tlv.md`](capability-tlv.en.md).
- Attestation cert + dispatcher: [`attestation.md`](attestation.en.md).
