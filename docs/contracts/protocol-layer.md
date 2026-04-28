# Contract: Protocol Layer (kernel↔plugin envelope)

**Status:** active · v1
**Owner:** `core/orchestrator`, `plugins/protocols/*`
**Last verified:** 2026-04-27
**Stability:** breaking changes require kernel ABI bump

---

## 1. Purpose

Mesh-framing is the **single mandatory layer** that lets the kernel route by
public-key without polluting application protocols. This contract defines the
data structure (`gn_message_t`) and interface (`IProtocolLayer`) that kernel
and protocol plugins agree on. Wire bytes belong to the plugin; kernel never
parses bytes itself.

The contract is consumed by:
- `core/kernel` — calls `deframe` on inbound, `frame` on outbound, dispatches
  by `(receiver_pk, msg_id)`.
- `core/registry` — keys connection lookup by `(local_pk, remote_pk)`.
- `plugins/protocols/<name>/` — implements `IProtocolLayer`.

It is **not** consumed by handlers. Handlers see the envelope read-only and
treat `payload` as opaque application bytes.

---

## 2. Envelope: `gn_message_t`

```c
typedef struct gn_message_t {
    uint8_t        sender_pk[32];    // Ed25519 — who originated
    uint8_t        receiver_pk[32];  // Ed25519 — mesh address; ZERO = broadcast
    uint32_t       msg_id;           // routing target inside receiver
    const uint8_t* payload;          // borrowed; valid until handler returns
    size_t         payload_size;
    void*          _reserved[4];     // ABI evolution; must be NULL on init
} gn_message_t;
```

### 2.1 Field semantics

| Field | Meaning | Set by |
|---|---|---|
| `sender_pk` | Ed25519 public key of the originating node. End-to-end identity — relay nodes must NOT rewrite. | Plugin on `deframe`. On `frame`, kernel passes local node identity unless explicit override (inject-external use case). |
| `receiver_pk` | Mesh-level destination. `ZERO` (32 zero bytes) = broadcast. Used for relay routing and multi-tenant dispatch. | Caller of `frame`. On `deframe`, plugin populates from wire (relay/broadcast plugins) or from connection state (direct mesh-native plugins). |
| `msg_id` | Per-protocol routing identifier. Handler registers on `(protocol_id, msg_id)` pair. **Not** a global namespace. | Caller of `frame`. Plugin reads from wire on `deframe`. |
| `payload` | Opaque application bytes. Borrowed pointer — valid only inside the synchronous `handle_message` call. Handler that needs to retain must copy. | Caller of `frame` provides; kernel surfaces in `deframe` output. |
| `payload_size` | Byte count of `payload`. Hard cap enforced by transport layer (default 64 KiB, configurable). | Caller / plugin. |
| `_reserved` | Future ABI evolution. **Must be zero-initialised.** Kernel rejects messages where any reserved slot is non-NULL on the current ABI version. | Kernel asserts. |

### 2.2 Lifetime rules

- `payload` is **borrowed** for the duration of the synchronous handler
  `handle_message` call (see `handler-registration.md`). Plugins
  implementing `frame` must guarantee the same on outbound.
- `gn_message_t` itself lives on the stack of the dispatching thread; its
  pointer **must not** escape `handle_message`.
- Cross-thread or async retention is the consumer's responsibility:
  copy the `payload` bytes into a buffer the consumer owns before
  yielding. The kernel does not extend `payload`'s lifetime past the
  dispatch return.

### 2.3 ZERO `receiver_pk` (broadcast)

A receiver of `ZERO` indicates the message has no specific destination. Kernel
fans out to all registered handlers for the matching `msg_id` regardless of
identity. Broadcast scope is a per-protocol policy (gossip TTL, neighbour-only,
flood) and lives inside the plugin, not the kernel.

A sender **must never** be `ZERO`. Messages with `sender_pk == ZERO` are
dropped at kernel ingress and counted in `metrics.dropped.zero_sender`.

---

## 3. `IProtocolLayer`

The kernel-facing interface is a C ABI vtable declared in
`sdk/protocol.h`. A plugin implements `IProtocolLayer` by populating a
`gn_protocol_layer_vtable_t` and registering it through the host API.
The vtable carries four entry points:

| Entry point | Purpose |
|---|---|
| `protocol_id` | Returns a stable, lowercase, hyphenated string identifying the protocol (e.g. `"gnet-v1"`, `"mesh-v2"`). Used for handler registration scope. |
| `deframe` | Inbound: parses zero or more envelopes out of a decrypted byte stream. The stream may contain partial frames; the plugin reports how many input bytes were consumed and surfaces a sequence of envelopes whose `payload` pointers are borrowed from the input buffer for the duration of the dispatch cycle. |
| `frame` | Outbound: serialises a single envelope into wire bytes. The kernel hands the result to the security layer for encryption, then to the transport for IO. |
| `max_payload_size` | Reports the largest payload the protocol can frame in one message. The kernel consults this for fragmentation decisions. |

`deframe` and `frame` return a `gn_result_t` plus an output buffer
descriptor; see `sdk/protocol.h` for exact field layout. Errors are
mapped to the codes listed in §8.

### 3.1 `ConnectionContext`

Per-connection state is passed to every `deframe` / `frame` call as
`gn_connection_context_t`, declared in `sdk/connection.h`. The
struct is opaque; plugins read it through five accessors:

| Accessor | Returns |
|---|---|
| `gn_ctx_local_pk(ctx)` | borrowed pointer to the 32-byte local Ed25519 public key |
| `gn_ctx_remote_pk(ctx)` | borrowed pointer to the 32-byte peer key; all-zero before the handshake completes |
| `gn_ctx_conn_id(ctx)` | `gn_conn_id_t` allocated by the kernel |
| `gn_ctx_trust(ctx)` | `gn_trust_class_t` per `security-trust.md` |
| `gn_ctx_plugin_state(ctx)` / `gn_ctx_set_plugin_state(ctx, p)` | plugin-private scratch slot; kernel never inspects |

For mesh-native direct connections the plugin reads
`gn_ctx_remote_pk(ctx)` → `sender_pk` (inbound) or
`gn_ctx_local_pk(ctx)` → `sender_pk` (outbound). For relay /
broadcast plugins the public-key fields come from the wire.

---

### 3.2 `gn::wire::WireSchema<T>` for typed payloads

A handler that exchanges a fixed-shape payload (heartbeat,
auto-NAT, relay tunnel header, …) binds a stateless schema type
that satisfies `gn::wire::WireSchema<T>` from `sdk/cpp/wire.hpp`:

```cpp
template <class T>
concept WireSchema = requires {
    typename T::value_type;
    { T::msg_id } -> std::convertible_to<std::uint32_t>;
    { T::size   } -> std::convertible_to<std::size_t>;
    requires std::is_invocable_v<
        decltype(&T::serialize),
        const typename T::value_type&>;
    requires std::is_invocable_r_v<
        std::optional<typename T::value_type>,
        decltype(&T::parse),
        std::span<const std::uint8_t>>;
};
```

A schema is a stateless type (never instantiated) carrying:

- `using value_type = …;` — the in-memory representation
- `static constexpr std::uint32_t msg_id` — protocol-layer routing key
- `static constexpr std::size_t   size`   — fixed wire-frame length
- `static std::array<std::uint8_t, size> serialize(const value_type&) noexcept`
- `static std::optional<value_type> parse(std::span<const std::uint8_t>) noexcept`

`serialize` writes exactly `size` bytes; `parse` returns
`std::nullopt` when the input length is wrong or the bytes do not
decode to a valid `value_type`. Both functions must be `noexcept`.
Implementers add a `static_assert(WireSchema<MySchema>)` next to
the binding to fail fast on a missing or mistyped member.

`HeartbeatSchema` (`plugins/handlers/heartbeat/heartbeat.hpp`) is
the v1 reference binding.

---

## 4. Mandatory single-implementation rule

The kernel binary links **exactly one** `IProtocolLayer` implementation
statically (`target_link_libraries(kernel PUBLIC <impl>)`). Default
implementation: `gnet-v1` in `plugins/protocols/gnet/`. A second
implementation, `raw-v1` in `plugins/protocols/raw/`, is permitted as
a build-time alternative for simulation harnesses, PCAP replay, and
foreign-protocol passthrough; `raw-v1` deframes only on
`GN_TRUST_LOOPBACK` / `GN_TRUST_INTRA_NODE` per `security-trust.md`
§4.

Multi-impl loading at runtime is **not** supported. Future evolution path:
1. Add `mesh-v2` impl alongside `gnet-v1`.
2. Build kernel with `-DGOODNET_MESH_LAYER=mesh-v2`.
3. Cut deprecation release that ships both binaries during transition.
4. Drop `gnet-v1` once ecosystem migrated.

This is intentional — runtime selection of mesh-framing creates wire-format
ambiguity at peer-to-peer handshake. One node, one mesh-format.

---

## 5. Identity sourcing rules

| Scenario | `sender_pk` | `receiver_pk` |
|---|---|---|
| Direct mesh-native, inbound | `ctx.remote` (from Noise) | `ctx.local.public_key` |
| Direct mesh-native, outbound | `ctx.local.public_key` (auto-fill if caller passed ZERO) | caller-specified |
| Relay-extension protocol, inbound | wire-explicit (parsed from frame) | wire-explicit |
| Relay forwarding, transit node | preserved end-to-end (do **not** rewrite) | preserved end-to-end |
| Broadcast (gossip), inbound | wire-explicit (originator) | `ZERO` |
| Inject-external (test/bridge plugin) | caller-specified, kernel does not validate against `ctx.local` | caller-specified |

---

## 6. Routing within kernel

Kernel routing logic — protocol-agnostic:

```
on inbound envelope:
    if envelope.receiver_pk == ZERO:
        dispatch_broadcast(envelope.msg_id, envelope)
    elif envelope.receiver_pk in local_identities:
        dispatch_local(envelope.receiver_pk, envelope.msg_id, envelope)
    else:
        relay_or_drop(envelope)   # delegated to relay-extension if loaded

on outbound from handler:
    plugin = registry.active_protocol_layer
    bytes  = plugin.frame(ctx, envelope)
    encrypted = security.encrypt(ctx, bytes)
    transport.send(ctx, encrypted)
```

`local_identities` is the multi-tenant set: a kernel may host N node
identities sharing one process. Single-identity case = vector of size 1.

---

## 7. Handler registration

```c
host_api->register_handler(host_ctx,
                           "gnet-v1",   /* active protocol; handler bound to this layer */
                           0x1001,      /* msg_id — per-protocol namespace */
                           priority,
                           &handler_vtable,
                           handler_self,
                           &out_handler_id);
```

Handlers are scoped to a `(protocol_id, msg_id)` pair. The same `msg_id`
under different protocols is independent. The per-protocol namespace
prevents collisions between unrelated protocols and lets plugins evolve
their ID space without cross-protocol coordination. See
`handler-registration.md` for the full registration semantics.

---

## 8. Errors

| Code | When kernel produces | Plugin response |
|---|---|---|
| `kErrInvalidEnvelope` | `_reserved` non-zero, `sender_pk == ZERO`, `msg_id == 0` | `frame` must reject these inputs upstream |
| `kErrUnknownReceiver` | `receiver_pk` not in `local_identities` and no relay loaded | drop + metric |
| `kErrPayloadTooLarge` | `payload_size > plugin.max_payload_size()` | caller fragments or fails |
| `kErrDeframeIncomplete` | partial frame, plugin signals `bytes_consumed = 0` | kernel buffers, retries on next chunk |
| `kErrDeframeCorrupt` | plugin signals corruption (magic mismatch, length overflow, etc) | kernel closes connection, increments metric |

---

## 9. Compatibility statement

This contract is **stable for v1.0.x**. Field additions to `gn_message_t`
require ABI bump (`GOODNET_ABI_VERSION` minor → major) and a parallel
`gn_message_v2_t` until removal cycle completes. `_reserved` slots exist
exactly to permit additive evolution without immediate ABI break, but only
the kernel may interpret them.

---

## 10. Cross-references

- Wire details for the canonical mesh-framing implementation:
  `gnet-protocol.md`.
- Noise security: `noise-handshake.md`.
- Transport ABI: `transport.md`.
- Handler registration: `handler-registration.md`.
- Trust-class policy: `security-trust.md`.
- Architectural roadmap: `docs/ROADMAP.md`.
