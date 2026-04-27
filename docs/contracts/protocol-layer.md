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

- `payload` is **borrowed** for the duration of `IHandler::handle_message`.
  Plugins implementing `frame` must guarantee the same on outbound.
- `gn_message_t` itself lives on the stack of the dispatching thread; its
  pointer **must not** escape `handle_message`.
- Cross-thread retention requires `gn_message_dup(const gn_message_t*)` (SDK
  helper, allocates owned copy of payload + struct).

### 2.3 ZERO `receiver_pk` (broadcast)

A receiver of `ZERO` indicates the message has no specific destination. Kernel
fans out to all registered handlers for the matching `msg_id` regardless of
identity. Broadcast scope is a per-protocol policy (gossip TTL, neighbour-only,
flood) and lives inside the plugin, not the kernel.

A sender **must never** be `ZERO`. Messages with `sender_pk == ZERO` are
dropped at kernel ingress and counted in `metrics.dropped.zero_sender`.

---

## 3. `IProtocolLayer`

```cpp
class IProtocolLayer {
public:
    virtual ~IProtocolLayer() = default;

    // Identity for handler registration. Stable, lowercase, hyphenated.
    // Examples: "gnet-v1", "mesh-v2".
    virtual std::string_view protocol_id() const noexcept = 0;

    // Inbound: parse one or more envelopes out of a decrypted byte stream.
    // Stream may contain partial frames; plugin returns consumed-byte count.
    // Returned envelopes are kernel-owned; payload pointers are borrowed
    // from the input buffer for the duration of the dispatch cycle.
    struct DeframeResult {
        std::span<const gn_message_t> messages;
        size_t                        bytes_consumed;
    };
    virtual Result<DeframeResult> deframe(
        ConnectionContext& ctx,
        std::span<const uint8_t> bytes) = 0;

    // Outbound: serialise envelope into wire bytes (handed to security layer
    // for encryption, then transport for IO).
    virtual Result<std::vector<uint8_t>> frame(
        ConnectionContext& ctx,
        const gn_message_t& msg) = 0;

    // Maximum payload size this protocol can frame in a single message.
    // Kernel uses for fragmentation decisions.
    virtual size_t max_payload_size() const noexcept = 0;
};
```

### 3.1 `ConnectionContext`

Per-connection state passed to every `deframe`/`frame` call. Plugin uses to
populate envelope fields when wire does not carry them explicitly:

```cpp
struct ConnectionContext {
    NodeIdentity   local;          // our pk + privkey handle (for sign/verify)
    PublicKey      remote;         // peer pk from Noise handshake
    ConnectionId   conn_id;        // stable per-conn handle
    ProtocolId     active;         // active protocol for this conn
    void*          plugin_state;   // plugin-private, opaque to kernel
};
```

For mesh-native direct conn: plugin reads `ctx.remote` → `sender_pk` (inbound)
or `ctx.local.public_key` → `sender_pk` (outbound). For relay/broadcast: PK
fields come from wire.

---

## 4. Mandatory single-implementation rule

The kernel binary links **exactly one** `IProtocolLayer` implementation
statically (`target_link_libraries(kernel PUBLIC <impl>)`). Default and
currently only blessed implementation: `gnet-v1` in `plugins/protocols/gnet/`.

Multi-impl loading is **not** supported. Future evolution path:
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

```cpp
kernel.register_handler(
    ProtocolId{"gnet-v1"},   // active protocol; handler bound to this layer
    msg_id_t{0x1001},        // local namespace per protocol
    handler_ptr);
```

Handlers are scoped to a `(protocol_id, msg_id)` pair. The same `msg_id`
under different protocols is independent. This avoids the legacy
`MSG_TYPE_*` global-namespace collision risk and lets plugins evolve their
ID space without coordination.

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

- Wire details for the current mesh-framing implementation:
  `docs/contracts/gnet-protocol.md`.
- Security layer contract: `docs/contracts/security-provider.md` (TBD).
- Transport contract: `docs/contracts/transport.md` (TBD).
- Handler contract: `docs/contracts/handler.md` (TBD).
- Architectural decision log: `docs/ROADMAP.md` Phase 0 entry.
