# Contract: Host API

**Status:** active · v1
**Owner:** `core/kernel`, every plugin
**Implements:** size-prefix evolution per `abi-evolution.md`
**Last verified:** 2026-04-27
**Stability:** stable for v1.x; new entries appended at the tail.

---

## 1. Purpose

Plugins drive the kernel through one C ABI table: `host_api_t`. Every
operation a plugin can request — sending a message, looking up a peer,
querying an extension, registering a handler — goes through one of its
function pointers. The table is handed to the plugin once at init time
and remains live for the plugin's lifetime.

Two distinct vtables exist:

| Table | Audience | When passed |
|---|---|---|
| `host_api_t` | every plugin | once, on `gn_plugin_init` |
| `host_loader_api_t` | kernel-internal `PluginManager` only | never crosses the plugin boundary |

A plugin **cannot** see `host_loader_api_t`. The split is structural;
loader entries (such as `_create_plugin_ctx`) are not even declared in
public headers.

---

## 2. `host_api_t` structure

```c
typedef struct host_api_s {
    uint32_t api_size;             /* sizeof(host_api_t) at build time */

    /**
     * @brief Opaque kernel context. Pass back unchanged on every call.
     *
     * Set by the kernel before `gn_plugin_init` returns. The plugin
     * retains the single `api*` pointer; convenience macros in
     * `sdk/convenience.h` read `api->host_ctx` so that a call site
     * stays one argument shorter than the raw vtable invocation.
     */
    void* host_ctx;

    /* ── Messaging ───────────────────────────────────────────────────── */
    /**
     * @brief Send an envelope to a specific peer over an existing connection.
     * @param payload @borrowed; copied internally before return.
     */
    gn_result_t (*send)(void* host_ctx,
                        gn_conn_id_t conn,
                        uint32_t msg_id,
                        const uint8_t* payload, size_t payload_size);

    /**
     * @brief Send to a peer identified by URI; opens connection if needed.
     */
    gn_result_t (*send_uri)(void* host_ctx,
                            const char* uri,
                            uint32_t msg_id,
                            const uint8_t* payload, size_t payload_size);

    /**
     * @brief Broadcast to all currently-connected peers.
     */
    gn_result_t (*broadcast)(void* host_ctx,
                             uint32_t msg_id,
                             const uint8_t* payload, size_t payload_size);

    /**
     * @brief Close a connection; safe to call from any thread.
     */
    gn_result_t (*disconnect)(void* host_ctx, gn_conn_id_t conn);

    /* ── Handler registration ────────────────────────────────────────── */
    /**
     * @brief Register a handler for a (protocol_id, msg_id) pair.
     * @param vtable @borrowed; must remain valid until unregister.
     */
    gn_result_t (*register_handler)(void* host_ctx,
                                    const char* protocol_id,
                                    uint32_t msg_id,
                                    uint8_t priority,
                                    const gn_handler_vtable_t* vtable,
                                    void* handler_self,
                                    gn_handler_id_t* out_id);

    gn_result_t (*unregister_handler)(void* host_ctx, gn_handler_id_t id);

    /* ── Transport registration ──────────────────────────────────────── */
    gn_result_t (*register_transport)(void* host_ctx,
                                      const char* scheme,
                                      const gn_transport_vtable_t* vtable,
                                      void* transport_self,
                                      gn_transport_id_t* out_id);

    gn_result_t (*unregister_transport)(void* host_ctx, gn_transport_id_t id);

    /* ── Registry queries ────────────────────────────────────────────── */
    /**
     * @brief Find a connection by remote public key.
     * @return GN_OK if found, GN_ERR_UNKNOWN_RECEIVER otherwise.
     */
    gn_result_t (*find_conn_by_pk)(void* host_ctx,
                                   const uint8_t pk[GN_PUBLIC_KEY_BYTES],
                                   gn_conn_id_t* out_conn);

    /**
     * @brief Read endpoint info for a known connection.
     * @param out @in-out; caller allocates, kernel fills.
     */
    gn_result_t (*get_endpoint)(void* host_ctx,
                                gn_conn_id_t conn,
                                gn_endpoint_t* out);

    /* ── Extension API ───────────────────────────────────────────────── */
    /**
     * @brief Look up an extension vtable, verifying its declared version.
     * @param out_vtable @borrowed; lifetime tied to the extension provider.
     */
    gn_result_t (*query_extension_checked)(void* host_ctx,
                                           const char* name,
                                           uint32_t version,
                                           const void** out_vtable);

    gn_result_t (*register_extension)(void* host_ctx,
                                      const char* name,
                                      uint32_t version,
                                      const void* vtable);

    /* ── Configuration ───────────────────────────────────────────────── */
    /**
     * @brief Read a typed config value. Type-suffix in name.
     * @param out_str @owned; caller calls *out_free when done.
     */
    gn_result_t (*config_get_string)(void* host_ctx,
                                     const char* key,
                                     char** out_str,
                                     void (**out_free)(char*));

    gn_result_t (*config_get_int64)(void* host_ctx,
                                    const char* key,
                                    int64_t* out_value);

    /* ── Logging ─────────────────────────────────────────────────────── */
    void (*log)(void* host_ctx,
                gn_log_level_t level,
                const char* fmt, ...);

    /* ── Transport-side notifications ────────────────────────────────── */
    /**
     * @brief Transport announces a fully-established connection.
     *        Allocates a kernel-side `gn_conn_id_t`, returned via @p out_conn.
     *        Per `transport.md` §3 the transport computes `trust` from
     *        observable connection properties; per `transport.md` §3a it
     *        also reports `role` — `GN_ROLE_INITIATOR` for outbound
     *        (`connect(uri)`) and `GN_ROLE_RESPONDER` for inbound
     *        (accepted on `listen`). The kernel forwards `role` to
     *        `security_provider->handshake_open` so the handshake state
     *        machine drives the correct side of the pattern.
     */
    gn_result_t (*notify_connect)(void* host_ctx,
                                  const uint8_t remote_pk[GN_PUBLIC_KEY_BYTES],
                                  const char* uri,
                                  const char* scheme,
                                  gn_trust_class_t trust,
                                  gn_handshake_role_t role,
                                  gn_conn_id_t* out_conn);

    /**
     * @brief Push received bytes through the kernel pipeline:
     *        security decrypt → protocol deframe → router dispatch.
     *        `bytes` is `@borrowed` for the duration of the call.
     */
    gn_result_t (*notify_inbound_bytes)(void* host_ctx,
                                        gn_conn_id_t conn,
                                        const uint8_t* bytes,
                                        size_t size);

    /**
     * @brief Transport announces a connection close.
     *        `reason` is `GN_OK` on a clean close, otherwise the
     *        `gn_result_t` value that triggered teardown.
     */
    gn_result_t (*notify_disconnect)(void* host_ctx,
                                     gn_conn_id_t conn,
                                     gn_result_t reason);

    /* ── Reserved for future use ─────────────────────────────────────── */
    void* _reserved[8];
} host_api_t;
```

Plugins access fields via the version-checked helpers in `sdk/abi.h`:

```c
if (GN_API_HAS(api, pin_handler)) {
    api->pin_handler(host_ctx, conn, handler_id);
}
```

---

## 3. Lifetime of `host_api_t`

The kernel guarantees:

- `api` and every function pointer in it remain valid from
  `gn_plugin_init` return until `gn_plugin_shutdown` returns.
- Calls into `api` are thread-safe; the kernel serialises internally.
- `api->host_ctx` is opaque to the plugin; passed back unchanged.
- A plugin **must not** retain `api` past `gn_plugin_shutdown`. Posting
  a task that fires after shutdown and dereferences `api` would be a
  use-after-free.

Per `plugin-lifetime.md` §4, async tasks capture a weak observer of the
plugin's reference-counted handle and upgrade before using `api`.

---

## 4. What is **not** in `host_api_t`

These belong to `host_loader_api_t` (kernel-internal) and are never
reachable from a plugin:

- `_create_plugin_ctx` — kernel allocates the plugin context.
- `_load_so` / `_unload_so` — `dlopen` / `dlclose` orchestration.
- `_iterate_plugins` — kernel introspection over the plugin set.
- Plugin manifest verification (`plugin-manifest.md` TBD).

A plugin that needs cross-plugin communication uses extensions
(`query_extension_checked`), not loader internals.

---

## 5. Error semantics

Every function pointer returns `gn_result_t`. Negative values are
errors; plugins **must** propagate or handle them. Silently dropping a
non-`GN_OK` return is a contract violation per `fsm-events.md` §4.

The kernel records every error in `metrics.host_api.<entry>.errors`
with the result code as label. This is the surface for production
alerting.

---

## 6. Forbidden inside plugin entries

Plugins **must not**:

- Block on synchronous `send` / `broadcast` for tail responses. The
  kernel enqueues; the call returns immediately. Wait on the response
  handler.
- Call `register_*` from inside a `handle_message` dispatch. The
  handler registry is locked at that point — registration deadlocks.
  Plugins register all handlers in `gn_plugin_register`, not lazily.
- Issue calls to `api` from a thread other than the plugin's own
  io-context unless a slot is documented as cross-thread safe.

The plugin lint pass (`tools/plugin_lint.py`, TBD) flags these
statically.

---

## 7. Cross-references

- Evolution rules: `abi-evolution.md` §3 (size-prefix), §4
  (`_reserved`).
- Init / shutdown ordering: `plugin-lifetime.md`.
- Handler registration semantics: `handler-registration.md`.
- Transport registration semantics: `transport.md` §6.
- Error propagation requirements: `fsm-events.md` §4.

---

## 8. Foreign-payload injection

Bridge handlers connect external systems (MQTT, HTTP, OPC-UA, …) to
the mesh. The external system has no Ed25519 identity of its own; the
bridge — which does — re-publishes incoming foreign payloads under
its own identity through these two entries:

```c
gn_result_t (*inject_external_message)(void* host_ctx,
                                        gn_conn_id_t source,
                                        uint32_t msg_id,
                                        const uint8_t* payload,
                                        size_t payload_size);

gn_result_t (*inject_frame)(void* host_ctx,
                             gn_conn_id_t source,
                             const uint8_t* frame,
                             size_t frame_size);
```

`inject_external_message` builds an envelope `(sender_pk =
source.remote_pk, receiver_pk = local_identity, msg_id, payload)` and
dispatches it through the router as if the bytes had arrived from
the source connection's transport. `inject_frame` accepts a fully
formed wire-side frame, hands it to the active protocol layer's
`deframe`, and dispatches the envelopes the deframe produces. The
two entries differ in who built the envelope: `inject_external_message`
when the bridge knows the application payload, `inject_frame` for
relay-style tunnels that move opaque inner frames between mesh peers.

Failure modes:

| Condition | Result |
|---|---|
| `source` does not refer to a known connection | `GN_ERR_UNKNOWN_RECEIVER` |
| `payload == NULL && size > 0` | `GN_ERR_NULL_ARG` |
| `payload_size > limits.max_payload_bytes` | `GN_ERR_PAYLOAD_TOO_LARGE` |
| `msg_id == 0` (envelope invariant per `protocol-layer.md` §2) | `GN_ERR_INVALID_ENVELOPE` |
| Rate budget exceeded for `source` | `GN_ERR_LIMIT_REACHED` |

Per-source rate limiting uses a token bucket sized at one hundred
messages per second with a burst of fifty by default; the budget is
configurable through `limits.md` §inject. The bucket key is the
`gn_conn_id_t` of the source. The kernel creates buckets lazily;
LRU eviction caps the map at `inject_rate_limit_max_sources` entries
(default 4096) so unbounded source-id growth cannot exhaust memory.

The contract is **not** a downgrade from peer-direct delivery: the
envelope's `sender_pk` is whatever the source connection records as
the remote pk, signed metadata is unchanged, the trust class stays
that of the source connection. Bridges cannot upgrade their own
trust through the inject path.

`inject_frame` does not skip the protocol layer's deframer; a
malformed frame returns the deframer's error verbatim. This rules
out a class of forged-frame attacks where a compromised plugin
synthesises a system-message envelope: the deframer rejects unknown
flags and the framing magic, and the kernel applies the same `msg_id
== 0` and payload-size limits as the regular inbound path.

Implementations live in `core/kernel/host_api_builder.cpp`; the rate
limiter primitive is `core/util/token_bucket.hpp`.
