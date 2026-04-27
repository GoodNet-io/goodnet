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
     *        observable connection properties.
     */
    gn_result_t (*notify_connect)(void* host_ctx,
                                  const uint8_t remote_pk[GN_PUBLIC_KEY_BYTES],
                                  const char* uri,
                                  const char* scheme,
                                  gn_trust_class_t trust,
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
