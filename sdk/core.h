/**
 * @file   sdk/core.h
 * @brief  Library-as-binary C ABI — full Kernel surface mirrored.
 *
 * `goodnet_kernel` ships as a shared library; `sdk/core.h` is the C
 * ABI a non-C++ host (Rust application, Python tooling, Go panel,
 * WASM browser embed) crosses to drive a kernel from outside the
 * C++ world. Every public method on `gn::core::Kernel` and its
 * registries is reachable through one of the `gn_core_*` entries
 * below.
 *
 * Plugin authors stay on `sdk/host_api.h` — that surface is the
 * inverse direction (kernel → plugin). `sdk/core.h` is application
 * → kernel; the two are independent and a non-C++ binding ships
 * both.
 *
 * Lifecycle:
 *
 * @code
 *     gn_core_t* core = gn_core_create();
 *     gn_core_set_limits(core, &limits);                 // optional
 *     gn_result_t rc = gn_core_init(core);               // identity + protocol
 *     if (rc != GN_OK) { gn_core_destroy(core); return; }
 *     gn_core_load_plugin(core, "/path/libnoise.so", sha256);
 *     gn_core_register_link(core, &my_link_vtable, my_link_self);
 *     gn_core_start(core);                               // accept inbound
 *     // ... gn_core_send_to / gn_core_subscribe / etc ...
 *     gn_core_stop(core);
 *     gn_core_destroy(core);
 * @endcode
 *
 * Threading: every entry is callable from any thread once
 * `gn_core_init` has returned `GN_OK`. The kernel's data path is
 * event-driven; concurrent application threads talking to one
 * `gn_core_t` share the same kernel state through the existing
 * registry mutexes and atomic counters.
 *
 * Drift from the legacy `include/core.h` (audit-driven):
 *  - No `gn_core_register_defaults / register_noise / register_gnet`
 *    — hardcoded plugin names crystallised onto the C ABI; v1.x
 *    rename would break every host. Use `gn_core_load_plugin` with
 *    an explicit path + manifest hash, or compose static plugins at
 *    link time per `feedback_plugin_deployment_modes`.
 *  - No auto-load from `Config::stacks[].transport` — coupled the
 *    config schema to C ABI behaviour. Host loads plugins
 *    explicitly.
 *  - No typed extension accessors (`gn_core_health/relay/dht/…`) —
 *    bindings own the typed-wrapper layer in their own language;
 *    `gn_core_query_extension_checked` is the raw entry.
 *  - Manifest SHA-256 verification is now mandatory on
 *    `gn_core_load_plugin` per `plugin-manifest.md`.
 *
 * See `docs/contracts/core-c.md` for the full contract.
 */
#ifndef GOODNET_SDK_CORE_H
#define GOODNET_SDK_CORE_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/conn_events.h>
#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/limits.h>
#include <sdk/link.h>
#include <sdk/protocol.h>
#include <sdk/security.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque handle ───────────────────────────────────────────────────────── */

/**
 * @brief Forward declaration of the embedded kernel handle.
 *
 * The struct definition is private to `core/kernel/core_c.cpp` —
 * binding callers only ever hold `gn_core_t*` and pass it to the
 * accessors below. Layout is opaque on purpose so internal kernel
 * fields can move freely between minor releases without surface
 * rebuild.
 */
typedef struct gn_core_s gn_core_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/**
 * @brief Allocate a fresh kernel handle.
 *
 * Defaults from `sdk/limits.h` are pre-applied; the host overrides
 * them through `gn_core_set_limits` before `gn_core_init` if needed.
 *
 * @return @owned handle; pair with `gn_core_destroy`. NULL only on
 *         out-of-memory.
 */
GN_EXPORT gn_core_t* gn_core_create(void);

/**
 * @brief Allocate a kernel handle and parse the JSON configuration
 *        text inline.
 *
 * Equivalent to `gn_core_create()` followed by
 * `gn_core_reload_config_json(core, json_str)`. Required for browser
 * / WASM hosts and any embedder that ships its config as a string.
 *
 * @param json_str @borrowed NUL-terminated JSON document; copied
 *                 internally before return.
 *
 * @return @owned handle; pair with `gn_core_destroy`. NULL on
 *         out-of-memory or when the JSON fails to parse.
 */
GN_EXPORT gn_core_t* gn_core_create_from_json(const char* json_str);

/**
 * @brief Tear down the kernel and free the handle.
 *
 * Walks the FSM through `PreShutdown → Shutdown`, drains plugin
 * anchors per `plugin-lifetime.md` §4 (default 1 s), publishes
 * `DISCONNECTED` for every live connection, and frees the handle.
 * `gn_core_destroy(NULL)` is a no-op.
 */
GN_EXPORT void gn_core_destroy(gn_core_t* core);

/**
 * @brief Bring the kernel to the `Ready` phase.
 *
 * Generates a fresh `NodeIdentity` (Ed25519 device keypair) when
 * none has been installed by the host, registers the canonical
 * `gnet-v1` protocol layer, and walks the FSM through `Load → Wire
 * → Resolve → Ready`. Plugins (link, security, handler) are NOT
 * loaded here — the host registers them through
 * `gn_core_load_plugin` / `gn_core_register_*` after init returns.
 *
 * @return `GN_OK` on success; `GN_ERR_INVALID_STATE` if the kernel
 *         is past `Phase::Ready`; `GN_ERR_INTEGRITY_FAILED` when
 *         identity generation fails (libsodium error).
 */
GN_EXPORT gn_result_t gn_core_init(gn_core_t* core);

/**
 * @brief Advance the kernel from `Ready` to `Running`. After this
 *        the kernel accepts inbound traffic and dispatches.
 *
 * Idempotent — calling on an already-Running kernel returns `GN_OK`
 * with no effect. The function returns immediately; the kernel is
 * event-driven and runs whenever a link plugin posts inbound bytes.
 */
GN_EXPORT gn_result_t gn_core_start(gn_core_t* core);

/**
 * @brief Trigger graceful shutdown.
 *
 * Walks the FSM through `PreShutdown → Shutdown`, drains plugin
 * anchors, publishes `DISCONNECTED` for every live connection.
 * Idempotent. Concurrent callers race through a single
 * compare-and-exchange.
 */
GN_EXPORT void gn_core_stop(gn_core_t* core);

/**
 * @brief Block the calling thread until `gn_core_stop` has fired
 *        and the kernel reaches `Phase::Shutdown`.
 *
 * Useful as the main-thread idle wait in single-threaded hosts.
 * Multi-threaded hosts typically use it on a dedicated «kernel
 * lifetime» thread.
 */
GN_EXPORT void gn_core_wait(gn_core_t* core);

/**
 * @brief Non-zero iff the kernel is currently in `Phase::Running`.
 *
 * Cheap, lock-free read.
 */
GN_EXPORT int gn_core_is_running(gn_core_t* core);

/**
 * @brief Reload kernel-side config from a JSON document.
 *
 * The kernel re-parses, validates, and applies the new config. On
 * failure the previous config remains active — the kernel never
 * lands in a partially-applied state. Subscribers fire on the
 * `on_config_reload` channel after a successful reload.
 *
 * @param json_str @borrowed; copied internally before return.
 */
GN_EXPORT gn_result_t gn_core_reload_config_json(gn_core_t* core,
                                                 const char* json_str);

/* ── Configuration & limits ──────────────────────────────────────────────── */

/**
 * @brief Snapshot of the kernel's active limits.
 *
 * @return @borrowed pointer; lifetime tied to @p core.
 */
GN_EXPORT const gn_limits_t* gn_core_limits(gn_core_t* core);

/**
 * @brief Apply a new limits struct.
 *
 * Must be called before `gn_core_init` — limit changes after
 * `Phase::Ready` are rejected with `GN_ERR_INVALID_STATE`. The
 * kernel copies @p limits; the input pointer is not retained.
 *
 * @param limits @borrowed; must be zero-initialised per
 *               `abi-evolution.md` §4.
 */
GN_EXPORT gn_result_t gn_core_set_limits(gn_core_t* core,
                                         const gn_limits_t* limits);

/* ── Identity ────────────────────────────────────────────────────────────── */

/**
 * @brief Read the local node's Ed25519 device public key.
 *
 * Available after `gn_core_init` returns `GN_OK`.
 *
 * @param out_pk @borrowed caller-allocated 32-byte buffer.
 *
 * @return `GN_OK` on success; `GN_ERR_INVALID_STATE` if the kernel
 *         has no identity yet; `GN_ERR_NULL_ARG` when @p out_pk
 *         is NULL.
 */
GN_EXPORT gn_result_t gn_core_get_pubkey(
    gn_core_t* core,
    uint8_t out_pk[GN_PUBLIC_KEY_BYTES]);

/* ── Network ─────────────────────────────────────────────────────────────── */

/**
 * @brief Initiate an outbound connection through the link plugin
 *        registered for @p scheme.
 *
 * Resolves the `gn.link.<scheme>` extension and calls
 * `connect(uri, &out_conn)` on its `gn_link_api_t` vtable. Pass
 * @p scheme as NULL to derive it from the URI prefix
 * (`tcp://`, `udp://`, `ws://`, `ipc://`).
 *
 * @param uri      @borrowed for the duration of the call.
 * @param scheme   @borrowed; NULL → derive from @p uri prefix.
 * @param out_conn caller-allocated; receives the kernel
 *                 `gn_conn_id_t` on success.
 *
 * @return `GN_OK` on success; `GN_ERR_NOT_FOUND` when no link is
 *         registered for the scheme; whatever the link plugin's
 *         `connect` returns on transport-level failure.
 */
GN_EXPORT gn_result_t gn_core_connect(gn_core_t* core,
                                       const char* uri,
                                       const char* scheme,
                                       gn_conn_id_t* out_conn);

/**
 * @brief Send a single application message on @p conn.
 *
 * Frames @p payload through the active protocol layer, encrypts
 * through the bound security session, and hands the bytes to the
 * link plugin's `send`. Equivalent to `host_api->send(...)` from a
 * plugin context.
 *
 * @param payload @borrowed for the duration of the call.
 */
GN_EXPORT gn_result_t gn_core_send_to(gn_core_t* core,
                                       gn_conn_id_t conn,
                                       uint32_t msg_id,
                                       const uint8_t* payload,
                                       size_t payload_size);

/**
 * @brief Send @p payload to every live connection.
 *
 * Each frame is independently broadcast via `gn_core_send_to`;
 * partial failures do not stop the walk.
 */
GN_EXPORT void gn_core_broadcast(gn_core_t* core,
                                 uint32_t msg_id,
                                 const uint8_t* payload,
                                 size_t payload_size);

/**
 * @brief Tear down @p conn through the owning link plugin's
 *        `disconnect` slot.
 */
GN_EXPORT gn_result_t gn_core_disconnect(gn_core_t* core, gn_conn_id_t conn);

/* ── Stats / introspection ───────────────────────────────────────────────── */

/**
 * @brief Aggregate counters for at-a-glance status.
 *
 * Each field is a snapshot at call time; reads are not coordinated
 * — concurrent traffic may bump counters between field-by-field
 * reads. Per-frame consistency is bounded by the kernel's atomic
 * counter granularity.
 */
typedef struct gn_stats_s {
    /** sizeof(gn_stats_t) at producer build time per
     *  `abi-evolution.md` §3. */
    uint32_t api_size;
    uint64_t connections_active;       /**< live entries in `ConnectionRegistry` */
    uint64_t handlers_registered;      /**< live entries in `HandlerRegistry`    */
    uint64_t links_registered;         /**< live entries in `LinkRegistry`       */
    uint64_t extensions_registered;    /**< live entries in `ExtensionRegistry`  */
    uint64_t bytes_in;                 /**< sum of per-conn `bytes_in`           */
    uint64_t bytes_out;                /**< sum of per-conn `bytes_out`          */
    uint64_t frames_in;                /**< sum of per-conn `frames_in`          */
    uint64_t frames_out;               /**< sum of per-conn `frames_out`         */
    uint64_t plugin_dlclose_leaks;     /**< from `plugin.leak.dlclose_skipped`   */
    void*    _reserved[4];             /**< MUST be zero per abi-evolution.md §4 */
} gn_stats_t;

GN_VTABLE_API_SIZE_FIRST(gn_stats_t);

/**
 * @brief Snapshot the aggregate counters into @p out.
 *
 * @param out @borrowed caller-allocated; must be zero-initialised
 *            on first call.
 */
GN_EXPORT gn_result_t gn_core_get_stats(gn_core_t* core, gn_stats_t* out);

/** Number of live connection records. Lock-free read. */
GN_EXPORT size_t gn_core_connection_count(gn_core_t* core);

/** Number of live handler registrations. Lock-free read. */
GN_EXPORT size_t gn_core_handler_count(gn_core_t* core);

/** Number of live link registrations. Lock-free read. */
GN_EXPORT size_t gn_core_link_count(gn_core_t* core);

/* ── Subscriptions ───────────────────────────────────────────────────────── */

/**
 * @brief Application-level message subscription.
 *
 * Receives every inbound envelope whose `msg_id` matches @p msg_id
 * after the kernel has dispatched it through the priority chain.
 * Re-entrancy: callbacks fire on the kernel's dispatch thread; do
 * not block.
 *
 * @param cb        @borrowed function pointer; the kernel keeps
 *                  it alive until `gn_core_unsubscribe` returns.
 * @param user_data @borrowed by the kernel under the same lifetime
 *                  as @p cb; pass-through to every callback.
 *
 * @return non-zero subscription token on success, 0 on failure.
 */
typedef void (*gn_message_cb_t)(void* user_data,
                                gn_conn_id_t conn,
                                uint32_t msg_id,
                                const uint8_t* payload,
                                size_t payload_size);

GN_EXPORT uint64_t gn_core_subscribe(gn_core_t* core,
                                     uint32_t msg_id,
                                     gn_message_cb_t cb,
                                     void* user_data);

/** Cancel a subscription by token. No-op on unknown token. */
GN_EXPORT void gn_core_unsubscribe(gn_core_t* core, uint64_t token);

/**
 * @brief Connection-event subscription (CONNECTED / DISCONNECTED /
 *        TRUST_UPGRADED / BACKPRESSURE_*).
 *
 * @param cb        @borrowed function pointer; lifetime as in
 *                  `gn_core_subscribe`.
 * @param user_data @borrowed; pass-through to every callback.
 *
 * @return non-zero token on success, 0 on failure.
 */
typedef void (*gn_conn_event_cb_t)(void* user_data,
                                   const gn_conn_event_t* ev);

GN_EXPORT uint64_t gn_core_on_conn_state(gn_core_t* core,
                                          gn_conn_event_cb_t cb,
                                          void* user_data);

/** Cancel a connection-event subscription. */
GN_EXPORT void gn_core_off_conn_state(gn_core_t* core, uint64_t token);

/* ── Plugin lifecycle ────────────────────────────────────────────────────── */

/**
 * @brief Load a plugin shared object after manifest verification.
 *
 * The loader resolves @p so_path against the executable's directory
 * (`<exe>/<rel>` and `<exe>/lib/<rel>`) to close the
 * `LD_LIBRARY_PATH` hijack vector, computes SHA-256 over the file
 * contents, compares against @p expected_sha256, then `dlopen`s
 * with `RTLD_NOW | RTLD_LOCAL` and drives the 5+1 plugin entry
 * symbols (`gn_plugin_sdk_version`, `gn_plugin_init`,
 * `gn_plugin_register`, `gn_plugin_unregister`, `gn_plugin_shutdown`,
 * optional `gn_plugin_descriptor`) per `plugin-lifetime.md` §3.
 *
 * @param so_path           @borrowed exe-relative path to the .so.
 * @param expected_sha256   @borrowed 32-byte SHA-256 digest the
 *                          host computed at manifest time. The
 *                          loader rejects on mismatch with
 *                          `GN_ERR_INTEGRITY_FAILED`.
 *
 * @return `GN_OK` on success; `GN_ERR_NOT_FOUND` when the path
 *         escapes the executable's directory; `GN_ERR_INTEGRITY_FAILED`
 *         on hash mismatch; `GN_ERR_VERSION_MISMATCH` on SDK
 *         major-version drift; the plugin's own init error code on
 *         setup failure.
 */
GN_EXPORT gn_result_t gn_core_load_plugin(
    gn_core_t* core,
    const char* so_path,
    const uint8_t expected_sha256[32]);

/**
 * @brief Unload a previously loaded plugin by name.
 *
 * Walks the shutdown sequence per `plugin-lifetime.md` §4 (publish
 * `shutdown_requested`, `gn_plugin_unregister`, drain anchor,
 * `gn_plugin_shutdown`, `dlclose`).
 *
 * @param name @borrowed plugin name as registered in its
 *             descriptor.
 */
GN_EXPORT gn_result_t gn_core_unload_plugin(gn_core_t* core, const char* name);

/* ── Provider registration (in-process, no .so) ──────────────────────────── */

/**
 * @brief Register an in-process security provider vtable.
 *
 * Equivalent to a plugin's `host_api->register_vtable(GN_REGISTER_SECURITY,
 * meta, vtable, self)`. Use when the host wants to inject a custom
 * Noise / null / TLS provider without going through `dlopen`.
 *
 * @param meta   @borrowed metadata (name, api_size). Must be
 *               zero-initialised per `abi-evolution.md` §4.
 * @param vtable @borrowed for the lifetime of the registration.
 * @param self   @borrowed plugin instance pointer.
 */
GN_EXPORT gn_result_t gn_core_register_security(
    gn_core_t* core,
    const gn_register_meta_t* meta,
    const gn_security_provider_vtable_t* vtable,
    void* self);

/**
 * @brief Register an in-process protocol layer.
 *
 * The kernel statically links exactly one protocol layer
 * (`gnet-v1` by default after `gn_core_init`). This entry overrides
 * the layer for hosts that want a custom mesh-framing
 * implementation.
 *
 * @param vtable @borrowed for the lifetime of the registration.
 * @param self   @borrowed plugin instance pointer.
 */
GN_EXPORT gn_result_t gn_core_register_protocol(
    gn_core_t* core,
    const gn_protocol_layer_vtable_t* vtable,
    void* self);

/**
 * @brief Register an in-process handler vtable.
 *
 * Equivalent to `host_api->register_vtable(GN_REGISTER_HANDLER, …)`.
 *
 * @return non-zero handler id on success, 0 on failure.
 */
GN_EXPORT gn_handler_id_t gn_core_register_handler(
    gn_core_t* core,
    const gn_register_meta_t* meta,
    const gn_handler_vtable_t* vtable,
    void* self);

/**
 * @brief Register an in-process link vtable.
 *
 * Equivalent to `host_api->register_vtable(GN_REGISTER_LINK, …)`.
 *
 * @return non-zero link id on success, 0 on failure.
 */
GN_EXPORT gn_link_id_t gn_core_register_link(
    gn_core_t* core,
    const gn_register_meta_t* meta,
    const gn_link_vtable_t* vtable,
    void* self);

/* ── Extensions ──────────────────────────────────────────────────────────── */

/**
 * @brief Versioned vtable lookup. Returns NULL when the extension
 *        is missing or the registered version is incompatible.
 *
 * Bindings (Rust traits, Python class wrappers) build their typed
 * accessors on top of this raw entry — no per-extension typed C
 * function is exposed in `sdk/core.h` so adding a new extension
 * never bumps the `sdk/core.h` ABI.
 *
 * @return @borrowed vtable; lifetime tied to the providing plugin.
 */
GN_EXPORT const void* gn_core_query_extension_checked(
    gn_core_t* core,
    const char* name,
    uint32_t required_version);

/**
 * @brief Register an extension vtable under @p name.
 *
 * Equivalent to `host_api->register_extension(name, version, vtable)`.
 *
 * @param version producer-side version pin; consumers
 *                `query_extension_checked(name, required_version)`
 *                fail when @p version is older or major-different.
 * @param vtable  @borrowed for the lifetime of the registration.
 */
GN_EXPORT gn_result_t gn_core_register_extension(
    gn_core_t* core,
    const char* name,
    uint32_t version,
    const void* vtable);

/** Cancel an extension registration by name. */
GN_EXPORT gn_result_t gn_core_unregister_extension(gn_core_t* core,
                                                    const char* name);

/* ── host_api accessor ───────────────────────────────────────────────────── */

/**
 * @brief Hand the host a `host_api_t` shaped against the embedded
 *        kernel.
 *
 * Most hosts do not need this — `gn_core_*` covers the lifecycle,
 * provider registration, and network paths. Reach for it when the
 * host wants to drive a slot on `host_api_t` that has no `gn_core_*`
 * mirror (timers, posted tasks, structured logging at a custom
 * level).
 *
 * The returned table lives inside the kernel handle. Do not free.
 *
 * @return @borrowed pointer; lifetime tied to @p core.
 */
GN_EXPORT const host_api_t* gn_core_host_api(gn_core_t* core);

/* ── Version ─────────────────────────────────────────────────────────────── */

/** Human-readable version string ("0.1.0", "1.0.0-rc1", …). */
GN_EXPORT const char* gn_version(void);

/** Packed `(MAJOR << 16) | (MINOR << 8) | PATCH`. */
GN_EXPORT uint32_t gn_version_packed(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_CORE_H */
