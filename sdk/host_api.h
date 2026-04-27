/**
 * @file   sdk/host_api.h
 * @brief  Public host vtable handed to every plugin at init.
 *
 * Plugins drive the kernel through this single C ABI table. Every
 * operation a plugin can request — sending a message, registering a
 * handler, querying an extension — goes through one of its function
 * pointers.
 *
 * The table is paired with an opaque @c host_ctx pointer that the plugin
 * receives at init time and passes back unchanged on every call. Both
 * `api` and `host_ctx` remain valid from `gn_plugin_init` return until
 * `gn_plugin_shutdown` returns.
 *
 * See `docs/contracts/host-api.md`.
 */
#ifndef GOODNET_SDK_HOST_API_H
#define GOODNET_SDK_HOST_API_H

#include <stdint.h>
#include <stddef.h>

#include <sdk/types.h>
#include <sdk/handler.h>
#include <sdk/limits.h>
#include <sdk/endpoint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations — full vtable types live in their own headers. */
typedef struct gn_handler_vtable_s    gn_handler_vtable_t;
typedef struct gn_transport_vtable_s  gn_transport_vtable_t;

/**
 * @brief Public host vtable.
 *
 * Begins with @ref api_size for size-prefix evolution. New entries are
 * appended at the tail; consumers gate access through `GN_API_HAS`
 * (`sdk/abi.h`).
 */
typedef struct host_api_s {
    /** sizeof(host_api_t) at the producer's build time. */
    uint32_t api_size;

    /* ── Messaging ─────────────────────────────────────────────────────── */

    /**
     * @brief Send an envelope on an existing connection.
     * @param payload @borrowed; copied internally before return.
     */
    gn_result_t (*send)(void* host_ctx,
                        gn_conn_id_t conn,
                        uint32_t msg_id,
                        const uint8_t* payload, size_t payload_size);

    /**
     * @brief Send to a peer identified by URI; opens the connection
     *        on first call.
     */
    gn_result_t (*send_uri)(void* host_ctx,
                            const char* uri,
                            uint32_t msg_id,
                            const uint8_t* payload, size_t payload_size);

    /** Broadcast to every currently connected peer. */
    gn_result_t (*broadcast)(void* host_ctx,
                             uint32_t msg_id,
                             const uint8_t* payload, size_t payload_size);

    /** Close a connection. Safe from any thread. */
    gn_result_t (*disconnect)(void* host_ctx, gn_conn_id_t conn);

    /* ── Handler registration ──────────────────────────────────────────── */

    /**
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

    /* ── Transport registration ────────────────────────────────────────── */

    gn_result_t (*register_transport)(void* host_ctx,
                                      const char* scheme,
                                      const gn_transport_vtable_t* vtable,
                                      void* transport_self,
                                      gn_transport_id_t* out_id);

    gn_result_t (*unregister_transport)(void* host_ctx, gn_transport_id_t id);

    /* ── Registry queries ──────────────────────────────────────────────── */

    /**
     * @return GN_OK and a connection id, or GN_ERR_UNKNOWN_RECEIVER.
     */
    gn_result_t (*find_conn_by_pk)(void* host_ctx,
                                   const uint8_t pk[GN_PUBLIC_KEY_BYTES],
                                   gn_conn_id_t* out_conn);

    /**
     * @param out @in-out; caller allocates, kernel fills.
     */
    gn_result_t (*get_endpoint)(void* host_ctx,
                                gn_conn_id_t conn,
                                gn_endpoint_t* out);

    /* ── Extension API ─────────────────────────────────────────────────── */

    /**
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

    /* ── Configuration ─────────────────────────────────────────────────── */

    /**
     * @param out_str  @owned; caller calls *out_free when done.
     * @param out_free destructor matching @p out_str allocation.
     */
    gn_result_t (*config_get_string)(void* host_ctx,
                                     const char* key,
                                     char** out_str,
                                     void (**out_free)(char*));

    gn_result_t (*config_get_int64)(void* host_ctx,
                                    const char* key,
                                    int64_t* out_value);

    /* ── Limits read access ────────────────────────────────────────────── */

    /**
     * @return @borrowed pointer to the live limits struct; valid for the
     *         plugin's lifetime.
     */
    const gn_limits_t* (*limits)(void* host_ctx);

    /* ── Logging ───────────────────────────────────────────────────────── */

    void (*log)(void* host_ctx,
                gn_log_level_t level,
                const char* fmt, ...);

    /* ── Reserved for future extension ─────────────────────────────────── */

    void* _reserved[8];
} host_api_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_HOST_API_H */
