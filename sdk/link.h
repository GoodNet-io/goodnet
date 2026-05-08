/**
 * @file   sdk/link.h
 * @brief  C ABI vtable for link plugins.
 *
 * Links move bytes. They do not interpret payloads, do not
 * authenticate peers, and do not route messages. See
 * `docs/contracts/link.en.md`.
 */
#ifndef GOODNET_SDK_LINK_H
#define GOODNET_SDK_LINK_H

#include <stdint.h>
#include <stddef.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Scatter-gather descriptor for batched send.
 *
 * Each entry points to a contiguous span of bytes. The link may
 * coalesce them into a single OS-level write (e.g. via `writev`).
 */
typedef struct gn_byte_span_s {
    const uint8_t* bytes;
    size_t         size;
} gn_byte_span_t;

/**
 * @brief Vtable for an `ILink` implementation.
 *
 * Begins with `api_size` for size-prefix evolution per
 * `abi-evolution.md` §3.
 */
typedef struct gn_link_vtable_s {
    uint32_t api_size;          /**< sizeof(gn_link_vtable_t) at producer build time */

    /**
     * @brief Stable lowercase scheme. Examples: `"tcp"`, `"udp"`, `"ws"`.
     *
     * @return @borrowed pointer; valid for the lifetime of the plugin.
     */
    const char* (*scheme)(void* self);

    /**
     * @brief Begin accepting connections matching the scheme.
     *
     * Plugin is responsible for parsing the URI and binding sockets.
     *
     * @param uri @borrowed for the duration of the call.
     */
    gn_result_t (*listen)(void* self, const char* uri);

    /**
     * @brief Initiate an outbound connection.
     *
     * On success the link calls `host_api->notify_connect` once the
     * underlying handshake completes; the call below returns immediately.
     *
     * @param uri @borrowed for the duration of the call.
     */
    gn_result_t (*connect)(void* self, const char* uri);

    /**
     * @brief Send a frame on an existing connection.
     *
     * @param bytes @borrowed for the duration of this call. Link
     *              copies internally if it needs to retain past return.
     */
    gn_result_t (*send)(void* self,
                        gn_conn_id_t conn,
                        const uint8_t* bytes, size_t size);

    /**
     * @brief Send a scatter-gather batch atomically on one connection.
     *
     * The kernel calls this when the send queue holds multiple ready
     * frames; link may use `writev`-style multiplexing internally.
     *
     * The single-writer invariant (`link.md` §4) covers batches: the
     * batch must not interleave with other sends on the same connection.
     */
    gn_result_t (*send_batch)(void* self,
                              gn_conn_id_t conn,
                              const gn_byte_span_t* batch, size_t count);

    /**
     * @brief Close a connection. Idempotent: a second call returns
     *        @ref GN_OK no-op.
     */
    gn_result_t (*disconnect)(void* self, gn_conn_id_t conn);

    /**
     * @brief Per-link extension surface (stats, runtime tweaks).
     *
     * Returns NULL if the link exposes no extension. Otherwise
     * returns a stable name like `"gn.link.tcp"` and the matching
     * vtable through @ref extension_vtable. See `link.md` §8.
     *
     * @return @borrowed name pointer; valid for the lifetime of the
     *         plugin.
     */
    const char* (*extension_name)(void* self);
    /**
     * @return @borrowed vtable pointer; valid while the plugin is
     *         registered. The kernel passes it through
     *         `query_extension_checked` to the consumer.
     */
    const void* (*extension_vtable)(void* self);

    /**
     * @brief Tear down. Called once after `unregister_link` and
     *        full quiescence. Plugin frees `self`-owned resources.
     */
    void (*destroy)(void* self);

    void* _reserved[4];
} gn_link_vtable_t;

GN_VTABLE_API_SIZE_FIRST(gn_link_vtable_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_LINK_H */
