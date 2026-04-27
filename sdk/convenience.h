/**
 * @file   sdk/convenience.h
 * @brief  One-liner macros for C plugin authors.
 *
 * Hides the `(api)->host_ctx` boilerplate that every vtable call would
 * otherwise repeat. Plugin code that retains a single `api*` pointer
 * uses these macros to call host entries with one argument fewer than
 * the raw vtable invocation:
 *
 * @code
 *     // raw
 *     api->send(api->host_ctx, conn, msg_id, payload, size);
 *
 *     // with this header
 *     gn_send(api, conn, msg_id, payload, size);
 * @endcode
 *
 * C++ plugins typically use the wrappers in `sdk/cpp/` instead. This
 * header is for pure-C plugins and language bindings that prefer the
 * macro style.
 *
 * Include order: any time after `sdk/host_api.h`.
 */
#ifndef GOODNET_SDK_CONVENIENCE_H
#define GOODNET_SDK_CONVENIENCE_H

#include <sdk/host_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Messaging ───────────────────────────────────────────────────────────── */

#define gn_send(api, conn, msg_id, payload, size) \
    (api)->send((api)->host_ctx, (conn), (msg_id), (payload), (size))

#define gn_send_uri(api, uri, msg_id, payload, size) \
    (api)->send_uri((api)->host_ctx, (uri), (msg_id), (payload), (size))

#define gn_broadcast(api, msg_id, payload, size) \
    (api)->broadcast((api)->host_ctx, (msg_id), (payload), (size))

#define gn_disconnect(api, conn) \
    (api)->disconnect((api)->host_ctx, (conn))

/* ── Handler registration ────────────────────────────────────────────────── */

#define gn_register_handler(api, protocol_id, msg_id, priority, vtable, self, out_id) \
    (api)->register_handler((api)->host_ctx, (protocol_id), (msg_id), \
                            (priority), (vtable), (self), (out_id))

#define gn_unregister_handler(api, id) \
    (api)->unregister_handler((api)->host_ctx, (id))

/* ── Transport registration ──────────────────────────────────────────────── */

#define gn_register_transport(api, scheme, vtable, self, out_id) \
    (api)->register_transport((api)->host_ctx, (scheme), (vtable), (self), (out_id))

#define gn_unregister_transport(api, id) \
    (api)->unregister_transport((api)->host_ctx, (id))

/* ── Registry queries ────────────────────────────────────────────────────── */

#define gn_find_conn_by_pk(api, pk, out_conn) \
    (api)->find_conn_by_pk((api)->host_ctx, (pk), (out_conn))

#define gn_get_endpoint(api, conn, out_endpoint) \
    (api)->get_endpoint((api)->host_ctx, (conn), (out_endpoint))

/* ── Extensions ──────────────────────────────────────────────────────────── */

#define gn_query_extension(api, name, version, out_vtable) \
    (api)->query_extension_checked((api)->host_ctx, (name), (version), (out_vtable))

#define gn_register_extension(api, name, version, vtable) \
    (api)->register_extension((api)->host_ctx, (name), (version), (vtable))

/**
 * @brief Inline helper that runs `query_extension_checked` and returns
 *        the resulting vtable pointer (or NULL).
 *
 * Backs the `GN_EXT_CHECKED` macro below. Plain C; no compiler
 * extensions.
 */
static inline const void* gn_query_ext_checked_value(
    const host_api_t* api, const char* name, uint32_t version) {
    const void* vt = NULL;
    if (api && api->query_extension_checked) {
        (void)api->query_extension_checked(api->host_ctx, name, version, &vt);
    }
    return vt;
}

/**
 * @brief Typed-cast wrapper for `query_extension_checked`.
 *
 * Expects the extension's name macro to have a paired `_VERSION` macro
 * (e.g. `GN_EXT_HEARTBEAT` and `GN_EXT_HEARTBEAT_VERSION`). On failure
 * the resulting pointer is NULL and the consumer falls through.
 *
 * @code
 *     const gn_heartbeat_api_t* hb =
 *         GN_EXT_CHECKED(api, GN_EXT_HEARTBEAT, gn_heartbeat_api_t);
 *     if (hb) hb->reset_window(hb_self, conn);
 * @endcode
 */
#define GN_EXT_CHECKED(api, name, type) \
    ((const type*)gn_query_ext_checked_value((api), (name), name##_VERSION))

/* ── Configuration ───────────────────────────────────────────────────────── */

#define gn_config_get_string(api, key, out_str, out_free) \
    (api)->config_get_string((api)->host_ctx, (key), (out_str), (out_free))

#define gn_config_get_int64(api, key, out_value) \
    (api)->config_get_int64((api)->host_ctx, (key), (out_value))

/* ── Limits ──────────────────────────────────────────────────────────────── */

#define gn_limits(api) \
    (api)->limits((api)->host_ctx)

/* ── Logging ─────────────────────────────────────────────────────────────── */

#define gn_log_trace(api, ...)    (api)->log((api)->host_ctx, GN_LOG_TRACE, __VA_ARGS__)
#define gn_log_debug(api, ...)    (api)->log((api)->host_ctx, GN_LOG_DEBUG, __VA_ARGS__)
#define gn_log_info(api, ...)     (api)->log((api)->host_ctx, GN_LOG_INFO,  __VA_ARGS__)
#define gn_log_warn(api, ...)     (api)->log((api)->host_ctx, GN_LOG_WARN,  __VA_ARGS__)
#define gn_log_error(api, ...)    (api)->log((api)->host_ctx, GN_LOG_ERROR, __VA_ARGS__)
#define gn_log_fatal(api, ...)    (api)->log((api)->host_ctx, GN_LOG_FATAL, __VA_ARGS__)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_CONVENIENCE_H */
