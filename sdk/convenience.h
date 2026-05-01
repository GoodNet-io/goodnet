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

#include <stdio.h>

#include <sdk/host_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Messaging ───────────────────────────────────────────────────────────── */

#define gn_send(api, conn, msg_id, payload, size) \
    (api)->send((api)->host_ctx, (conn), (msg_id), (payload), (size))

#define gn_disconnect(api, conn) \
    (api)->disconnect((api)->host_ctx, (conn))

/* ── Handler / link registration ─────────────────────────────────────────── */

/* Universal slot under the hood; the typed convenience wrappers keep
 * the caller's existing argument shape and pack the metadata struct
 * into a temporary the kernel can read for the call.
 *
 * The temporary lives in the caller's stack frame for the duration of
 * the `register_vtable` call; the kernel copies / borrows the `name`
 * string per the contract documented on `gn_register_meta_t`. */
#define gn_register_handler(api, protocol_id, msg_id_v, priority_v, vtable, self, out_id) \
    (api)->register_vtable((api)->host_ctx, GN_REGISTER_HANDLER,                \
        &(gn_register_meta_t){                                                  \
            .api_size = sizeof(gn_register_meta_t),                             \
            .name     = (protocol_id),                                          \
            .msg_id   = (msg_id_v),                                             \
            .priority = (priority_v),                                           \
            ._pad     = {0, 0, 0},                                              \
            ._reserved = {0}                                                    \
        },                                                                      \
        (vtable), (self), (uint64_t*)(out_id))

#define gn_unregister_handler(api, id) \
    (api)->unregister_vtable((api)->host_ctx, (uint64_t)(id))

#define gn_register_link(api, scheme, vtable, self, out_id) \
    (api)->register_vtable((api)->host_ctx, GN_REGISTER_LINK,                   \
        &(gn_register_meta_t){                                                  \
            .api_size = sizeof(gn_register_meta_t),                             \
            .name     = (scheme),                                               \
            .msg_id   = 0,                                                      \
            .priority = 0,                                                      \
            ._pad     = {0, 0, 0},                                              \
            ._reserved = {0}                                                    \
        },                                                                      \
        (vtable), (self), (uint64_t*)(out_id))

#define gn_unregister_link(api, id) \
    (api)->unregister_vtable((api)->host_ctx, (uint64_t)(id))

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

/* String reads. The kernel writes a malloc'd NUL-terminated copy
 * into `out_str` and the matching destructor into `out_free`; the
 * plugin frees through (*out_free)(*out_str). */
#define gn_config_get_string(api, key, out_str, out_free)                      \
    (api)->config_get((api)->host_ctx, (key),                                  \
                      GN_CONFIG_VALUE_STRING, GN_CONFIG_NO_INDEX,              \
                      (void*)(out_str), (out_free))

#define gn_config_get_int64(api, key, out_value)                               \
    (api)->config_get((api)->host_ctx, (key),                                  \
                      GN_CONFIG_VALUE_INT64, GN_CONFIG_NO_INDEX,               \
                      (void*)(out_value), NULL)

#define gn_config_get_bool(api, key, out_value)                                \
    (api)->config_get((api)->host_ctx, (key),                                  \
                      GN_CONFIG_VALUE_BOOL, GN_CONFIG_NO_INDEX,                \
                      (void*)(out_value), NULL)

#define gn_config_get_double(api, key, out_value)                              \
    (api)->config_get((api)->host_ctx, (key),                                  \
                      GN_CONFIG_VALUE_DOUBLE, GN_CONFIG_NO_INDEX,              \
                      (void*)(out_value), NULL)

#define gn_config_get_array_size(api, key, out_size)                           \
    (api)->config_get((api)->host_ctx, (key),                                  \
                      GN_CONFIG_VALUE_ARRAY_SIZE, GN_CONFIG_NO_INDEX,          \
                      (void*)(out_size), NULL)

#define gn_config_get_array_int64(api, key, index, out_value)                  \
    (api)->config_get((api)->host_ctx, (key),                                  \
                      GN_CONFIG_VALUE_INT64, (index),                          \
                      (void*)(out_value), NULL)

#define gn_config_get_array_string(api, key, index, out_str, out_free)         \
    (api)->config_get((api)->host_ctx, (key),                                  \
                      GN_CONFIG_VALUE_STRING, (index),                         \
                      (void*)(out_str), (out_free))

/* ── Limits ──────────────────────────────────────────────────────────────── */

#define gn_limits(api) \
    (api)->limits((api)->host_ctx)

/* ── Foreign-payload injection ───────────────────────────────────────────── */

#define gn_inject_external_message(api, source, msg_id, payload, size) \
    (api)->inject((api)->host_ctx, GN_INJECT_LAYER_MESSAGE, \
                  (source), (msg_id), (payload), (size))

#define gn_inject_frame(api, source, frame, size) \
    (api)->inject((api)->host_ctx, GN_INJECT_LAYER_FRAME, \
                  (source), 0, (frame), (size))

/* ── Logging ─────────────────────────────────────────────────────────────── */

/**
 * @brief Render a log line on the plugin's stack, then hand the
 *        formatted bytes to the kernel.
 *
 * `should_log` short-circuits the local `snprintf` when the level
 * is filtered out, so a hot dispatch path that emits
 * `gn_log_debug(...)` while the operator runs at INFO does not
 * pay for formatting a message nobody will see.
 *
 * `__FILE__` and `__LINE__` are captured at macro expansion site
 * so the kernel records the plugin's call-site source location.
 *
 * The kernel's `emit` slot accepts a fully-formatted buffer and
 * does not parse format specifiers — the format-string class of
 * attack against the kernel address space is closed.
 *
 * Truncates at 2048 bytes; longer messages lose the tail.
 */
#define gn_log(api, level, ...) do {                                          \
    const host_api_t* gn_log_api__ = (api);                                   \
    if (gn_log_api__ && gn_log_api__->log.should_log &&                       \
        gn_log_api__->log.emit &&                                             \
        gn_log_api__->log.should_log(gn_log_api__->host_ctx, (level))) {      \
        char gn_log_buf__[2048];                                              \
        (void)snprintf(gn_log_buf__, sizeof(gn_log_buf__), __VA_ARGS__);      \
        gn_log_api__->log.emit(gn_log_api__->host_ctx, (level),               \
                               __FILE__, __LINE__, gn_log_buf__);             \
    }                                                                         \
} while (0)

#define gn_log_trace(api, ...)    gn_log((api), GN_LOG_TRACE, __VA_ARGS__)
#define gn_log_debug(api, ...)    gn_log((api), GN_LOG_DEBUG, __VA_ARGS__)
#define gn_log_info(api, ...)     gn_log((api), GN_LOG_INFO,  __VA_ARGS__)
#define gn_log_warn(api, ...)     gn_log((api), GN_LOG_WARN,  __VA_ARGS__)
#define gn_log_error(api, ...)    gn_log((api), GN_LOG_ERROR, __VA_ARGS__)
#define gn_log_fatal(api, ...)    gn_log((api), GN_LOG_FATAL, __VA_ARGS__)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_CONVENIENCE_H */
