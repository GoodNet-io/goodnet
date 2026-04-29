/**
 * @file   sdk/log.h
 * @brief  Plugin-facing logging vtable embedded in `host_api_t`.
 *
 * Plugins emit log lines through `host_api_t::log.emit`. The slot
 * accepts a fully-formatted message buffer plus the calling
 * source file and line; the kernel never invokes `vsnprintf` on
 * plugin-supplied bytes.
 *
 * `should_log` short-circuits the plugin's local formatting on
 * filtered-out levels so a hot dispatch path that emits
 * `gn_log_debug(...)` while the operator is running at INFO does
 * not pay for the `snprintf` of a message that nobody will see.
 *
 * See `docs/contracts/host-api.md` §11.
 */
#ifndef GOODNET_SDK_LOG_H
#define GOODNET_SDK_LOG_H

#include <stdint.h>

#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Plugin-facing logging vtable.
 *
 * Embedded in `host_api_t::log`. The first field carries the
 * struct's size at the producer's build time so consumer plugins
 * gate access to entries beyond their own SDK through
 * `GN_API_HAS_LOG` (`sdk/abi.h`).
 */
typedef struct gn_log_api_s {
    /** sizeof(gn_log_api_t) at producer build time. */
    uint32_t api_size;

    /**
     * @brief Returns 1 when the kernel will emit a message at
     *        @p level, 0 otherwise.
     *
     * Plugins call this on hot paths to skip local `snprintf`
     * when the message would be filtered out.
     */
    int32_t (*should_log)(void* host_ctx, gn_log_level_t level);

    /**
     * @brief Emit a formatted log line.
     *
     * @p msg is a NUL-terminated UTF-8 buffer the plugin formatted
     * on its own stack. The kernel passes it to its sink as a
     * literal — no format specifier is interpreted on the kernel
     * side, closing the format-string class of attack against the
     * kernel address space.
     *
     * @p file and @p line carry the call-site source location.
     * Plugins fill them through the `gn_log_<level>` convenience
     * macros which capture `__FILE__` and `__LINE__` at expansion
     * time. A NULL `file` and zero `line` signal the kernel to
     * omit the source-location prefix.
     */
    void (*emit)(void* host_ctx,
                 gn_log_level_t level,
                 const char* file,
                 int32_t line,
                 const char* msg);

    /** Reserved slots for additive evolution per `abi-evolution.md`. */
    void* _reserved[8];
} gn_log_api_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_LOG_H */
