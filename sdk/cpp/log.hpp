/// @file   sdk/cpp/log.hpp
/// @brief  C++23 `std::format`-based wrapper around the host-api log
///         substruct (`sdk/log.h`).
///
/// The C SDK macros in `sdk/convenience.h` build the message with
/// `snprintf` — printf-style format specifiers, no type checking. C++
/// plugin authors usually want `std::format`'s type-safe `{}` syntax
/// instead. This header provides that without dragging the kernel's
/// spdlog (or any other formatter library) across the C ABI: the
/// format expansion still happens on the plugin's stack, and only the
/// NUL-terminated UTF-8 buffer crosses into the kernel.
///
/// @code
///     GN_LOGF_INFO(api, "session {} accepted from {}", id, peer);
/// @endcode
///
/// `GN_LOGF_*` macros capture `__FILE__` and `__LINE__` at the call
/// site so the kernel logs the plugin's source location. The function
/// underneath them (`gn::log::emit`) is callable directly when the
/// caller already holds a source location pair (e.g. when forwarding
/// from another logging facade).
///
/// Truncates at 2048 bytes of formatted output; longer messages lose
/// the tail. Same cap as the C macros so the two paths keep parity.
#pragma once

#include <sdk/host_api.h>

#include <cstdint>
#include <format>
#include <utility>

namespace gn::log {

/// @brief Format a log line on the caller's stack and route it to the
///        kernel's logging substruct.
///
/// `should_log` short-circuits the local `std::format_to_n` call when
/// the level is filtered out, so a hot dispatch path that emits at
/// DEBUG while the operator runs at INFO does not pay for formatting
/// a message nobody will see.
///
/// @p api  Host-api pointer; the call is a silent no-op when null,
///         which matches the C macros and keeps tear-down paths
///         crash-free.
/// @p file `__FILE__` of the call site, or `nullptr` to omit the
///         source-location prefix.
/// @p line `__LINE__` of the call site, or zero when @p file is null.
template <class... Args>
inline void emit(const host_api_t*           api,
                  gn_log_level_t              level,
                  const char*                 file,
                  std::int32_t                line,
                  std::format_string<Args...> fmt,
                  Args&&...                   args) {
    if (api == nullptr) return;
    if (api->log.should_log == nullptr || api->log.emit == nullptr) return;
    if (!api->log.should_log(api->host_ctx, level)) return;

    char buf[2048];
    auto result = std::format_to_n(buf, sizeof(buf) - 1, fmt,
                                    std::forward<Args>(args)...);
    *result.out = '\0';

    api->log.emit(api->host_ctx, level, file, line, buf);
}

} // namespace gn::log

/* ── Call-site macros (capture __FILE__ / __LINE__) ─────────────────────── */

#define GN_LOGF_TRACE(api, ...) \
    ::gn::log::emit((api), GN_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)

#define GN_LOGF_DEBUG(api, ...) \
    ::gn::log::emit((api), GN_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)

#define GN_LOGF_INFO(api, ...) \
    ::gn::log::emit((api), GN_LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)

#define GN_LOGF_WARN(api, ...) \
    ::gn::log::emit((api), GN_LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)

#define GN_LOGF_ERROR(api, ...) \
    ::gn::log::emit((api), GN_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)

#define GN_LOGF_FATAL(api, ...) \
    ::gn::log::emit((api), GN_LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)
