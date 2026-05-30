// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/log.hpp
/// @brief  Type-safe logging for C++ plugins.
///
/// ## Quick start
///
/// ### Method 1 — Logger object (recommended)
///
/// Store a `gn::log::Logger` in your plugin class and call level methods
/// directly.  No `api` or `__FILE__`/`__LINE__` at every call site:
///
/// ```cpp
/// class MyHandler {
///     gn::log::Logger log_;
/// public:
///     explicit MyHandler(const host_api_t* api) : log_(api) {}
///
///     gn_propagation_t handle_message(const gn_message_t& m) {
///         log_.info("handling msg {:#x}", m.msg_id);
///         if (bad) { log_.warn("rejected: {}", reason); return REJECT; }
///         return PROPAGATE;
///     }
/// };
/// ```
///
/// ### Method 2 — free function (source_location, no macros needed)
///
/// ```cpp
/// gn::log::warn(api, "tcp: connection {} closed", id);
/// ```
///
/// Source location is captured automatically at the call site via
/// `std::source_location` — no `__FILE__` / `__LINE__` macros required.
///
/// ### Method 3 — legacy macros (C-parity, still supported)
///
/// ```cpp
/// GN_LOGF_WARN(api, "tcp: {}", msg);   // C++ std::format syntax
/// gn_log_warn(api,  "tcp: %s", msg);   // C snprintf syntax (convenience.h)
/// ```
///
/// ## Truncation
///
/// Formatted output longer than `kLogBufBytes - 1` bytes is truncated and
/// suffixed with `" ..."` so the reader can see something was cut.

#pragma once

#include <sdk/host_api.h>
#include <sdk/cpp/contract.hpp>

#include <cstdint>
#include <format>
#include <source_location>
#include <utility>

namespace gn::log {

/// Stack buffer capacity for log messages.  Messages that overflow are
/// truncated and suffixed with " ..." (see below).
inline constexpr std::size_t kLogBufBytes = 2048;

// ── Internal: low-level emit (pre-formatted buffer) ──────────────────────────

namespace detail {

/// Route a pre-formatted buffer to the kernel log sink.
/// Short-circuits silently when api is null or the level is filtered.
inline void emit_buf(const host_api_t* api,
                     gn_log_level_t    level,
                     const char*       file,
                     std::int32_t      line,
                     const char*       buf) noexcept
    GN_EXPECTS(buf != nullptr)
{
    if (!api || !api->log.should_log || !api->log.emit) return;
    if (!api->log.should_log(api->host_ctx, level)) return;
    api->log.emit(api->host_ctx, level, file, line, buf);
}

} // namespace detail

// ── Fmt<Args...> — captures source_location as consteval default ──────────────

/// Tag struct whose constructor captures `std::source_location::current()`
/// as a `consteval` default argument.  Enables the free `emit()` functions
/// below to record the *call site* location without any macro machinery.
///
/// Users never spell this type explicitly — it is deduced from the format
/// string literal passed to `info()`, `warn()`, etc.
template <class... Args>
struct Fmt {
    std::format_string<Args...> str;
    std::source_location        loc;

    // consteval constructor: loc defaults to the CALL SITE of `Fmt{…}`
    // which is the point where `info(api, "…", args...)` is written.
    consteval Fmt(
        std::format_string<Args...>      s,
        std::source_location             l = std::source_location::current())
        : str(s), loc(l) {}
};

// ── Free emit functions — no macros, source_location auto-captured ────────────

/// Emit a log line at @p level.  Source location is captured from the call
/// site automatically; no `__FILE__` / `__LINE__` arguments needed.
template <class... Args>
inline void emit(const host_api_t* api,
                 gn_log_level_t    level,
                 Fmt<Args...>      fmt,
                 Args&&...         args) noexcept
    GN_EXPECTS(api != nullptr)
{
    if (!api || !api->log.should_log || !api->log.emit) return;
    if (!api->log.should_log(api->host_ctx, level)) return;

    char buf[kLogBufBytes];
    // Reserve 5 bytes for " ..." truncation suffix + NUL.
    auto r = std::format_to_n(buf, kLogBufBytes - 5,
                               fmt.str, std::forward<Args>(args)...);
    if (r.size >= kLogBufBytes - 5) {
        // Message was truncated — append visible marker.
        char* end = buf + (kLogBufBytes - 5);
        end[0] = ' '; end[1] = '.'; end[2] = '.'; end[3] = '.'; end[4] = '\0';
    } else {
        *r.out = '\0';
    }

    api->log.emit(api->host_ctx, level,
                  fmt.loc.file_name(),
                  static_cast<std::int32_t>(fmt.loc.line()),
                  buf);
}

template <class... Args>
inline void trace(const host_api_t* api, Fmt<Args...> fmt, Args&&... args) noexcept {
    emit(api, GN_LOG_TRACE, fmt, std::forward<Args>(args)...);
}
template <class... Args>
inline void debug(const host_api_t* api, Fmt<Args...> fmt, Args&&... args) noexcept {
    emit(api, GN_LOG_DEBUG, fmt, std::forward<Args>(args)...);
}
template <class... Args>
inline void info(const host_api_t* api, Fmt<Args...> fmt, Args&&... args) noexcept {
    emit(api, GN_LOG_INFO, fmt, std::forward<Args>(args)...);
}
template <class... Args>
inline void warn(const host_api_t* api, Fmt<Args...> fmt, Args&&... args) noexcept {
    emit(api, GN_LOG_WARN, fmt, std::forward<Args>(args)...);
}
template <class... Args>
inline void error(const host_api_t* api, Fmt<Args...> fmt, Args&&... args) noexcept {
    emit(api, GN_LOG_ERROR, fmt, std::forward<Args>(args)...);
}
template <class... Args>
inline void fatal(const host_api_t* api, Fmt<Args...> fmt, Args&&... args) noexcept {
    emit(api, GN_LOG_FATAL, fmt, std::forward<Args>(args)...);
}

// ── Logger — RAII wrapper that holds the api pointer ────────────────────────

/// Holds `const host_api_t*` and exposes level methods so plugin classes
/// can log without passing `api` at every call site.
///
/// ```cpp
/// class MyLink {
///     gn::log::Logger log_;
/// public:
///     explicit MyLink(const host_api_t* api) : log_(api) {}
///     void on_data(...) { log_.debug("rx {} bytes", n); }
/// };
/// ```
class Logger {
public:
    explicit Logger(const host_api_t* api) noexcept : api_(api) {}

    Logger()                         = default;
    Logger(const Logger&)            = default;
    Logger& operator=(const Logger&) = default;

    [[nodiscard]] bool should_log(gn_log_level_t level) const noexcept {
        return api_ && api_->log.should_log &&
               api_->log.should_log(api_->host_ctx, level);
    }

    template <class... Args>
    void trace(Fmt<Args...> fmt, Args&&... args) const noexcept {
        gn::log::trace(api_, fmt, std::forward<Args>(args)...);
    }
    template <class... Args>
    void debug(Fmt<Args...> fmt, Args&&... args) const noexcept {
        gn::log::debug(api_, fmt, std::forward<Args>(args)...);
    }
    template <class... Args>
    void info(Fmt<Args...> fmt, Args&&... args) const noexcept {
        gn::log::info(api_, fmt, std::forward<Args>(args)...);
    }
    template <class... Args>
    void warn(Fmt<Args...> fmt, Args&&... args) const noexcept {
        gn::log::warn(api_, fmt, std::forward<Args>(args)...);
    }
    template <class... Args>
    void error(Fmt<Args...> fmt, Args&&... args) const noexcept {
        gn::log::error(api_, fmt, std::forward<Args>(args)...);
    }
    template <class... Args>
    void fatal(Fmt<Args...> fmt, Args&&... args) const noexcept {
        gn::log::fatal(api_, fmt, std::forward<Args>(args)...);
    }

    /// Update the api pointer (e.g. after hot-reload gives a fresh host_api).
    void reset(const host_api_t* api) noexcept { api_ = api; }

    [[nodiscard]] const host_api_t* api() const noexcept { return api_; }

private:
    const host_api_t* api_ = nullptr;
};

} // namespace gn::log

// ── Legacy macros — backward-compat, C-parity ────────────────────────────────
// Prefer the macro-free forms above in new code.

#define GN_LOGF_TRACE(api, ...) \
    ::gn::log::trace((api), __VA_ARGS__)

#define GN_LOGF_DEBUG(api, ...) \
    ::gn::log::debug((api), __VA_ARGS__)

#define GN_LOGF_INFO(api, ...) \
    ::gn::log::info((api), __VA_ARGS__)

#define GN_LOGF_WARN(api, ...) \
    ::gn::log::warn((api), __VA_ARGS__)

#define GN_LOGF_ERROR(api, ...) \
    ::gn::log::error((api), __VA_ARGS__)

#define GN_LOGF_FATAL(api, ...) \
    ::gn::log::fatal((api), __VA_ARGS__)
