/// @file   core/util/log.hpp
/// @brief  Thin logging facade for kernel code.
///
/// Two ways to log:
///
/// 1. **Functions** — `gn::log::info("hello {}", n)` style. Use when the
///    format string is computed at runtime, or when source-location
///    capture is irrelevant.
///
/// 2. **Macros** — `GN_LOG_INFO("hello {}", n)` style. Same destination
///    as the functions, but compile-time level filtering and automatic
///    `__FILE__`/`__LINE__` capture. Prefer at every kernel call site.
///
/// Plugin code never includes this header. Plugins log through
/// `host_api->log` so messages cross the C ABI uniformly. The kernel
/// bridges those plugin calls back into this same singleton logger
/// in `core/kernel/host_api_builder.cpp::thunk_log`.

#pragma once

#include <string_view>

#include <spdlog/spdlog.h>

namespace gn::log {

/// Build-aware default pattern.
///
/// Release builds emit a tight one-line format — timestamp, level,
/// message — because the source-location field is noise for INFO and
/// above on production stderr. Debug builds tack the source-location
/// `[file:line]` after the level so the call site is visible during
/// diagnosis.
///
/// The choice is fixed at compile time via `NDEBUG`. Operators who
/// want a different shape call `set_pattern` after `init()`.
#if defined(NDEBUG)
inline constexpr const char* kDefaultPattern =
    "%Y-%m-%dT%H:%M:%S.%e %^%l%$ %v";
#else
inline constexpr const char* kDefaultPattern =
    "%Y-%m-%dT%H:%M:%S.%e %^%l%$ [%s:%#] %v";
#endif

/// Build-aware default runtime level. Release defaults to INFO so
/// the binary does not emit DEBUG even if compile-time filtering
/// kept the call site (e.g. when a plugin compiled in Debug links
/// against a Release kernel).
#if defined(NDEBUG)
inline constexpr ::spdlog::level::level_enum kDefaultLevel = ::spdlog::level::info;
#else
inline constexpr ::spdlog::level::level_enum kDefaultLevel = ::spdlog::level::debug;
#endif

/// Returns the kernel's structured logger. First call constructs a
/// default stderr logger with the build-aware pattern and runtime
/// level; subsequent calls reuse the same instance.
inline ::spdlog::logger& kernel() {
    static auto logger = []{
        auto l = ::spdlog::default_logger();
        l->set_pattern(kDefaultPattern);
        l->set_level(kDefaultLevel);
        return l;
    }();
    return *logger;
}

/// Initialise the logger explicitly with a chosen level. Idempotent;
/// re-calling adjusts the live level. Call once at kernel startup so
/// the first log message lands at the configured verbosity rather
/// than at whatever default the lazy path picked.
inline void init(::spdlog::level::level_enum lvl = ::spdlog::level::info) {
    kernel().set_level(lvl);
}

/// Adjust the live log level. Wired from config-reload paths so
/// operators flip verbosity without restarting the kernel.
inline void set_level(::spdlog::level::level_enum lvl) noexcept {
    kernel().set_level(lvl);
}

/// String-to-level helper used by config parsing. Returns the
/// corresponding `level_enum` for "trace", "debug", "info", "warn",
/// "warning", "error", "critical", "off"; otherwise returns the
/// fallback (default info).
[[nodiscard]] inline ::spdlog::level::level_enum
parse_level(std::string_view name,
            ::spdlog::level::level_enum fallback = ::spdlog::level::info) noexcept {
    if (name == "trace")                       return ::spdlog::level::trace;
    if (name == "debug")                       return ::spdlog::level::debug;
    if (name == "info")                        return ::spdlog::level::info;
    if (name == "warn" || name == "warning")   return ::spdlog::level::warn;
    if (name == "error")                       return ::spdlog::level::err;
    if (name == "critical" || name == "fatal") return ::spdlog::level::critical;
    if (name == "off")                         return ::spdlog::level::off;
    return fallback;
}

/// Set the live level by string name; convenience for config plumbing.
inline void set_level_str(std::string_view name) noexcept {
    set_level(parse_level(name));
}

/* ── Function-style API (runtime-formatted) ────────────────────────────── */

template <class... Args>
inline void trace(::spdlog::format_string_t<Args...> fmt, Args&&... args) {
    kernel().trace(fmt, std::forward<Args>(args)...);
}

template <class... Args>
inline void debug(::spdlog::format_string_t<Args...> fmt, Args&&... args) {
    kernel().debug(fmt, std::forward<Args>(args)...);
}

template <class... Args>
inline void info(::spdlog::format_string_t<Args...> fmt, Args&&... args) {
    kernel().info(fmt, std::forward<Args>(args)...);
}

template <class... Args>
inline void warn(::spdlog::format_string_t<Args...> fmt, Args&&... args) {
    kernel().warn(fmt, std::forward<Args>(args)...);
}

template <class... Args>
inline void error(::spdlog::format_string_t<Args...> fmt, Args&&... args) {
    kernel().error(fmt, std::forward<Args>(args)...);
}

template <class... Args>
inline void critical(::spdlog::format_string_t<Args...> fmt, Args&&... args) {
    kernel().critical(fmt, std::forward<Args>(args)...);
}

} // namespace gn::log

/* ── Macro-style API (source-location capture) ─────────────────────────── */

/// Logging macros that capture `__FILE__`/`__LINE__` at the call site
/// through `SPDLOG_LOGGER_*`. Compile-time level filtering applies
/// (set via `SPDLOG_ACTIVE_LEVEL` at build time), so a Release build
/// with the ceiling set above TRACE drops the trace calls entirely.
///
/// Prefer these at kernel call sites where the message is a literal.
#define GN_LOG_TRACE(...)    SPDLOG_LOGGER_TRACE(&::gn::log::kernel(),    __VA_ARGS__)
#define GN_LOG_DEBUG(...)    SPDLOG_LOGGER_DEBUG(&::gn::log::kernel(),    __VA_ARGS__)
#define GN_LOG_INFO(...)     SPDLOG_LOGGER_INFO(&::gn::log::kernel(),     __VA_ARGS__)
#define GN_LOG_WARN(...)     SPDLOG_LOGGER_WARN(&::gn::log::kernel(),     __VA_ARGS__)
#define GN_LOG_ERROR(...)    SPDLOG_LOGGER_ERROR(&::gn::log::kernel(),    __VA_ARGS__)
#define GN_LOG_CRITICAL(...) SPDLOG_LOGGER_CRITICAL(&::gn::log::kernel(), __VA_ARGS__)
