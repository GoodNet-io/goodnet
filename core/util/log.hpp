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
/// Plugin code never includes this header. Plugins log through the
/// `gn_log_*` macros in `sdk/convenience.h`, which call the
/// `host_api_t::log` substruct (`should_log` / `emit`). The kernel
/// bridges those plugin calls back into this same singleton logger
/// in `core/kernel/host_api_builder.cpp` (`thunk_log_emit`).
///
/// The singleton has a default-construction path (lazy `kernel()`
/// call brings up a basic stderr logger) and an explicit one
/// (`init_with(LogConfig)`) that the kernel runs from `Kernel`'s
/// constructor with values pulled from the loaded config. Calling
/// `init_with` again replaces the live sinks atomically — config
/// reload re-shapes the destination without losing the named logger
/// registration.
#pragma once

#include <cstddef>
#include <string>
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
/// want a different shape pass a custom pattern through `LogConfig`.
#if defined(NDEBUG)
inline constexpr const char* kDefaultPattern =
    "%Y-%m-%dT%H:%M:%S.%e %^%l%$ %v";
#else
inline constexpr const char* kDefaultPattern =
    "%Y-%m-%dT%H:%M:%S.%e %^%l%$ %Q%v";
#endif

/// File-sink default pattern carries the source-location prefix
/// always — operators reading rotated logs after the fact want the
/// call site preserved regardless of the live console verbosity.
inline constexpr const char* kDefaultFilePattern =
    "%Y-%m-%dT%H:%M:%S.%e %^%l%$ %Q%v";

/// Build-aware default runtime level. Release defaults to INFO so
/// the binary does not emit DEBUG even if compile-time filtering
/// kept the call site (e.g. when a plugin compiled in Debug links
/// against a Release kernel).
#if defined(NDEBUG)
inline constexpr ::spdlog::level::level_enum kDefaultLevel = ::spdlog::level::info;
#else
inline constexpr ::spdlog::level::level_enum kDefaultLevel = ::spdlog::level::debug;
#endif

/// Source-location detail mode for the custom `%Q` format flag.
///
///  - `Auto` (0) — TRACE/DEBUG carry full path + line; INFO and
///    above carry basename only. Default. Reads as production noise
///    at the upper levels and as a precise breadcrumb at the lower.
///  - `FullPath` (1) — every level carries the project-relative path
///    plus `:line`.
///  - `BasenameWithLine` (2) — every level carries the file
///    basename plus `:line`.
///  - `BasenameOnly` (3) — the basename, no line. Tightest format.
enum class SourceDetail : int {
    Auto              = 0,
    FullPath          = 1,
    BasenameWithLine  = 2,
    BasenameOnly      = 3,
};

/// Configuration the kernel hands to `init_with` after the first
/// successful config load. Field defaults match the lazy startup
/// path so an unset field never turns logging off.
struct LogConfig {
    std::string  level            = "info";

    /// Console-sink minimum level. Empty string keeps the build-aware
    /// default — Release pins WARN as a noise filter for long-running
    /// daemons; Debug carries everything the logger itself accepts.
    /// Operators who want the kernel's INFO startup markers visible
    /// on a Release deployment set this to `"info"` in their config.
    std::string  console_level;

    /// Path to the rotating log file, or empty to skip the file
    /// sink and keep the destination console-only.
    std::string  log_file;
    std::size_t  max_size         = std::size_t{10} * 1024 * 1024;  // 10 MiB
    int          max_files        = 5;

    SourceDetail source_detail    = SourceDetail::Auto;

    /// Project-relative path prefix the `%Q` flag strips off
    /// `__FILE__` to keep emitted paths short. The CMake
    /// `-fmacro-prefix-map=${CMAKE_SOURCE_DIR}/=` flag already
    /// drops the prefix at compile time; this knob covers the
    /// case where consumers set a different working directory.
    std::string  project_root;

    /// Strip the extension (`.cpp` / `.hpp`) from the displayed
    /// filename. Off by default — losing the extension makes
    /// header vs. .cpp call sites indistinguishable.
    bool         strip_extension  = false;

    std::string  console_pattern;  // empty => kDefaultPattern
    std::string  file_pattern;     // empty => kDefaultFilePattern
};

/// Returns the kernel's named logger (`"gn"`). First call brings up
/// a basic stderr-only logger with the build-aware pattern and
/// runtime level; `init_with` swaps the singleton atomically so
/// concurrent log calls on a soon-to-be-replaced logger keep the
/// shared ownership of the prior instance until they release the
/// returned handle.
[[nodiscard]] std::shared_ptr<::spdlog::logger> kernel();

/// Initialise the logger explicitly with a chosen level. Idempotent;
/// re-calling adjusts the live level without recreating sinks. Safe
/// to call before or after `kernel()`.
void init(::spdlog::level::level_enum lvl = ::spdlog::level::info);

/// Replace the singleton's sink set + pattern + level using the
/// values in @p cfg. Re-callable on every config-reload event so
/// operators flip detail mode, file path, or pattern without
/// restarting the kernel. Returns `true` if the reshape applied;
/// `false` if a sink construction failed (the prior shape stays
/// active).
bool init_with(const LogConfig& cfg) noexcept;

/// Adjust the live log level. Wired from config-reload paths so
/// operators flip verbosity without restarting the kernel.
void set_level(::spdlog::level::level_enum lvl) noexcept;

/// String-to-level helper used by config parsing. Returns the
/// corresponding `level_enum` for "trace", "debug", "info", "warn",
/// "warning", "error", "critical", "off"; otherwise returns the
/// fallback (default info).
[[nodiscard]] ::spdlog::level::level_enum
parse_level(std::string_view name,
            ::spdlog::level::level_enum fallback = ::spdlog::level::info) noexcept;

/// Set the live level by string name; convenience for config plumbing.
inline void set_level_str(std::string_view name) noexcept {
    set_level(parse_level(name));
}

/* ── Function-style API (runtime-formatted) ────────────────────────────── */

template <class... Args>
inline void trace(::spdlog::format_string_t<Args...> fmt, Args&&... args) {
    kernel()->trace(fmt, std::forward<Args>(args)...);
}

template <class... Args>
inline void debug(::spdlog::format_string_t<Args...> fmt, Args&&... args) {
    kernel()->debug(fmt, std::forward<Args>(args)...);
}

template <class... Args>
inline void info(::spdlog::format_string_t<Args...> fmt, Args&&... args) {
    kernel()->info(fmt, std::forward<Args>(args)...);
}

template <class... Args>
inline void warn(::spdlog::format_string_t<Args...> fmt, Args&&... args) {
    kernel()->warn(fmt, std::forward<Args>(args)...);
}

template <class... Args>
inline void error(::spdlog::format_string_t<Args...> fmt, Args&&... args) {
    kernel()->error(fmt, std::forward<Args>(args)...);
}

template <class... Args>
inline void critical(::spdlog::format_string_t<Args...> fmt, Args&&... args) {
    kernel()->critical(fmt, std::forward<Args>(args)...);
}

} // namespace gn::log

/* ── Macro-style API (source-location capture) ─────────────────────────── */

/// Logging macros that capture `__FILE__`/`__LINE__` at the call site
/// through `SPDLOG_LOGGER_*`. Compile-time level filtering applies
/// (set via `SPDLOG_ACTIVE_LEVEL` at build time), so a Release build
/// with the ceiling set above TRACE drops the trace calls entirely.
///
/// Prefer these at kernel call sites where the message is a literal.
#define GN_LOG_TRACE(...)    SPDLOG_LOGGER_TRACE(::gn::log::kernel().get(),    __VA_ARGS__)
#define GN_LOG_DEBUG(...)    SPDLOG_LOGGER_DEBUG(::gn::log::kernel().get(),    __VA_ARGS__)
#define GN_LOG_INFO(...)     SPDLOG_LOGGER_INFO(::gn::log::kernel().get(),     __VA_ARGS__)
#define GN_LOG_WARN(...)     SPDLOG_LOGGER_WARN(::gn::log::kernel().get(),     __VA_ARGS__)
#define GN_LOG_ERROR(...)    SPDLOG_LOGGER_ERROR(::gn::log::kernel().get(),    __VA_ARGS__)
#define GN_LOG_CRITICAL(...) SPDLOG_LOGGER_CRITICAL(::gn::log::kernel().get(), __VA_ARGS__)
