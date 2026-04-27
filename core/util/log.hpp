/// @file   core/util/log.hpp
/// @brief  Thin logging facade for kernel code.
///
/// The kernel logs through `gn::log::info`, `gn::log::warn`, etc. The
/// facade currently delegates to spdlog; the indirection lets us swap
/// the back end without touching call sites.
///
/// Plugin code does not include this header — plugins log through
/// `host_api->log` so messages cross the C ABI.

#pragma once

#include <spdlog/spdlog.h>

namespace gn::log {

/// Returns the kernel's structured logger. First call constructs a
/// default stderr logger; subsequent calls reuse the same instance.
inline ::spdlog::logger& kernel() {
    static auto logger = []{
        auto l = ::spdlog::default_logger();
        l->set_pattern("%Y-%m-%dT%H:%M:%S.%e %^%l%$ %v");
        return l;
    }();
    return *logger;
}

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
