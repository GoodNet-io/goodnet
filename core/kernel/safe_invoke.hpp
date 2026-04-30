/// @file   core/kernel/safe_invoke.hpp
/// @brief  C ABI exception-safety wrappers for vtable callbacks.
///
/// Plugin authors must not throw exceptions across `extern "C"` —
/// the C ABI does not specify exception propagation, and a throw
/// that escapes a plugin callback corrupts the kernel's stack.
/// `__attribute__((nothrow))` on the function-pointer typedef is
/// a hint to the compiler, not a runtime guard. This header is
/// the runtime guard: every kernel-side call into a plugin
/// vtable runs through one of these wrappers, which catches every
/// exception type and converts it to a documented error code.
///
/// The wrappers are templated to keep the call shape identical
/// to the bare invocation. Compilers inline the try/catch block
/// when no exception is thrown; the steady-state cost is one
/// extra stack frame, no syscalls, no allocations.

#pragma once

#include <exception>
#include <optional>
#include <type_traits>
#include <utility>

#include <core/util/log.hpp>
#include <sdk/types.h>

namespace gn::core {

/// Invoke a `gn_result_t`-returning vtable slot. Returns
/// `GN_ERR_INTERNAL` when the slot throws. The slot is
/// guaranteed never to leak a `std::exception` past this call.
///
/// @param site_tag  short ASCII label for the log line; identifies
///                  which kernel call site caught the exception so
///                  the operator can pinpoint the misbehaving
///                  plugin without reading kernel internals.
template <typename Fn, typename... Args>
[[nodiscard]] inline gn_result_t
safe_call_result(const char* site_tag, Fn&& fn, Args&&... args) noexcept {
    static_assert(std::is_invocable_r_v<gn_result_t, Fn, Args...>,
                  "safe_call_result wraps gn_result_t-returning slots");
    try {
        return std::forward<Fn>(fn)(std::forward<Args>(args)...);
    } catch (const std::exception& e) {
        SPDLOG_LOGGER_ERROR(::gn::log::kernel().get(),
            "plugin callback at {} threw std::exception: {} — "
            "returning GN_ERR_INTERNAL", site_tag, e.what());
        return GN_ERR_INTERNAL;
    } catch (...) {
        SPDLOG_LOGGER_ERROR(::gn::log::kernel().get(),
            "plugin callback at {} threw a non-std exception — "
            "returning GN_ERR_INTERNAL", site_tag);
        return GN_ERR_INTERNAL;
    }
}

/// Invoke a void-returning vtable slot. The wrapper has no
/// failure channel — exceptions are logged and swallowed. The
/// caller cannot tell whether the slot ran to completion or
/// faulted partway, but the kernel's own state stays consistent.
template <typename Fn, typename... Args>
inline void
safe_call_void(const char* site_tag, Fn&& fn, Args&&... args) noexcept {
    try {
        std::forward<Fn>(fn)(std::forward<Args>(args)...);
    } catch (const std::exception& e) {
        SPDLOG_LOGGER_ERROR(::gn::log::kernel().get(),
            "plugin callback at {} threw std::exception: {} — "
            "swallowed", site_tag, e.what());
    } catch (...) {
        SPDLOG_LOGGER_ERROR(::gn::log::kernel().get(),
            "plugin callback at {} threw a non-std exception — "
            "swallowed", site_tag);
    }
}

/// Invoke a value-returning vtable slot whose return value is
/// not `gn_result_t`. Returns `nullopt` when the slot throws so
/// the caller can pick a sensible default for its dispatch path.
template <typename R, typename Fn, typename... Args>
[[nodiscard]] inline std::optional<R>
safe_call_value(const char* site_tag, Fn&& fn, Args&&... args) noexcept {
    static_assert(std::is_invocable_r_v<R, Fn, Args...>,
                  "safe_call_value: R must match the slot's return type");
    static_assert(std::is_constructible_v<std::optional<R>, R&&>,
                  "safe_call_value: R must be optional-constructible");
    try {
        return std::optional<R>{
            std::forward<Fn>(fn)(std::forward<Args>(args)...)};
    } catch (const std::exception& e) {
        SPDLOG_LOGGER_ERROR(::gn::log::kernel().get(),
            "plugin callback at {} threw std::exception: {} — "
            "returning nullopt", site_tag, e.what());
        return std::nullopt;
    } catch (...) {
        SPDLOG_LOGGER_ERROR(::gn::log::kernel().get(),
            "plugin callback at {} threw a non-std exception — "
            "returning nullopt", site_tag);
        return std::nullopt;
    }
}

}  // namespace gn::core
