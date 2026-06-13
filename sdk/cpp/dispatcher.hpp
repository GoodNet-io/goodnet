// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/dispatcher.hpp
/// @brief  Generic optional-method dispatchers for plugin macros.
///
/// Replaces the 14 near-identical SFINAE dispatch templates spread
/// across link_plugin.hpp, handler_plugin.hpp, and strategy_plugin.hpp.
///
/// ## Pattern
///
/// Plugin vtable slots that map to *optional* class methods share a
/// common shape:
///   - If the class defines the method → call it and return the result.
///   - If not → return GN_ERR_NOT_IMPLEMENTED (result slots) or do
///     nothing (void slots).
///
/// Previously each slot required its own template specialisation with
/// a `requires` guard. The two templates here collapse that to a single
/// call:
///
/// ```cpp
/// // Before (per-slot, 5 lines each):
/// template <class T>
/// [[nodiscard]] gn_result_t composer_listen_dispatch(
///     T& link, std::string_view uri) noexcept {
///     if constexpr (requires { link.composer_listen(uri); })
///         return link.composer_listen(uri);
///     else
///         return GN_ERR_NOT_IMPLEMENTED;
/// }
///
/// // After (one call, any signature):
/// dispatch_result<&T::composer_listen>(link, uri);
/// ```

#pragma once

#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::sdk::detail {

/// Call `(obj.*MethodPtr)(args...)` if the method exists; otherwise
/// return `GN_ERR_NOT_IMPLEMENTED`. Useful for optional plugin vtable
/// slots whose return type is `gn_result_t`.
///
/// @tparam MethodPtr  Pointer-to-member (e.g. `&T::composer_listen`).
/// @tparam T          Object type — deduced from @p obj.
/// @tparam Args       Argument types — deduced from @p args.
template <auto MethodPtr, class T, class... Args>
[[nodiscard]] gn_result_t dispatch_result(T& obj, Args&&... args) noexcept {
    if constexpr (requires { (obj.*MethodPtr)(static_cast<Args&&>(args)...); })
        return (obj.*MethodPtr)(static_cast<Args&&>(args)...);
    else
        return GN_ERR_NOT_IMPLEMENTED;
}

/// Call `(obj.*MethodPtr)(args...)` if the method exists; otherwise
/// do nothing. For optional void-returning lifecycle hooks
/// (e.g. `on_init`, `on_shutdown`, `on_path_event`).
template <auto MethodPtr, class T, class... Args>
void dispatch_void(T& obj, Args&&... args) noexcept {
    if constexpr (requires { (obj.*MethodPtr)(static_cast<Args&&>(args)...); })
        (obj.*MethodPtr)(static_cast<Args&&>(args)...);
    else
        (void)obj;
}

/// Call `obj.on_init()` if the method exists; otherwise do nothing.
/// Template wrapper so `if constexpr` is evaluated per-instantiation.
template <class T>
void dispatch_on_init(T& obj) noexcept {
    if constexpr (requires { obj.on_init(); }) obj.on_init();
}

/// Call `obj.on_shutdown()` if the method exists; otherwise do nothing.
template <class T>
void dispatch_on_shutdown(T& obj) noexcept {
    if constexpr (requires { obj.on_shutdown(); }) obj.on_shutdown();
}

/// Call `obj.set_default_trust_class(tc)` if the method exists; otherwise
/// do nothing.
template <class T>
void dispatch_set_default_trust_class(T& obj, gn_trust_class_t tc) noexcept {
    if constexpr (requires { obj.set_default_trust_class(tc); })
        obj.set_default_trust_class(tc);
}

} // namespace gn::sdk::detail
