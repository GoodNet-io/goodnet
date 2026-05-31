// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/handler_plugin.hpp
/// @brief  `GN_HANDLER_PLUGIN(Class, "plugin_name", "version")` —
///         collapses handler plugin entry-file boilerplate
///         (~110 LOC per plugin) into one macro.
///
/// What the macro generates:
///   1. Five `gn_plugin_*` extern "C" entry points.
///   2. `gn_handler_vtable_t` with SFINAE-dispatched lifecycle hooks
///      (`on_init` / `on_result` / `on_shutdown` are wired only when
///      the user's class defines them).
///   3. `register_vtable(..., GN_REGISTER_HANDLER, ...)` call against
///      the class's static `protocol_id()` / `msg_id()` / `priority()`.
///   4. Optional `register_extension(...)` call when the user's class
///      defines a static `extension_name()`, static `extension_version()`,
///      and instance `extension_vtable()`.
///   5. `gn_plugin_descriptor_t` table with kind = `HANDLER`.
///
/// ## Class concept
///
/// ```cpp
/// class MyHandler {
/// public:
///     explicit MyHandler(const host_api_t* api);
///
///     static constexpr const char* protocol_id() { return "gnet-v1"; }
///     static constexpr std::uint32_t msg_id() { return 0x10; }
///     static constexpr std::uint8_t priority() { return 240; }
///
///     gn_propagation_t handle_message(const gn_message_t& envelope);
///
///     /// All optional:
///     void on_init() {}
///     void on_shutdown() {}
///     void on_result(const gn_message_t&, gn_propagation_t) {}
///     std::span<const std::uint32_t> extra_msg_ids() const;
///
///     /// Optional extension surface — only used when *all three*
///     /// of the symbols below are visible at macro expansion.
///     static constexpr const char* extension_name();
///     static constexpr std::uint32_t extension_version();
///     const void* extension_vtable() const noexcept;
/// };
/// ```

#pragma once

#include <algorithm>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <type_traits>
#include <vector>

#include <sdk/abi.h>
#include <sdk/cpp/contract.hpp>
#include <sdk/cpp/dispatcher.hpp>
#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/types.h>

namespace gn::sdk::detail {

template <class T>
struct HandlerPluginInstance {
    const host_api_t* api      = nullptr;
    void*             host_ctx = nullptr;
    std::unique_ptr<T> handler;
    gn_handler_id_t   handler_id           = GN_INVALID_ID;
    bool              extension_registered = false;
    // Per-instance msg_id list — avoids static state that breaks hot-reload
    // (a second register call with new extra_msg_ids would silently use stale data).
    std::vector<std::uint32_t> msg_ids;
};

template <class T>
[[nodiscard]] gn_propagation_t handle_message_dispatch(
    T& h, const gn_message_t* envelope) noexcept {
    if (!envelope) return GN_PROPAGATION_REJECT;
    try {
        return h.handle_message(*envelope);
    } catch (...) {
        return GN_PROPAGATION_REJECT;
    }
}

template <class T>
void on_result_dispatch(T& h, const gn_message_t* envelope,
                         gn_propagation_t result) noexcept {
    if constexpr (requires { h.on_result(*envelope, result); }) {
        if (!envelope) return;
        try { h.on_result(*envelope, result); } catch (...) {}  // NOLINT(bugprone-empty-catch)
    } else { (void)h; (void)envelope; (void)result; }
}

template <class T>
[[nodiscard]] std::span<const std::uint32_t>
msg_ids_dispatch(const T& h) noexcept {
    if constexpr (requires { { T::msg_ids() } -> std::convertible_to<
            std::span<const std::uint32_t>>; }) {
        return T::msg_ids();
    } else if constexpr (requires { { h.extra_msg_ids() } ->
            std::convertible_to<std::span<const std::uint32_t>>; }) {
        return h.extra_msg_ids();
    } else {
        return {};
    }
}

template <class T>
constexpr bool has_extension_v =
    requires {
        { T::extension_name() }    -> std::convertible_to<const char*>;
        { T::extension_version() } -> std::convertible_to<std::uint32_t>;
    } &&
    requires(const T& t) {
        { t.extension_vtable() } -> std::convertible_to<const void*>;
    };

/// Plugin-side extension registration helper. The body has to live
/// inside a function template so `if constexpr` actually discards
/// the call to `T::extension_name()` etc. — `if constexpr` in a
/// non-template function still checks the discarded substatement
/// for ill-formed non-dependent expressions, which would otherwise
/// force every handler class to define `extension_name()` /
/// `extension_version()` / `extension_vtable()` even when the
/// plugin ships no extension surface.
template <class T>
inline void maybe_register_extension(HandlerPluginInstance<T>* p) {
    if constexpr (has_extension_v<T>) {
        if (p->api && p->api->register_extension) {
            if (p->api->register_extension(
                    p->host_ctx,
                    T::extension_name(),
                    T::extension_version(),
                    p->handler->extension_vtable()) == GN_OK) {
                p->extension_registered = true;
            }
        }
    } else {
        (void)p;
    }
}

template <class T>
inline void maybe_unregister_extension(HandlerPluginInstance<T>* p) noexcept {
    if constexpr (has_extension_v<T>) {
        if (p->extension_registered &&
            p->api && p->api->unregister_extension) {
            (void)p->api->unregister_extension(
                p->host_ctx, T::extension_name());
            p->extension_registered = false;
        }
    } else {
        (void)p;
    }
}

/// Compile-time list of extension names this handler advertises
/// through `gn_plugin_descriptor_t::ext_provides`. Returns a
/// null-terminated array when the handler class defines the
/// extension trio, or `nullptr` when it doesn't — the kernel
/// reads this list at load time and the macro below cannot push
/// names into a const array at runtime.
template <class T, bool HasExt = has_extension_v<T>>
struct handler_provides {
    static constexpr const char* const* value = nullptr;
};

template <class T>
struct handler_provides<T, true> {
    /// Two-slot array: the extension name from the handler class
    /// plus a trailing nullptr terminator the kernel walks until.
    static constexpr const char* names[] = {T::extension_name(), nullptr};
    static constexpr const char* const* value = &names[0];
};

/// Returns the class's `inject_targets` if it declares one, else nullptr.
template <class T>
consteval const gn_inject_dep_t* get_inject_targets() noexcept {
    if constexpr (requires { T::inject_targets; })
        return T::inject_targets;
    else
        return nullptr;
}

/// Compile-time validation for a null-terminated `gn_inject_dep_t` array.
/// Returns false if any entry before the sentinel has an empty protocol_id
/// or if any two entries share the same (protocol_id, msg_id) pair.
consteval bool validate_inject_targets(const gn_inject_dep_t* arr) noexcept {
    if (!arr) return true;
    std::size_t n = 0;
    while (arr[n].protocol_id != nullptr) {
        if (arr[n].protocol_id[0] == '\0') return false;
        for (std::size_t j = 0; j < n; ++j)
            if (arr[j].msg_id == arr[n].msg_id &&
                std::string_view(arr[j].protocol_id) ==
                std::string_view(arr[n].protocol_id))
                return false;
        ++n;
    }
    return true;
}

} // namespace gn::sdk::detail

/// `GN_HANDLER_PLUGIN(Class, "plugin_name", "version")`. See file
/// header for the class concept. The `plugin_name` and `version` are
/// embedded in the `gn_plugin_descriptor_t` so the kernel can log /
/// audit the handler at load time.
#define GN_HANDLER_PLUGIN(ClassName, PLUGIN_NAME, PLUGIN_VERSION)              \
    namespace {                                                                \
    using _gn_handler_class_t = ClassName;                                     \
    using _gn_handler_instance_t =                                             \
        ::gn::sdk::detail::HandlerPluginInstance<_gn_handler_class_t>;         \
                                                                               \
    [[maybe_unused]] constexpr const char* _gn_handler_plugin_name    = PLUGIN_NAME;    \
    [[maybe_unused]] constexpr const char* _gn_handler_plugin_version = PLUGIN_VERSION; \
                                                                               \
    inline _gn_handler_class_t& _gn_handler_of(void* p) noexcept {             \
        return *static_cast<_gn_handler_instance_t*>(p)->handler;              \
    }                                                                          \
                                                                               \
    /* Build per-instance msg_id list on first registration.                   \
     * Stored on HandlerPluginInstance so hot-reload gets a fresh list.        \
     * O(N log N) dedup via sort+unique. */                                    \
    inline void _gn_handler_build_msg_ids(_gn_handler_instance_t& inst) {      \
        auto& ids = inst.msg_ids;                                              \
        ids.clear();                                                           \
        ids.push_back(_gn_handler_class_t::msg_id());                          \
        auto extras = ::gn::sdk::detail::msg_ids_dispatch(*inst.handler);      \
        ids.insert(ids.end(), extras.begin(), extras.end());                   \
        std::sort(ids.begin(), ids.end());                                     \
        ids.erase(std::unique(ids.begin(), ids.end()), ids.end());             \
    }                                                                          \
                                                                               \
    const char* _gn_handler_protocol_thunk(void*) noexcept {                   \
        return _gn_handler_class_t::protocol_id();                             \
    }                                                                          \
    void _gn_handler_supported_thunk(void* self,                               \
                                     const std::uint32_t** out_ids,            \
                                     std::size_t* out_count) noexcept {        \
        auto* inst = static_cast<_gn_handler_instance_t*>(self);               \
        if (out_ids)   *out_ids   = inst->msg_ids.data();                      \
        if (out_count) *out_count = inst->msg_ids.size();                      \
    }                                                                          \
    gn_propagation_t _gn_handler_handle_thunk(                                 \
        void* self, const gn_message_t* env) noexcept                          \
        GN_EXPECTS(self != nullptr)                                            \
    {                                                                          \
        if (!self) return GN_PROPAGATION_REJECT;                               \
        return ::gn::sdk::detail::handle_message_dispatch(                     \
            _gn_handler_of(self), env);                                        \
    }                                                                          \
    void _gn_handler_on_result_thunk(                                          \
        void* self, const gn_message_t* env,                                   \
        gn_propagation_t r) noexcept                                           \
        GN_EXPECTS(self != nullptr)                                            \
    {                                                                          \
        if (!self) return;                                                     \
        ::gn::sdk::detail::on_result_dispatch(                                 \
            _gn_handler_of(self), env, r);                                     \
    }                                                                          \
    void _gn_handler_on_init_thunk(void* self) noexcept                        \
        GN_EXPECTS(self != nullptr)                                            \
    {                                                                          \
        if (!self) return;                                                     \
        try { ::gn::sdk::detail::dispatch_on_init(_gn_handler_of(self)); }     \
        catch (...) {}  /* NOLINT(bugprone-empty-catch) */                     \
    }                                                                          \
    void _gn_handler_on_shutdown_thunk(void* self) noexcept                    \
        GN_EXPECTS(self != nullptr)                                            \
    {                                                                          \
        if (!self) return;                                                     \
        try { ::gn::sdk::detail::dispatch_on_shutdown(_gn_handler_of(self)); } \
        catch (...) {}  /* NOLINT(bugprone-empty-catch) */                     \
    }                                                                          \
                                                                               \
    gn_handler_vtable_t _gn_handler_make_vtable() noexcept {                   \
        gn_handler_vtable_t v{};                                               \
        v.api_size          = sizeof(gn_handler_vtable_t);                     \
        v.protocol_id       = &_gn_handler_protocol_thunk;                     \
        v.supported_msg_ids = &_gn_handler_supported_thunk;                    \
        v.handle_message    = &_gn_handler_handle_thunk;                       \
        v.on_result         = &_gn_handler_on_result_thunk;                    \
        v.on_init           = &_gn_handler_on_init_thunk;                      \
        v.on_shutdown       = &_gn_handler_on_shutdown_thunk;                  \
        return v;                                                              \
    }                                                                          \
    inline gn_handler_vtable_t& _gn_handler_vtable() noexcept {                \
        static gn_handler_vtable_t v = _gn_handler_make_vtable();              \
        return v;                                                              \
    }                                                                          \
                                                                               \
    const gn_plugin_descriptor_t _gn_handler_descriptor = {                    \
        /* name              */ PLUGIN_NAME,                                   \
        /* version           */ PLUGIN_VERSION,                                \
        /* hot_reload_safe   */ 0,                                             \
        /* ext_requires      */ nullptr,                                       \
        /* ext_provides      */ ::gn::sdk::detail::handler_provides<           \
                                    _gn_handler_class_t>::value,               \
        /* kind              */ GN_PLUGIN_KIND_HANDLER,                        \
        /* inject_targets    */ ::gn::sdk::detail::get_inject_targets<          \
                                    _gn_handler_class_t>(),                    \
        /* _reserved         */ {},                                              \
    };                                                                         \
    static_assert(                                                             \
        ::gn::sdk::detail::validate_inject_targets(                            \
            ::gn::sdk::detail::get_inject_targets<_gn_handler_class_t>()),     \
        #ClassName ": inject_targets has empty protocol_id or duplicate entry");\
    } /* anonymous namespace */                                                \
                                                                               \
    extern "C" {                                                               \
                                                                               \
    GN_PLUGIN_EXPORT void GN_PLUGIN_SDK_VERSION_NAME(std::uint32_t* major,     \
                                                 std::uint32_t* minor,         \
                                                 std::uint32_t* patch) {       \
        if (major) *major = GN_SDK_VERSION_MAJOR;                              \
        if (minor) *minor = GN_SDK_VERSION_MINOR;                              \
        if (patch) *patch = GN_SDK_VERSION_PATCH;                              \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_INIT_NAME(                          \
        const host_api_t* api, void** out_self) {                              \
        if (!api || !out_self) return GN_ERR_NULL_ARG;                         \
        auto* p = new (std::nothrow) _gn_handler_instance_t{};                 \
        if (!p) return GN_ERR_OUT_OF_MEMORY;                                   \
        p->api      = api;                                                     \
        p->host_ctx = api->host_ctx;                                           \
        try {                                                                  \
            p->handler = std::make_unique<_gn_handler_class_t>(api);           \
        } catch (...) {                                                        \
            delete p;                                                          \
            return GN_ERR_OUT_OF_MEMORY;                                       \
        }                                                                      \
        /* Build per-instance msg_id list before kernel queries it. */          \
        _gn_handler_build_msg_ids(*p);                                         \
        *out_self = p;                                                         \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_REGISTER_NAME(void* self) {         \
        if (!self) return GN_ERR_NULL_ARG;                                     \
        auto* p = static_cast<_gn_handler_instance_t*>(self);                  \
        if (!p->api || !p->api->register_vtable) {                             \
            return GN_ERR_NOT_IMPLEMENTED;                                     \
        }                                                                      \
        gn_register_meta_t meta{};                                             \
        meta.api_size = sizeof(gn_register_meta_t);                            \
        meta.name     = _gn_handler_class_t::protocol_id();                    \
        meta.msg_id   = _gn_handler_class_t::msg_id();                         \
        meta.priority = _gn_handler_class_t::priority();                       \
        const gn_result_t rc = p->api->register_vtable(                        \
            p->host_ctx, GN_REGISTER_HANDLER, &meta,                           \
            &_gn_handler_vtable(), p->handler.get(), &p->handler_id);          \
        if (rc != GN_OK) return rc;                                            \
        ::gn::sdk::detail::maybe_register_extension(p);                        \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_UNREGISTER_NAME(void* self) {       \
        if (!self) return GN_ERR_NULL_ARG;                                     \
        auto* p = static_cast<_gn_handler_instance_t*>(self);                  \
        ::gn::sdk::detail::maybe_unregister_extension(p);                      \
        if (p->api && p->api->unregister_vtable &&                             \
            p->handler_id != GN_INVALID_ID) {                                  \
            (void)p->api->unregister_vtable(p->host_ctx, p->handler_id);       \
            p->handler_id = GN_INVALID_ID;                                     \
        }                                                                      \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT void GN_PLUGIN_SHUTDOWN_NAME(void* self) {                \
        delete static_cast<_gn_handler_instance_t*>(self);                     \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT const gn_plugin_descriptor_t*                             \
    GN_PLUGIN_DESCRIPTOR_NAME(void) {                                          \
        return &_gn_handler_descriptor;                                        \
    }                                                                          \
                                                                               \
    } /* extern "C" */                                                         \
    /**/
