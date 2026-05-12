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

#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <type_traits>

#include <sdk/abi.h>
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
void on_init_dispatch(T& h) noexcept {
    if constexpr (requires { h.on_init(); }) {
        try { h.on_init(); } catch (...) {  // NOLINT(bugprone-empty-catch)
        // Plugin entry points must be noexcept across the C ABI;
        // an unhandled exception here would unwind into kernel C frames.
    }
    } else { (void)h; }
}

template <class T>
void on_shutdown_dispatch(T& h) noexcept {
    if constexpr (requires { h.on_shutdown(); }) {
        try { h.on_shutdown(); } catch (...) {  // NOLINT(bugprone-empty-catch)
        // Plugin entry points must be noexcept across the C ABI;
        // an unhandled exception here would unwind into kernel C frames.
    }
    } else { (void)h; }
}

template <class T>
void on_result_dispatch(T& h, const gn_message_t* envelope,
                         gn_propagation_t result) noexcept {
    if constexpr (requires { h.on_result(*envelope, result); }) {
        if (!envelope) return;
        try { h.on_result(*envelope, result); } catch (...) {  // NOLINT(bugprone-empty-catch)
        // Plugin entry points must be noexcept across the C ABI;
        // an unhandled exception here would unwind into kernel C frames.
    }
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
    constexpr const char* _gn_handler_plugin_name    = PLUGIN_NAME;            \
    constexpr const char* _gn_handler_plugin_version = PLUGIN_VERSION;         \
                                                                               \
    inline _gn_handler_class_t& _gn_handler_of(void* p) noexcept {             \
        return *static_cast<_gn_handler_instance_t*>(p)->handler;              \
    }                                                                          \
                                                                               \
    /* Persisted across calls because supported_msg_ids returns @borrowed. */  \
    inline std::span<const std::uint32_t>                                      \
    _gn_handler_persisted_msg_ids(_gn_handler_class_t* h, bool refresh) {      \
        static std::vector<std::uint32_t> ids;                                 \
        static bool                       inited = false;                      \
        if (!inited || refresh) {                                              \
            ids.clear();                                                       \
            ids.push_back(_gn_handler_class_t::msg_id());                      \
            auto extras = ::gn::sdk::detail::msg_ids_dispatch(*h);             \
            for (auto m : extras) {                                            \
                bool dup = false;                                              \
                for (auto x : ids) if (x == m) { dup = true; break; }          \
                if (!dup) ids.push_back(m);                                    \
            }                                                                  \
            inited = true;                                                     \
        }                                                                      \
        return {ids.data(), ids.size()};                                       \
    }                                                                          \
                                                                               \
    const char* _gn_handler_protocol_thunk(void*) noexcept {                   \
        return _gn_handler_class_t::protocol_id();                             \
    }                                                                          \
    void _gn_handler_supported_thunk(void* self,                               \
                                     const std::uint32_t** out_ids,            \
                                     std::size_t* out_count) noexcept {        \
        auto sp = _gn_handler_persisted_msg_ids(                               \
            &_gn_handler_of(self), false);                                     \
        if (out_ids) *out_ids = sp.data();                                     \
        if (out_count) *out_count = sp.size();                                 \
    }                                                                          \
    gn_propagation_t _gn_handler_handle_thunk(                                 \
        void* self, const gn_message_t* env) noexcept {                        \
        return ::gn::sdk::detail::handle_message_dispatch(                     \
            _gn_handler_of(self), env);                                        \
    }                                                                          \
    void _gn_handler_on_result_thunk(                                          \
        void* self, const gn_message_t* env,                                   \
        gn_propagation_t r) noexcept {                                         \
        ::gn::sdk::detail::on_result_dispatch(                                 \
            _gn_handler_of(self), env, r);                                     \
    }                                                                          \
    void _gn_handler_on_init_thunk(void* self) noexcept {                      \
        ::gn::sdk::detail::on_init_dispatch(_gn_handler_of(self));             \
    }                                                                          \
    void _gn_handler_on_shutdown_thunk(void* self) noexcept {                  \
        ::gn::sdk::detail::on_shutdown_dispatch(_gn_handler_of(self));         \
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
    const char* const _gn_handler_provides[] = {                               \
        nullptr,  /* extension name pushed in at init when present */          \
        nullptr,                                                               \
    };                                                                         \
                                                                               \
    const gn_plugin_descriptor_t _gn_handler_descriptor = {                    \
        /* name              */ PLUGIN_NAME,                                   \
        /* version           */ PLUGIN_VERSION,                                \
        /* hot_reload_safe   */ 0,                                             \
        /* ext_requires      */ nullptr,                                       \
        /* ext_provides      */ ::gn::sdk::detail::has_extension_v<            \
                                    _gn_handler_class_t>                       \
                                ? &_gn_handler_provides[0]                     \
                                : nullptr,                                     \
        /* kind              */ GN_PLUGIN_KIND_HANDLER,                        \
        /* _reserved         */ {nullptr, nullptr, nullptr, nullptr},          \
    };                                                                         \
    } /* anonymous namespace */                                                \
                                                                               \
    extern "C" {                                                               \
                                                                               \
    GN_PLUGIN_EXPORT void gn_plugin_sdk_version(std::uint32_t* major,          \
                                                 std::uint32_t* minor,         \
                                                 std::uint32_t* patch) {       \
        if (major) *major = GN_SDK_VERSION_MAJOR;                              \
        if (minor) *minor = GN_SDK_VERSION_MINOR;                              \
        if (patch) *patch = GN_SDK_VERSION_PATCH;                              \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t gn_plugin_init(                               \
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
        /* Force msg_ids cache to populate before kernel queries it. */        \
        (void)_gn_handler_persisted_msg_ids(p->handler.get(), true);           \
        *out_self = p;                                                         \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t gn_plugin_register(void* self) {              \
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
        if constexpr (::gn::sdk::detail::has_extension_v<                      \
                          _gn_handler_class_t>) {                              \
            if (p->api->register_extension) {                                  \
                if (p->api->register_extension(                                \
                        p->host_ctx,                                           \
                        _gn_handler_class_t::extension_name(),                 \
                        _gn_handler_class_t::extension_version(),              \
                        p->handler->extension_vtable()) == GN_OK) {            \
                    p->extension_registered = true;                            \
                }                                                              \
            }                                                                  \
        }                                                                      \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t gn_plugin_unregister(void* self) {            \
        if (!self) return GN_ERR_NULL_ARG;                                     \
        auto* p = static_cast<_gn_handler_instance_t*>(self);                  \
        if constexpr (::gn::sdk::detail::has_extension_v<                      \
                          _gn_handler_class_t>) {                              \
            if (p->extension_registered &&                                     \
                p->api && p->api->unregister_extension) {                      \
                (void)p->api->unregister_extension(                            \
                    p->host_ctx,                                               \
                    _gn_handler_class_t::extension_name());                    \
                p->extension_registered = false;                               \
            }                                                                  \
        }                                                                      \
        if (p->api && p->api->unregister_vtable &&                             \
            p->handler_id != GN_INVALID_ID) {                                  \
            (void)p->api->unregister_vtable(p->host_ctx, p->handler_id);       \
            p->handler_id = GN_INVALID_ID;                                     \
        }                                                                      \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT void gn_plugin_shutdown(void* self) {                     \
        delete static_cast<_gn_handler_instance_t*>(self);                     \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT const gn_plugin_descriptor_t*                             \
    gn_plugin_descriptor(void) {                                               \
        return &_gn_handler_descriptor;                                        \
    }                                                                          \
                                                                               \
    } /* extern "C" */                                                         \
    /**/
