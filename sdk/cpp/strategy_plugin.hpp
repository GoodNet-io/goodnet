// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/strategy_plugin.hpp
/// @brief  `GN_STRATEGY_PLUGIN(Class, "plugin_name", "version")` —
///         collapses strategy plugin entry-file boilerplate into one
///         macro, symmetrical to `GN_HANDLER_PLUGIN` /
///         `GN_LINK_PLUGIN`.
///
/// What the macro generates:
///   1. Five `gn_plugin_*` extern "C" entry points plus the optional
///      `gn_plugin_descriptor`.
///   2. `gn_strategy_api_t` vtable with SFINAE-dispatched optional
///      `on_path_event` thunk (the `pick_conn` slot is required).
///   3. `register_extension(extension_name(), extension_version(),
///      &vtable)` call on register; matching `unregister_extension`
///      on unregister.
///   4. `gn_plugin_descriptor_t` with `kind = GN_PLUGIN_KIND_STRATEGY`.
///
/// ## Class concept
///
/// ```cpp
/// class MyStrategy {
/// public:
///     explicit MyStrategy(const host_api_t* api);
///
///     /// Required extension surface. The macro registers this name
///     /// + version with the kernel's extension registry; the
///     /// vtable is auto-built from the methods below.
///     static constexpr const char*       extension_name();
///     static constexpr std::uint32_t     extension_version();
///
///     /// Required routing decision. Returns one of the conn ids in
///     /// `candidates` (or GN_ERR_NOT_FOUND to defer to fallback).
///     gn_result_t pick_conn(
///         const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
///         const gn_path_sample_t* candidates,
///         std::size_t candidate_count,
///         gn_conn_id_t* out_chosen);
///
///     /// All optional:
///     gn_result_t on_path_event(
///         const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
///         gn_path_event_t ev,
///         const gn_path_sample_t* sample);
///     void on_init();
///     void on_shutdown();
/// };
/// ```

#pragma once

#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>

#include <sdk/abi.h>
#include <sdk/extensions/strategy.h>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/types.h>

namespace gn::sdk::detail {

template <class T>
struct StrategyPluginInstance {
    const host_api_t* api                  = nullptr;
    void*             host_ctx             = nullptr;
    std::unique_ptr<T> strategy;
    bool              extension_registered = false;
};

template <class T>
[[nodiscard]] gn_result_t pick_conn_dispatch(
    T& s,
    const std::uint8_t* peer_pk,
    const gn_path_sample_t* candidates,
    std::size_t count,
    gn_conn_id_t* out_chosen) noexcept {
    if (!peer_pk || !candidates || count == 0 || !out_chosen) {
        return GN_ERR_NULL_ARG;
    }
    try {
        return s.pick_conn(peer_pk, candidates, count, out_chosen);
    } catch (...) {
        return GN_ERR_NULL_ARG;
    }
}

template <class T>
[[nodiscard]] gn_result_t on_path_event_dispatch(
    T& s,
    const std::uint8_t* peer_pk,
    gn_path_event_t ev,
    const gn_path_sample_t* sample) noexcept {
    if constexpr (requires { s.on_path_event(peer_pk, ev, sample); }) {
        try {
            return s.on_path_event(peer_pk, ev, sample);
        } catch (...) {
            return GN_OK;  // best-effort observer; never break dispatch
        }
    } else {
        (void)s; (void)peer_pk; (void)ev; (void)sample;
        return GN_OK;
    }
}

template <class T>
void strategy_on_init_dispatch(T& s) noexcept {
    if constexpr (requires { s.on_init(); }) {
        try { s.on_init(); } catch (...) {  // NOLINT(bugprone-empty-catch)
            // C ABI boundary — exceptions must not unwind into kernel.
        }
    } else { (void)s; }
}

template <class T>
void strategy_on_shutdown_dispatch(T& s) noexcept {
    if constexpr (requires { s.on_shutdown(); }) {
        try { s.on_shutdown(); } catch (...) {  // NOLINT(bugprone-empty-catch)
            // C ABI boundary — exceptions must not unwind into kernel.
        }
    } else { (void)s; }
}

template <class T>
constexpr bool strategy_has_required_v =
    requires {
        { T::extension_name() }    -> std::convertible_to<const char*>;
        { T::extension_version() } -> std::convertible_to<std::uint32_t>;
    };

}  // namespace gn::sdk::detail

/// `GN_STRATEGY_PLUGIN(Class, "plugin_name", "version")`. See file
/// header for the class concept. `plugin_name` and `version` are
/// embedded in the `gn_plugin_descriptor_t`; the registered
/// extension name + version come from the class's static methods.
#define GN_STRATEGY_PLUGIN(ClassName, PLUGIN_NAME, PLUGIN_VERSION)             \
    namespace {                                                                \
    using _gn_strategy_class_t = ClassName;                                    \
    using _gn_strategy_instance_t =                                            \
        ::gn::sdk::detail::StrategyPluginInstance<_gn_strategy_class_t>;       \
                                                                               \
    static_assert(                                                             \
        ::gn::sdk::detail::strategy_has_required_v<_gn_strategy_class_t>,      \
        "strategy class must expose extension_name() + "                       \
        "extension_version() static methods");                                 \
                                                                               \
    constexpr const char* _gn_strategy_plugin_name    = PLUGIN_NAME;           \
    constexpr const char* _gn_strategy_plugin_version = PLUGIN_VERSION;        \
                                                                               \
    inline _gn_strategy_class_t& _gn_strategy_of(void* p) noexcept {           \
        return *static_cast<_gn_strategy_instance_t*>(p)->strategy;            \
    }                                                                          \
                                                                               \
    gn_result_t _gn_strategy_pick_conn_thunk(                                  \
        void* ctx,                                                             \
        const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],                       \
        const gn_path_sample_t* candidates,                                    \
        std::size_t candidate_count,                                           \
        gn_conn_id_t* out_chosen) noexcept {                                   \
        return ::gn::sdk::detail::pick_conn_dispatch(                          \
            _gn_strategy_of(ctx),                                              \
            peer_pk, candidates, candidate_count, out_chosen);                 \
    }                                                                          \
                                                                               \
    gn_result_t _gn_strategy_on_path_event_thunk(                              \
        void* ctx,                                                             \
        const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],                       \
        gn_path_event_t ev,                                                    \
        const gn_path_sample_t* sample) noexcept {                             \
        return ::gn::sdk::detail::on_path_event_dispatch(                      \
            _gn_strategy_of(ctx), peer_pk, ev, sample);                        \
    }                                                                          \
                                                                               \
    gn_strategy_api_t _gn_strategy_make_vtable(void* ctx) noexcept {           \
        gn_strategy_api_t v{};                                                 \
        v.api_size      = sizeof(gn_strategy_api_t);                           \
        v.pick_conn     = &_gn_strategy_pick_conn_thunk;                       \
        v.on_path_event = &_gn_strategy_on_path_event_thunk;                   \
        v.ctx           = ctx;                                                 \
        return v;                                                              \
    }                                                                          \
                                                                               \
    const char* const _gn_strategy_provides[] = {                              \
        nullptr,                                                               \
        nullptr,                                                               \
    };                                                                         \
                                                                               \
    const gn_plugin_descriptor_t _gn_strategy_descriptor = {                   \
        /* name              */ PLUGIN_NAME,                                   \
        /* version           */ PLUGIN_VERSION,                                \
        /* hot_reload_safe   */ 0,                                             \
        /* ext_requires      */ nullptr,                                       \
        /* ext_provides      */ &_gn_strategy_provides[0],                     \
        /* kind              */ GN_PLUGIN_KIND_STRATEGY,                       \
        /* _reserved         */ {nullptr, nullptr, nullptr, nullptr},          \
    };                                                                         \
    }  /* anonymous namespace */                                               \
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
        auto* p = new (std::nothrow) _gn_strategy_instance_t{};                \
        if (!p) return GN_ERR_OUT_OF_MEMORY;                                   \
        p->api      = api;                                                     \
        p->host_ctx = api->host_ctx;                                           \
        try {                                                                  \
            p->strategy = std::make_unique<_gn_strategy_class_t>(api);         \
        } catch (...) {                                                        \
            delete p;                                                          \
            return GN_ERR_OUT_OF_MEMORY;                                       \
        }                                                                      \
        ::gn::sdk::detail::strategy_on_init_dispatch(*p->strategy);            \
        *out_self = p;                                                         \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t gn_plugin_register(void* self) {              \
        if (!self) return GN_ERR_NULL_ARG;                                     \
        auto* p = static_cast<_gn_strategy_instance_t*>(self);                 \
        if (!p->api || !p->api->register_extension) {                          \
            return GN_ERR_NOT_IMPLEMENTED;                                     \
        }                                                                      \
        static gn_strategy_api_t vt = _gn_strategy_make_vtable(p);             \
        vt.ctx = p;                                                            \
        const gn_result_t rc = p->api->register_extension(                     \
            p->host_ctx,                                                       \
            _gn_strategy_class_t::extension_name(),                            \
            _gn_strategy_class_t::extension_version(),                         \
            &vt);                                                              \
        if (rc != GN_OK) return rc;                                            \
        p->extension_registered = true;                                        \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t gn_plugin_unregister(void* self) {            \
        if (!self) return GN_ERR_NULL_ARG;                                     \
        auto* p = static_cast<_gn_strategy_instance_t*>(self);                 \
        if (p->extension_registered &&                                         \
            p->api && p->api->unregister_extension) {                          \
            (void)p->api->unregister_extension(                                \
                p->host_ctx,                                                   \
                _gn_strategy_class_t::extension_name());                       \
            p->extension_registered = false;                                   \
        }                                                                      \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT void gn_plugin_shutdown(void* self) {                     \
        if (!self) return;                                                     \
        auto* p = static_cast<_gn_strategy_instance_t*>(self);                 \
        if (p->strategy) {                                                     \
            ::gn::sdk::detail::strategy_on_shutdown_dispatch(*p->strategy);    \
        }                                                                      \
        delete p;                                                              \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT const gn_plugin_descriptor_t*                             \
    gn_plugin_descriptor(void) {                                               \
        return &_gn_strategy_descriptor;                                       \
    }                                                                          \
                                                                               \
    }  /* extern "C" */                                                        \
    /**/
