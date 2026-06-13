// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/float_send_plugin.hpp
/// @brief  `GN_FLOAT_SEND_PLUGIN(Class, "name", "version")` —
///         collapses float-send plugin entry boilerplate into one macro,
///         symmetric with `GN_STRATEGY_PLUGIN`.
///
/// ## Class concept
///
/// ```cpp
/// class MyFloatSend {
/// public:
///     explicit MyFloatSend(const host_api_t* api);
///
///     static constexpr const char*   extension_name();
///     static constexpr uint32_t      extension_version();
///
///     /// Required: called instead of the strategy chain when
///     /// float_send returns GN_OK. Return GN_ERR_NOT_FOUND to pass.
///     gn_result_t float_send(
///         const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
///         uint32_t msg_id,
///         const uint8_t* payload, size_t payload_size,
///         const gn_path_sample_t* candidates, size_t count);
///
///     /// Optional path-event hook (same contract as strategy):
///     gn_result_t on_path_event(
///         const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
///         gn_path_event_t ev,
///         const gn_path_sample_t* sample);
///
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
#include <sdk/cpp/contract.hpp>
#include <sdk/cpp/dispatcher.hpp>
#include <sdk/extensions/float_send.h>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/types.h>

namespace gn::sdk::detail {

template <class T>
struct FloatSendPluginInstance {
    const host_api_t* api                  = nullptr;
    void*             host_ctx             = nullptr;
    std::unique_ptr<T> plugin;
    bool              extension_registered = false;
    gn_float_send_api_t vtable             = {};
};

template <class T>
[[nodiscard]] gn_result_t float_send_dispatch(
    T& p,
    const std::uint8_t* peer_pk,
    std::uint32_t msg_id,
    const std::uint8_t* payload,
    std::size_t payload_size,
    const gn_path_sample_t* candidates,
    std::size_t count) noexcept {
    if (!peer_pk || (!payload && payload_size) || !candidates || count == 0)
        return GN_ERR_NULL_ARG;
    try {
        return p.float_send(peer_pk, msg_id, payload, payload_size,
                             candidates, count);
    } catch (...) {
        return GN_ERR_INVALID_STATE;
    }
}

template <class T>
[[nodiscard]] gn_result_t float_send_path_event_dispatch(
    T& p,
    const std::uint8_t* peer_pk,
    gn_path_event_t ev,
    const gn_path_sample_t* sample) noexcept {
    if constexpr (requires { p.on_path_event(peer_pk, ev, sample); }) {
        try {
            return p.on_path_event(peer_pk, ev, sample);
        } catch (...) {
            return GN_OK;
        }
    } else {
        (void)p; (void)peer_pk; (void)ev; (void)sample;
        return GN_OK;
    }
}

template <class T>
constexpr bool float_send_has_required_v =
    requires {
        { T::extension_name() }    -> std::convertible_to<const char*>;
        { T::extension_version() } -> std::convertible_to<std::uint32_t>;
    };

template <class T>
constexpr std::uint8_t float_send_hot_reload_safe_v = []() {
    if constexpr (requires { { T::hot_reload_safe } -> std::convertible_to<bool>; }) {
        return T::hot_reload_safe ? std::uint8_t{1} : std::uint8_t{0};
    } else {
        return std::uint8_t{0};
    }
}();

}  // namespace gn::sdk::detail

#define GN_FLOAT_SEND_PLUGIN(ClassName, PLUGIN_NAME, PLUGIN_VERSION)           \
    namespace {                                                                \
    using _gn_float_send_class_t = ClassName;                                  \
    using _gn_float_send_instance_t =                                          \
        ::gn::sdk::detail::FloatSendPluginInstance<_gn_float_send_class_t>;    \
                                                                               \
    static_assert(                                                             \
        ::gn::sdk::detail::float_send_has_required_v<_gn_float_send_class_t>, \
        "float-send class must expose extension_name() + "                     \
        "extension_version() static methods");                                 \
                                                                               \
    constexpr const char* _gn_float_send_plugin_name    = PLUGIN_NAME;         \
    constexpr const char* _gn_float_send_plugin_version = PLUGIN_VERSION;      \
                                                                               \
    inline _gn_float_send_class_t& _gn_float_send_of(void* p) noexcept {       \
        return *static_cast<_gn_float_send_instance_t*>(p)->plugin;            \
    }                                                                          \
                                                                               \
    gn_result_t _gn_float_send_thunk(                                          \
        void* ctx,                                                             \
        const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],                       \
        std::uint32_t msg_id,                                                  \
        const std::uint8_t* payload,                                           \
        std::size_t payload_size,                                              \
        const gn_path_sample_t* candidates,                                    \
        std::size_t candidate_count) noexcept                                  \
        GN_EXPECTS(ctx != nullptr)                                             \
    {                                                                          \
        if (!ctx) return GN_ERR_NULL_ARG;                                      \
        return ::gn::sdk::detail::float_send_dispatch(                         \
            _gn_float_send_of(ctx),                                            \
            peer_pk, msg_id, payload, payload_size,                            \
            candidates, candidate_count);                                      \
    }                                                                          \
                                                                               \
    gn_result_t _gn_float_send_path_event_thunk(                               \
        void* ctx,                                                             \
        const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],                       \
        gn_path_event_t ev,                                                    \
        const gn_path_sample_t* sample) noexcept                               \
        GN_EXPECTS(ctx != nullptr)                                             \
    {                                                                          \
        if (!ctx) return GN_ERR_NULL_ARG;                                      \
        return ::gn::sdk::detail::float_send_path_event_dispatch(              \
            _gn_float_send_of(ctx), peer_pk, ev, sample);                      \
    }                                                                          \
                                                                               \
    gn_float_send_api_t _gn_float_send_make_vtable(void* ctx) noexcept {       \
        gn_float_send_api_t v{};                                               \
        v.api_size      = sizeof(gn_float_send_api_t);                         \
        v.float_send    = &_gn_float_send_thunk;                               \
        v.on_path_event = &_gn_float_send_path_event_thunk;                    \
        v.ctx           = ctx;                                                 \
        return v;                                                              \
    }                                                                          \
                                                                               \
    const char* const _gn_float_send_provides[] = {nullptr, nullptr};          \
                                                                               \
    const gn_plugin_descriptor_t _gn_float_send_descriptor = {                 \
        PLUGIN_NAME, PLUGIN_VERSION,                                           \
        ::gn::sdk::detail::float_send_hot_reload_safe_v<                       \
            _gn_float_send_class_t>,                                           \
        nullptr, &_gn_float_send_provides[0],                                  \
        GN_PLUGIN_KIND_STRATEGY, nullptr, {},                                   \
    };                                                                         \
    }  /* anonymous namespace */                                               \
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
        auto* p = new (std::nothrow) _gn_float_send_instance_t{};              \
        if (!p) return GN_ERR_OUT_OF_MEMORY;                                   \
        p->api      = api;                                                     \
        p->host_ctx = api->host_ctx;                                           \
        try {                                                                  \
            p->plugin = std::make_unique<_gn_float_send_class_t>(api);         \
        } catch (...) {                                                        \
            delete p;                                                          \
            return GN_ERR_OUT_OF_MEMORY;                                       \
        }                                                                      \
        try { ::gn::sdk::detail::dispatch_on_init(*p->plugin); }               \
        catch (...) {}  /* NOLINT(bugprone-empty-catch) */                     \
        *out_self = p;                                                         \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_REGISTER_NAME(void* self) {         \
        if (!self) return GN_ERR_NULL_ARG;                                     \
        auto* p = static_cast<_gn_float_send_instance_t*>(self);               \
        if (!p->api || !p->api->register_extension)                            \
            return GN_ERR_NOT_IMPLEMENTED;                                     \
        p->vtable = _gn_float_send_make_vtable(p);                             \
        const gn_result_t rc = p->api->register_extension(                     \
            p->host_ctx,                                                       \
            _gn_float_send_class_t::extension_name(),                          \
            _gn_float_send_class_t::extension_version(),                       \
            &p->vtable);                                                       \
        if (rc != GN_OK) return rc;                                            \
        p->extension_registered = true;                                        \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_UNREGISTER_NAME(void* self) {       \
        if (!self) return GN_ERR_NULL_ARG;                                     \
        auto* p = static_cast<_gn_float_send_instance_t*>(self);               \
        if (p->extension_registered &&                                         \
            p->api && p->api->unregister_extension) {                          \
            (void)p->api->unregister_extension(                                \
                p->host_ctx,                                                   \
                _gn_float_send_class_t::extension_name());                     \
            p->extension_registered = false;                                   \
        }                                                                      \
        return GN_OK;                                                          \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT void GN_PLUGIN_SHUTDOWN_NAME(void* self) {                \
        if (!self) return;                                                     \
        auto* p = static_cast<_gn_float_send_instance_t*>(self);               \
        if (p->plugin) {                                                       \
            try { ::gn::sdk::detail::dispatch_on_shutdown(*p->plugin); }       \
            catch (...) {}  /* NOLINT(bugprone-empty-catch) */                 \
        }                                                                      \
        delete p;                                                              \
    }                                                                          \
                                                                               \
    GN_PLUGIN_EXPORT const gn_plugin_descriptor_t*                             \
    GN_PLUGIN_DESCRIPTOR_NAME(void) {                                          \
        return &_gn_float_send_descriptor;                                     \
    }                                                                          \
                                                                               \
    }  /* extern "C" */                                                        \
    /**/
