/// @file   sdk/cpp/link_plugin.hpp
/// @brief  `GN_LINK_PLUGIN(Class, scheme)` — collapses every
///         link plugin's `plugin_entry.cpp` boilerplate into one
///         macro instantiation.
///
/// The boilerplate it replaces:
///
/// 1. Five `gn_plugin_*` extern "C" entry points.
/// 2. The `gn_link_vtable_t` thunks bridging the C ABI to the
///    link's C++ method shapes.
/// 3. The `gn.link.<scheme>` extension vtable plus its thunks
///    (steady slots functional, composer slots returning
///    `GN_ERR_NOT_IMPLEMENTED` per `link.md` §8 staged delivery).
/// 4. The `gn_plugin_descriptor_t` table.
///
/// What the producer still owns: the implementation class with its
/// method shape (see *Class concept* below).
///
/// ## Class concept
///
/// `T` is constructible with `T()` (or via a static `T::create()`
/// returning `std::shared_ptr<T>` — the macro uses
/// `std::make_shared<T>()`).  Required methods:
///
/// ```cpp
/// gn_result_t listen(std::string_view uri);
/// gn_result_t connect(std::string_view uri);
/// gn_result_t send(gn_conn_id_t conn,
///                  std::span<const std::uint8_t> bytes);
/// gn_result_t send_batch(gn_conn_id_t conn,
///                        std::span<const std::span<const std::uint8_t>> frames);
/// gn_result_t disconnect(gn_conn_id_t conn);
/// void        set_host_api(const host_api_t* api) noexcept;
/// void        shutdown();
///
/// struct Stats {
///     std::uint64_t bytes_in, bytes_out, frames_in, frames_out,
///                   active_connections;
/// };
/// Stats stats() const noexcept;
///
/// /// Static capability descriptor; called once during plugin init.
/// static gn_link_caps_t capabilities() noexcept;
/// ```
///
/// Static `capabilities()` is preferred over a per-instance method
/// because the kernel snapshots the value during plugin registration
/// and never re-reads it (per `link.md` §8 capabilities are
/// stable for the plugin's lifetime).

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <span>
#include <string_view>
#include <vector>

#include <sdk/abi.h>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/link.h>
#include <sdk/types.h>

namespace gn::sdk::detail {

/// Per-instance plugin state common across every link. Lives
/// inside the macro's anonymous namespace so two link plugins
/// loaded at once each get their own typed copy.
template <class T>
struct LinkPluginInstance {
    const host_api_t*                api          = nullptr;
    void*                            host_ctx     = nullptr;
    std::shared_ptr<T>               link;
    gn_link_id_t                link_id = GN_INVALID_ID;
    gn_link_caps_t              caps         = {};
    gn_link_api_t               extension_vtable{};
    bool                             extension_registered = false;
    char                             extension_name_buf[64] = {0};
};

/// Map a `gn_byte_span_t[]` onto the `span<span<...>>` shape the
/// link class consumes. Pulled out of the macro so the
/// producer's translation unit doesn't end up with a duplicated
/// helper for every link.
template <class T>
[[nodiscard]] gn_result_t batch_through(
    T& t,
    gn_conn_id_t conn,
    const gn_byte_span_t* batch,
    std::size_t count) {
    if (count > 0 && !batch) return GN_ERR_NULL_ARG;
    std::vector<std::span<const std::uint8_t>> frames;
    frames.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        frames.emplace_back(batch[i].bytes, batch[i].size);
    }
    return t.send_batch(conn,
        std::span<const std::span<const std::uint8_t>>(frames));
}

/// Composer-surface dispatchers — opt-in per link class. A link
/// class that defines `composer_listen / connect / subscribe_data
/// / unsubscribe_data` gets routed through; classes that don't
/// see the same `GN_ERR_NOT_IMPLEMENTED` answer the kernel-facing
/// extension surface used to return via stub thunks. Templated
/// to give `requires` a real SFINAE context — see `link.en.md` §8.
template <class T>
[[nodiscard]] gn_result_t composer_listen_dispatch(
    T& link, std::string_view uri) noexcept {
    if constexpr (requires { link.composer_listen(uri); }) {
        return link.composer_listen(uri);
    } else {
        (void)link; (void)uri;
        return GN_ERR_NOT_IMPLEMENTED;
    }
}

template <class T>
[[nodiscard]] gn_result_t composer_connect_dispatch(
    T& link, std::string_view uri, gn_conn_id_t* out) noexcept {
    if constexpr (requires { link.composer_connect(uri, out); }) {
        return link.composer_connect(uri, out);
    } else {
        (void)link; (void)uri;
        if (out) *out = GN_INVALID_ID;
        return GN_ERR_NOT_IMPLEMENTED;
    }
}

template <class T>
[[nodiscard]] gn_result_t composer_subscribe_dispatch(
    T& link, gn_conn_id_t conn,
    gn_link_data_cb_t cb, void* user) noexcept {
    if constexpr (requires { link.composer_subscribe_data(conn, cb, user); }) {
        return link.composer_subscribe_data(conn, cb, user);
    } else {
        (void)link; (void)conn; (void)cb; (void)user;
        return GN_ERR_NOT_IMPLEMENTED;
    }
}

template <class T>
[[nodiscard]] gn_result_t composer_unsubscribe_dispatch(
    T& link, gn_conn_id_t conn) noexcept {
    if constexpr (requires { link.composer_unsubscribe_data(conn); }) {
        return link.composer_unsubscribe_data(conn);
    } else {
        (void)link; (void)conn;
        return GN_ERR_NOT_IMPLEMENTED;
    }
}

template <class T>
[[nodiscard]] gn_result_t composer_subscribe_accept_dispatch(
    T& link, gn_link_accept_cb_t cb, void* user,
    gn_subscription_id_t* out_token) noexcept {
    if constexpr (requires { link.composer_subscribe_accept(cb, user, out_token); }) {
        return link.composer_subscribe_accept(cb, user, out_token);
    } else {
        (void)link; (void)cb; (void)user;
        if (out_token) *out_token = GN_INVALID_SUBSCRIPTION_ID;
        return GN_ERR_NOT_IMPLEMENTED;
    }
}

template <class T>
[[nodiscard]] gn_result_t composer_unsubscribe_accept_dispatch(
    T& link, gn_subscription_id_t token) noexcept {
    if constexpr (requires { link.composer_unsubscribe_accept(token); }) {
        return link.composer_unsubscribe_accept(token);
    } else {
        (void)link; (void)token;
        return GN_ERR_NOT_IMPLEMENTED;
    }
}

template <class T>
[[nodiscard]] gn_result_t composer_listen_port_dispatch(
    T& link, std::uint16_t* out_port) noexcept {
    if constexpr (requires { link.composer_listen_port(out_port); }) {
        return link.composer_listen_port(out_port);
    } else {
        (void)link;
        if (out_port) *out_port = 0;
        return GN_ERR_NOT_IMPLEMENTED;
    }
}

} // namespace gn::sdk::detail

/// `GN_LINK_PLUGIN(Class, "scheme")`. See file header for the class
/// concept. Defines the full plugin entry surface in an anonymous
/// namespace and the matching `extern "C"` symbols. Place at file
/// scope in exactly one translation unit per shared object.
#define GN_LINK_PLUGIN(Class, SchemeStrLiteral)                              \
    namespace {                                                                \
    using _gn_link_instance_t = ::gn::sdk::detail::LinkPluginInstance<Class>;\
    constexpr const char  _gn_link_scheme[]   = SchemeStrLiteral;                \
    constexpr const char  _gn_link_extension_prefix[] = GN_EXT_LINK_PREFIX; \
    constexpr const char  _gn_link_plugin_name[] = "goodnet_link_" SchemeStrLiteral; \
                                                                               \
    inline auto& _gn_link_of(void* self) {                                       \
        return *static_cast<_gn_link_instance_t*>(self)->link;              \
    }                                                                          \
                                                                               \
    /* ── kernel-facing link vtable ──────────────────────── */          \
    const char* _gn_link_scheme_thunk(void*) { return _gn_link_scheme; }           \
    gn_result_t _gn_link_listen(void* self, const char* uri) noexcept {          \
        if (!self || !uri) return GN_ERR_NULL_ARG;                             \
        try { return _gn_link_of(self).listen(uri); }                            \
        catch (...) { return GN_ERR_NULL_ARG; }                                \
    }                                                                          \
    gn_result_t _gn_link_connect(void* self, const char* uri) noexcept {         \
        if (!self || !uri) return GN_ERR_NULL_ARG;                             \
        try { return _gn_link_of(self).connect(uri); }                           \
        catch (...) { return GN_ERR_NULL_ARG; }                                \
    }                                                                          \
    gn_result_t _gn_link_send(void* self, gn_conn_id_t conn,                     \
                             const std::uint8_t* bytes, std::size_t size) noexcept { \
        if (!self) return GN_ERR_NULL_ARG;                                     \
        if (!bytes && size > 0) return GN_ERR_NULL_ARG;                        \
        try { return _gn_link_of(self).send(conn,                                \
            std::span<const std::uint8_t>(bytes, size)); }                     \
        catch (...) { return GN_ERR_NULL_ARG; }                                \
    }                                                                          \
    gn_result_t _gn_link_send_batch(void* self, gn_conn_id_t conn,               \
                                   const gn_byte_span_t* batch,                \
                                   std::size_t count) noexcept {               \
        if (!self) return GN_ERR_NULL_ARG;                                     \
        try { return ::gn::sdk::detail::batch_through(                         \
            _gn_link_of(self), conn, batch, count); }                            \
        catch (...) { return GN_ERR_NULL_ARG; }                                \
    }                                                                          \
    gn_result_t _gn_link_disconnect(void* self, gn_conn_id_t conn) noexcept {    \
        if (!self) return GN_ERR_NULL_ARG;                                     \
        try { return _gn_link_of(self).disconnect(conn); }                       \
        catch (...) { return GN_ERR_NULL_ARG; }                                \
    }                                                                          \
    const char* _gn_link_ext_name(void* self) noexcept {                         \
        if (!self) return nullptr;                                             \
        return static_cast<_gn_link_instance_t*>(self)->extension_name_buf;      \
    }                                                                          \
    const void* _gn_link_ext_vtable(void* self) noexcept {                       \
        if (!self) return nullptr;                                             \
        return &static_cast<_gn_link_instance_t*>(self)->extension_vtable;       \
    }                                                                          \
    void _gn_link_destroy(void*) noexcept {}                                     \
                                                                               \
    /* ── gn.link.<scheme> extension thunks ──────────────── */          \
    gn_result_t _gn_link_ext_get_stats(                                          \
        void* ctx, gn_link_stats_t* out) noexcept {                       \
        if (!ctx || !out) return GN_ERR_NULL_ARG;                              \
        try {                                                                  \
            auto* inst = static_cast<_gn_link_instance_t*>(ctx);                 \
            auto s = inst->link->stats();                                 \
            std::memset(out, 0, sizeof(*out));                                 \
            out->bytes_in           = s.bytes_in;                              \
            out->bytes_out          = s.bytes_out;                             \
            out->frames_in          = s.frames_in;                             \
            out->frames_out         = s.frames_out;                            \
            out->active_connections = s.active_connections;                    \
            return GN_OK;                                                      \
        } catch (...) { return GN_ERR_NULL_ARG; }                              \
    }                                                                          \
    gn_result_t _gn_link_ext_get_caps(                                           \
        void* ctx, gn_link_caps_t* out) noexcept {                        \
        if (!ctx || !out) return GN_ERR_NULL_ARG;                              \
        *out = static_cast<_gn_link_instance_t*>(ctx)->caps;                     \
        return GN_OK;                                                          \
    }                                                                          \
    gn_result_t _gn_link_ext_send(                                               \
        void* ctx, gn_conn_id_t conn,                                          \
        const std::uint8_t* bytes, std::size_t size) noexcept {                \
        if (!ctx) return GN_ERR_NULL_ARG;                                      \
        if (!bytes && size > 0) return GN_ERR_NULL_ARG;                        \
        try {                                                                  \
            auto* inst = static_cast<_gn_link_instance_t*>(ctx);                 \
            return inst->link->send(conn,                                 \
                std::span<const std::uint8_t>(bytes, size));                   \
        } catch (...) { return GN_ERR_NULL_ARG; }                              \
    }                                                                          \
    gn_result_t _gn_link_ext_send_batch(                                         \
        void* ctx, gn_conn_id_t conn,                                          \
        const gn_byte_span_t* batch, std::size_t count) noexcept {             \
        if (!ctx) return GN_ERR_NULL_ARG;                                      \
        try {                                                                  \
            auto* inst = static_cast<_gn_link_instance_t*>(ctx);                 \
            return ::gn::sdk::detail::batch_through(                           \
                *inst->link, conn, batch, count);                         \
        } catch (...) { return GN_ERR_NULL_ARG; }                              \
    }                                                                          \
    gn_result_t _gn_link_ext_close(                                              \
        void* ctx, gn_conn_id_t conn, int /*hard*/) noexcept {                 \
        if (!ctx) return GN_ERR_NULL_ARG;                                      \
        try {                                                                  \
            auto* inst = static_cast<_gn_link_instance_t*>(ctx);                 \
            return inst->link->disconnect(conn);                          \
        } catch (...) { return GN_ERR_NULL_ARG; }                              \
    }                                                                          \
    /* Composer (L2) routing — see `link.en.md` §8. Each thunk defers     \
     * to the templated dispatcher in `gn::sdk::detail`, which uses          \
     * C++23 `requires` to detect the composer methods on the link          \
     * class. Baseline links return GN_ERR_NOT_IMPLEMENTED for free; a       \
     * future composer-aware link class opts in by defining the matching    \
     * `composer_*` methods.                                                 \
     */                                                                      \
    gn_result_t _gn_link_ext_listen(                                           \
        void* ctx, const char* uri) noexcept {                                 \
        if (!ctx || !uri) return GN_ERR_NULL_ARG;                              \
        try {                                                                  \
            return ::gn::sdk::detail::composer_listen_dispatch(                \
                _gn_link_of(ctx), uri);                                        \
        } catch (...) { return GN_ERR_NULL_ARG; }                              \
    }                                                                          \
    gn_result_t _gn_link_ext_connect(                                          \
        void* ctx, const char* uri, gn_conn_id_t* out) noexcept {              \
        if (!ctx || !uri || !out) return GN_ERR_NULL_ARG;                      \
        try {                                                                  \
            return ::gn::sdk::detail::composer_connect_dispatch(               \
                _gn_link_of(ctx), uri, out);                                   \
        } catch (...) { return GN_ERR_NULL_ARG; }                              \
    }                                                                          \
    gn_result_t _gn_link_ext_subscribe(                                        \
        void* ctx, gn_conn_id_t conn,                                          \
        gn_link_data_cb_t cb, void* user) noexcept {                           \
        if (!ctx || !cb) return GN_ERR_NULL_ARG;                               \
        try {                                                                  \
            return ::gn::sdk::detail::composer_subscribe_dispatch(             \
                _gn_link_of(ctx), conn, cb, user);                             \
        } catch (...) { return GN_ERR_NULL_ARG; }                              \
    }                                                                          \
    gn_result_t _gn_link_ext_unsubscribe(                                      \
        void* ctx, gn_conn_id_t conn) noexcept {                               \
        if (!ctx) return GN_ERR_NULL_ARG;                                      \
        try {                                                                  \
            return ::gn::sdk::detail::composer_unsubscribe_dispatch(           \
                _gn_link_of(ctx), conn);                                       \
        } catch (...) { return GN_ERR_NULL_ARG; }                              \
    }                                                                          \
    gn_result_t _gn_link_ext_subscribe_accept(                                 \
        void* ctx, gn_link_accept_cb_t cb, void* user,                         \
        gn_subscription_id_t* out_token) noexcept {                            \
        if (!ctx || !cb || !out_token) return GN_ERR_NULL_ARG;                 \
        try {                                                                  \
            return ::gn::sdk::detail::composer_subscribe_accept_dispatch(      \
                _gn_link_of(ctx), cb, user, out_token);                        \
        } catch (...) { return GN_ERR_NULL_ARG; }                              \
    }                                                                          \
    gn_result_t _gn_link_ext_unsubscribe_accept(                               \
        void* ctx, gn_subscription_id_t token) noexcept {                      \
        if (!ctx) return GN_ERR_NULL_ARG;                                      \
        try {                                                                  \
            return ::gn::sdk::detail::composer_unsubscribe_accept_dispatch(    \
                _gn_link_of(ctx), token);                                      \
        } catch (...) { return GN_ERR_NULL_ARG; }                              \
    }                                                                          \
    gn_result_t _gn_link_ext_listen_port(                                      \
        void* ctx, std::uint16_t* out_port) noexcept {                         \
        if (!ctx || !out_port) return GN_ERR_NULL_ARG;                         \
        try {                                                                  \
            return ::gn::sdk::detail::composer_listen_port_dispatch(           \
                _gn_link_of(ctx), out_port);                                   \
        } catch (...) { return GN_ERR_NULL_ARG; }                              \
    }                                                                          \
                                                                               \
    void _gn_link_install_ext(_gn_link_instance_t* inst) noexcept {                \
        auto& v = inst->extension_vtable;                                      \
        v               = gn_link_api_t{};                                \
        v.api_size      = sizeof(gn_link_api_t);                          \
        v.get_stats     = &_gn_link_ext_get_stats;                               \
        v.get_capabilities = &_gn_link_ext_get_caps;                             \
        v.send          = &_gn_link_ext_send;                                    \
        v.send_batch    = &_gn_link_ext_send_batch;                              \
        v.close         = &_gn_link_ext_close;                                   \
        v.listen           = &_gn_link_ext_listen;                               \
        v.connect          = &_gn_link_ext_connect;                              \
        v.subscribe_data   = &_gn_link_ext_subscribe;                            \
        v.unsubscribe_data = &_gn_link_ext_unsubscribe;                          \
        v.subscribe_accept   = &_gn_link_ext_subscribe_accept;                   \
        v.unsubscribe_accept = &_gn_link_ext_unsubscribe_accept;                 \
        v.composer_listen_port = &_gn_link_ext_listen_port;                      \
        v.ctx = inst;                                                          \
        std::memcpy(inst->extension_name_buf,                                  \
                    _gn_link_extension_prefix,                                   \
                    sizeof(_gn_link_extension_prefix) - 1);                      \
        std::memcpy(inst->extension_name_buf + sizeof(_gn_link_extension_prefix) - 1, \
                    _gn_link_scheme,                                             \
                    sizeof(_gn_link_scheme));                                    \
    }                                                                          \
                                                                               \
    gn_link_vtable_t _gn_link_make_vtable() noexcept {                      \
        gn_link_vtable_t v{};                                             \
        v.api_size         = sizeof(gn_link_vtable_t);                    \
        v.scheme           = &_gn_link_scheme_thunk;                             \
        v.listen           = &_gn_link_listen;                                   \
        v.connect          = &_gn_link_connect;                                  \
        v.send             = &_gn_link_send;                                     \
        v.send_batch       = &_gn_link_send_batch;                               \
        v.disconnect       = &_gn_link_disconnect;                               \
        v.extension_name   = &_gn_link_ext_name;                                 \
        v.extension_vtable = &_gn_link_ext_vtable;                               \
        v.destroy          = &_gn_link_destroy;                                  \
        return v;                                                              \
    }                                                                          \
                                                                               \
    const gn_link_vtable_t _gn_link_kVtable = _gn_link_make_vtable();         \
                                                                               \
    const char* const _gn_link_kProvides[] = {                                   \
        "gn.link." SchemeStrLiteral,                                      \
        nullptr,                                                               \
    };                                                                         \
                                                                               \
    const gn_plugin_descriptor_t _gn_link_kDescriptor = {                        \
        /* name              */ _gn_link_plugin_name,                            \
        /* version           */ "0.1.0",                                       \
        /* hot_reload_safe   */ 0,                                             \
        /* ext_requires      */ nullptr,                                       \
        /* ext_provides      */ _gn_link_kProvides,                              \
        /* kind              */ GN_PLUGIN_KIND_LINK,                      \
        /* _reserved         */ {nullptr, nullptr, nullptr, nullptr},          \
    };                                                                         \
    } /* anonymous namespace */                                                \
                                                                               \
    extern "C" {                                                               \
    GN_PLUGIN_EXPORT void GN_PLUGIN_SDK_VERSION_NAME(                          \
        std::uint32_t* major, std::uint32_t* minor, std::uint32_t* patch) {    \
        if (major) *major = GN_SDK_VERSION_MAJOR;                              \
        if (minor) *minor = GN_SDK_VERSION_MINOR;                              \
        if (patch) *patch = GN_SDK_VERSION_PATCH;                              \
    }                                                                          \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_INIT_NAME(                          \
        const host_api_t* api, void** out_self) {                              \
        if (!api || !out_self) return GN_ERR_NULL_ARG;                         \
        auto* p = new (std::nothrow) _gn_link_instance_t{};                      \
        if (!p) return GN_ERR_OUT_OF_MEMORY;                                   \
        try {                                                                  \
            p->api      = api;                                                 \
            p->host_ctx = api->host_ctx;                                       \
            p->link = std::make_shared<Class>();                          \
            p->link->set_host_api(api);                                   \
            p->caps = Class::capabilities();                                   \
            _gn_link_install_ext(p);                                             \
            *out_self = p;                                                     \
            return GN_OK;                                                      \
        } catch (...) {                                                        \
            delete p;                                                          \
            return GN_ERR_OUT_OF_MEMORY;                                       \
        }                                                                      \
    }                                                                          \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_REGISTER_NAME(void* self) {         \
        if (!self) return GN_ERR_NULL_ARG;                                     \
        auto* p = static_cast<_gn_link_instance_t*>(self);                       \
        if (!p->api || !p->api->register_vtable) return GN_ERR_NOT_IMPLEMENTED; \
        gn_register_meta_t _gn_link_meta{};                                      \
        _gn_link_meta.api_size = sizeof(gn_register_meta_t);                     \
        _gn_link_meta.name     = _gn_link_scheme;                                  \
        if (auto rc = p->api->register_vtable(                                 \
                p->host_ctx, GN_REGISTER_LINK, &_gn_link_meta,                   \
                &_gn_link_kVtable, p, &p->link_id);                              \
            rc != GN_OK) {                                                     \
            return rc;                                                         \
        }                                                                      \
        if (p->api->register_extension) {                                      \
            if (auto rc = p->api->register_extension(                          \
                    p->host_ctx, p->extension_name_buf,                        \
                    GN_EXT_LINK_VERSION, &p->extension_vtable);           \
                rc == GN_OK) {                                                 \
                p->extension_registered = true;                                \
            }                                                                  \
        }                                                                      \
        return GN_OK;                                                          \
    }                                                                          \
    GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_UNREGISTER_NAME(void* self) {       \
        if (!self) return GN_ERR_NULL_ARG;                                     \
        auto* p = static_cast<_gn_link_instance_t*>(self);                       \
        if (p->extension_registered &&                                         \
            p->api && p->api->unregister_extension) {                          \
            (void)p->api->unregister_extension(                                \
                p->host_ctx, p->extension_name_buf);                           \
            p->extension_registered = false;                                   \
        }                                                                      \
        if (p->api && p->api->unregister_vtable &&                             \
            p->link_id != GN_INVALID_ID) {                                     \
            (void)p->api->unregister_vtable(p->host_ctx, p->link_id);          \
            p->link_id = GN_INVALID_ID;                                        \
        }                                                                      \
        if (p->link) p->link->shutdown();                                  \
        return GN_OK;                                                          \
    }                                                                          \
    GN_PLUGIN_EXPORT void GN_PLUGIN_SHUTDOWN_NAME(void* self) {                \
        delete static_cast<_gn_link_instance_t*>(self);                          \
    }                                                                          \
    GN_PLUGIN_EXPORT const gn_plugin_descriptor_t*                             \
    GN_PLUGIN_DESCRIPTOR_NAME(void) {                                          \
        return &_gn_link_kDescriptor;                                            \
    }                                                                          \
    } /* extern "C" */
