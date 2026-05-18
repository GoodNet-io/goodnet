// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/raw_inject/plugin_entry.cpp
/// @brief  C ABI entry points. The kernel resolves the five `gn_plugin_*`
///         symbols at dlopen; everything else is the link vtable and
///         the `gn.link.raw-inject` extension vtable.
///
/// Hand-rolled (no `GN_LINK_PLUGIN` macro) because the link declares
/// the `raw-v1` protocol layer rather than the macro's default
/// `gnet-v1`. The `raw-v1` layer ships payloads verbatim — exactly
/// what the SOCKS5-style proxy contract wants.

#include "raw_inject.hpp"

#include <cstring>
#include <memory>
#include <new>
#include <span>
#include <string_view>
#include <vector>

#include <sdk/abi.h>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/plugin.h>
#include <sdk/types.h>

namespace {

using ::gn::link::raw_inject::RawInjectLink;
using ::gn::link::raw_inject::kProtocolId;

constexpr const char  kScheme[]            = "raw-inject";
constexpr const char  kPluginName[]        = "goodnet_link_raw_inject";
constexpr const char  kExtensionName[]     = "gn.link.raw-inject";

struct Instance {
    const host_api_t*              api          = nullptr;
    void*                           host_ctx     = nullptr;
    std::shared_ptr<RawInjectLink>  link;
    gn_link_id_t                    link_id      = GN_INVALID_ID;
    gn_link_caps_t                  caps         = {};
    gn_link_api_t                   extension_vtable{};
    bool                            extension_registered = false;
};

inline RawInjectLink& link_of(void* self) {
    return *static_cast<Instance*>(self)->link;
}

// ── kernel-facing link vtable ───────────────────────────────────

const char* link_scheme(void*) { return kScheme; }

gn_result_t link_listen(void* self, const char* uri) noexcept {
    if (!self || !uri) return GN_ERR_NULL_ARG;
    try { return link_of(self).listen(uri); }
    catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_connect(void* self, const char* uri) noexcept {
    if (!self || !uri) return GN_ERR_NULL_ARG;
    try { return link_of(self).connect(uri); }
    catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_send(void* self, gn_conn_id_t conn,
                       const std::uint8_t* bytes, std::size_t size) noexcept {
    if (!self) return GN_ERR_NULL_ARG;
    if (!bytes && size > 0) return GN_ERR_NULL_ARG;
    try {
        return link_of(self).send(
            conn, std::span<const std::uint8_t>(bytes, size));
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_send_batch(void* self, gn_conn_id_t conn,
                             const gn_byte_span_t* batch,
                             std::size_t count) noexcept {
    if (!self) return GN_ERR_NULL_ARG;
    if (count > 0 && !batch) return GN_ERR_NULL_ARG;
    try {
        std::vector<std::span<const std::uint8_t>> frames;
        frames.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            frames.emplace_back(batch[i].bytes, batch[i].size);
        }
        return link_of(self).send_batch(
            conn, std::span<const std::span<const std::uint8_t>>(frames));
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t link_disconnect(void* self, gn_conn_id_t conn) noexcept {
    if (!self) return GN_ERR_NULL_ARG;
    try { return link_of(self).disconnect(conn); }
    catch (...) { return GN_ERR_NULL_ARG; }
}

const char* link_ext_name(void* self) noexcept {
    if (!self) return nullptr;
    return kExtensionName;
}

const void* link_ext_vtable(void* self) noexcept {
    if (!self) return nullptr;
    return &static_cast<Instance*>(self)->extension_vtable;
}

void link_destroy(void*) noexcept {}

// ── gn.link.raw-inject extension thunks ─────────────────────────

gn_result_t ext_get_stats(void* ctx, gn_link_stats_t* out) noexcept {
    if (!ctx || !out) return GN_ERR_NULL_ARG;
    try {
        auto* inst = static_cast<Instance*>(ctx);
        const auto s = inst->link->stats();
        std::memset(out, 0, sizeof(*out));
        out->bytes_in           = s.bytes_in;
        out->bytes_out          = s.bytes_out;
        out->frames_in          = s.frames_in;
        out->frames_out         = s.frames_out;
        out->active_connections = s.active_connections;
        return GN_OK;
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t ext_get_caps(void* ctx, gn_link_caps_t* out) noexcept {
    if (!ctx || !out) return GN_ERR_NULL_ARG;
    *out = static_cast<Instance*>(ctx)->caps;
    return GN_OK;
}

gn_result_t ext_send(void* ctx, gn_conn_id_t conn,
                      const std::uint8_t* bytes, std::size_t size) noexcept {
    if (!ctx) return GN_ERR_NULL_ARG;
    if (!bytes && size > 0) return GN_ERR_NULL_ARG;
    try {
        auto* inst = static_cast<Instance*>(ctx);
        return inst->link->send(
            conn, std::span<const std::uint8_t>(bytes, size));
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t ext_send_batch(void* ctx, gn_conn_id_t conn,
                            const gn_byte_span_t* batch,
                            std::size_t count) noexcept {
    if (!ctx) return GN_ERR_NULL_ARG;
    if (count > 0 && !batch) return GN_ERR_NULL_ARG;
    try {
        auto* inst = static_cast<Instance*>(ctx);
        std::vector<std::span<const std::uint8_t>> frames;
        frames.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            frames.emplace_back(batch[i].bytes, batch[i].size);
        }
        return inst->link->send_batch(
            conn, std::span<const std::span<const std::uint8_t>>(frames));
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t ext_close(void* ctx, gn_conn_id_t conn, int /*hard*/) noexcept {
    if (!ctx) return GN_ERR_NULL_ARG;
    try {
        auto* inst = static_cast<Instance*>(ctx);
        return inst->link->disconnect(conn);
    } catch (...) { return GN_ERR_NULL_ARG; }
}

gn_result_t ext_unimpl_listen(void*, const char*) noexcept {
    return GN_ERR_NOT_IMPLEMENTED;
}
gn_result_t ext_unimpl_connect(void*, const char*, gn_conn_id_t* out) noexcept {
    if (out) *out = GN_INVALID_ID;
    return GN_ERR_NOT_IMPLEMENTED;
}
gn_result_t ext_unimpl_subscribe(void*, gn_conn_id_t,
                                  gn_link_data_cb_t, void*) noexcept {
    return GN_ERR_NOT_IMPLEMENTED;
}
gn_result_t ext_unimpl_unsubscribe(void*, gn_conn_id_t) noexcept {
    return GN_ERR_NOT_IMPLEMENTED;
}
gn_result_t ext_unimpl_subscribe_accept(void*, gn_link_accept_cb_t,
                                         void*,
                                         gn_subscription_id_t* out) noexcept {
    if (out) *out = GN_INVALID_SUBSCRIPTION_ID;
    return GN_ERR_NOT_IMPLEMENTED;
}
gn_result_t ext_unimpl_unsubscribe_accept(
    void*, gn_subscription_id_t) noexcept {
    return GN_ERR_NOT_IMPLEMENTED;
}
gn_result_t ext_unimpl_listen_port(void*, std::uint16_t* out) noexcept {
    if (out) *out = 0;
    return GN_ERR_NOT_IMPLEMENTED;
}

void install_ext(Instance* inst) noexcept {
    auto& v          = inst->extension_vtable;
    v                = gn_link_api_t{};
    v.api_size       = sizeof(gn_link_api_t);
    v.get_stats      = &ext_get_stats;
    v.get_capabilities = &ext_get_caps;
    v.send           = &ext_send;
    v.send_batch     = &ext_send_batch;
    v.close          = &ext_close;
    v.listen         = &ext_unimpl_listen;
    v.connect        = &ext_unimpl_connect;
    v.subscribe_data = &ext_unimpl_subscribe;
    v.unsubscribe_data = &ext_unimpl_unsubscribe;
    v.subscribe_accept = &ext_unimpl_subscribe_accept;
    v.unsubscribe_accept = &ext_unimpl_unsubscribe_accept;
    v.composer_listen_port = &ext_unimpl_listen_port;
    v.ctx = inst;
}

gn_link_vtable_t make_link_vtable() noexcept {
    gn_link_vtable_t v{};
    v.api_size         = sizeof(gn_link_vtable_t);
    v.scheme           = &link_scheme;
    v.listen           = &link_listen;
    v.connect          = &link_connect;
    v.send             = &link_send;
    v.send_batch       = &link_send_batch;
    v.disconnect       = &link_disconnect;
    v.extension_name   = &link_ext_name;
    v.extension_vtable = &link_ext_vtable;
    v.destroy          = &link_destroy;
    return v;
}

const gn_link_vtable_t kVtable = make_link_vtable();

const char* const kProvides[] = {
    "gn.link.raw-inject",
    nullptr,
};

const gn_plugin_descriptor_t kDescriptor = {
    /* name              */ kPluginName,
    /* version           */ "0.1.0",
    /* hot_reload_safe   */ 0,
    /* ext_requires      */ nullptr,
    /* ext_provides      */ kProvides,
    /* kind              */ GN_PLUGIN_KIND_LINK,
    /* _reserved         */ {nullptr, nullptr, nullptr, nullptr},
};

}  // namespace

extern "C" {

GN_PLUGIN_EXPORT void GN_PLUGIN_SDK_VERSION_NAME(
    std::uint32_t* major, std::uint32_t* minor, std::uint32_t* patch) {
    if (major) *major = GN_SDK_VERSION_MAJOR;
    if (minor) *minor = GN_SDK_VERSION_MINOR;
    if (patch) *patch = GN_SDK_VERSION_PATCH;
}

GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_INIT_NAME(
    const host_api_t* api, void** out_self) {
    if (!api || !out_self) return GN_ERR_NULL_ARG;
    auto* p = new (std::nothrow) Instance{};
    if (!p) return GN_ERR_OUT_OF_MEMORY;
    try {
        p->api      = api;
        p->host_ctx = api->host_ctx;
        p->link     = std::make_shared<RawInjectLink>();
        p->link->set_host_api(api);
        p->caps     = RawInjectLink::capabilities();
        install_ext(p);
        *out_self = p;
        return GN_OK;
    } catch (...) {
        delete p;
        return GN_ERR_OUT_OF_MEMORY;
    }
}

GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_REGISTER_NAME(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<Instance*>(self);
    if (!p->api || !p->api->register_vtable) return GN_ERR_NOT_IMPLEMENTED;

    gn_register_meta_t meta{};
    meta.api_size    = sizeof(gn_register_meta_t);
    meta.name        = kScheme;
    meta.protocol_id = kProtocolId;

    if (auto rc = p->api->register_vtable(
            p->host_ctx, GN_REGISTER_LINK, &meta,
            &kVtable, p, &p->link_id);
        rc != GN_OK) {
        return rc;
    }

    if (p->api->register_extension) {
        if (auto rc = p->api->register_extension(
                p->host_ctx, kExtensionName,
                GN_EXT_LINK_VERSION, &p->extension_vtable);
            rc == GN_OK) {
            p->extension_registered = true;
        }
    }

    /// Kick off the acceptor here so the operator does not need to
    /// thread a separate `start` slot through the plugin shape. The
    /// `listen` URI was read off the live config at init time; the
    /// link binds the socket and returns.
    const auto cfg = p->link->config();
    if (const auto rc = p->link->listen(cfg.listen_uri); rc != GN_OK) {
        return rc;
    }
    return GN_OK;
}

GN_PLUGIN_EXPORT gn_result_t GN_PLUGIN_UNREGISTER_NAME(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<Instance*>(self);
    if (p->extension_registered &&
        p->api && p->api->unregister_extension) {
        (void)p->api->unregister_extension(p->host_ctx, kExtensionName);
        p->extension_registered = false;
    }
    if (p->api && p->api->unregister_vtable &&
        p->link_id != GN_INVALID_ID) {
        (void)p->api->unregister_vtable(p->host_ctx, p->link_id);
        p->link_id = GN_INVALID_ID;
    }
    if (p->link) p->link->shutdown();
    return GN_OK;
}

GN_PLUGIN_EXPORT void GN_PLUGIN_SHUTDOWN_NAME(void* self) {
    delete static_cast<Instance*>(self);
}

GN_PLUGIN_EXPORT const gn_plugin_descriptor_t*
GN_PLUGIN_DESCRIPTOR_NAME(void) {
    return &kDescriptor;
}

}  // extern "C"
