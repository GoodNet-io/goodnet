// SPDX-License-Identifier: MIT
/// @file   plugins/transports/tcp/plugin_entry.cpp
/// @brief  `gn_plugin_*` entry symbols + `gn_transport_vtable_t`
///         glue around `TcpTransport`.

#include "tcp.hpp"

#include <sdk/abi.h>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/transport.h>

#include <cstdint>
#include <new>
#include <span>

namespace {

using gn::transport::tcp::TcpTransport;

/// Plugin self carries the live transport plus the
/// kernel-allocated transport-id returned from
/// `host_api->register_transport`. The transport is owned through
/// `shared_ptr` so async sessions can outlive the plugin's
/// `gn_plugin_unregister` call until the io_context drains.
struct TcpPlugin {
    const host_api_t*                api          = nullptr;
    void*                            host_ctx     = nullptr;
    std::shared_ptr<TcpTransport>    transport;
    gn_transport_id_t                transport_id = GN_INVALID_ID;
};

/// Helper: cast the vtable's `self` to `TcpPlugin*` and reach the
/// transport. Vtable callers always pass back the pointer registered
/// alongside the vtable, so this is a stable down-cast.
TcpTransport& tcp_of(void* self) {
    return *static_cast<TcpPlugin*>(self)->transport;
}

constexpr const char kTcpScheme[] = "tcp";

const char* tcp_scheme(void* /*self*/) { return kTcpScheme; }

gn_result_t tcp_listen(void* self, const char* uri) {
    if (!self || !uri) return GN_ERR_NULL_ARG;
    return tcp_of(self).listen(uri);
}

gn_result_t tcp_connect(void* self, const char* uri) {
    if (!self || !uri) return GN_ERR_NULL_ARG;
    return tcp_of(self).connect(uri);
}

gn_result_t tcp_send(void* self, gn_conn_id_t conn,
                      const std::uint8_t* bytes, std::size_t size) {
    if (!self) return GN_ERR_NULL_ARG;
    if (!bytes && size > 0) return GN_ERR_NULL_ARG;
    return tcp_of(self).send(conn,
        std::span<const std::uint8_t>(bytes, size));
}

gn_result_t tcp_send_batch(void* self, gn_conn_id_t conn,
                            const gn_byte_span_t* batch, std::size_t count) {
    if (!self) return GN_ERR_NULL_ARG;
    if (count > 0 && !batch) return GN_ERR_NULL_ARG;
    /// Map gn_byte_span_t[] onto std::span<std::span> on the stack —
    /// small fixed-size batches are the steady-state shape.
    std::vector<std::span<const std::uint8_t>> frames;
    frames.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        frames.emplace_back(batch[i].bytes, batch[i].size);
    }
    return tcp_of(self).send_batch(conn,
        std::span<const std::span<const std::uint8_t>>(frames));
}

gn_result_t tcp_disconnect(void* self, gn_conn_id_t conn) {
    if (!self) return GN_ERR_NULL_ARG;
    return tcp_of(self).disconnect(conn);
}

const char* tcp_extension_name(void* /*self*/) {
    return nullptr;  /// no extension surface in this revision
}

const void* tcp_extension_vtable(void* /*self*/) { return nullptr; }

void tcp_destroy(void* /*self*/) {
    /// Symmetrical pair of `gn_plugin_init`'s allocation; the actual
    /// `delete` happens in `gn_plugin_shutdown`. Kernel-driven
    /// `destroy` arrives only after `unregister_transport`, leaving
    /// the plugin object ready for `shutdown` to free.
}

gn_transport_vtable_t make_vtable() {
    gn_transport_vtable_t v{};
    v.api_size         = sizeof(gn_transport_vtable_t);
    v.scheme           = &tcp_scheme;
    v.listen           = &tcp_listen;
    v.connect          = &tcp_connect;
    v.send             = &tcp_send;
    v.send_batch       = &tcp_send_batch;
    v.disconnect       = &tcp_disconnect;
    v.extension_name   = &tcp_extension_name;
    v.extension_vtable = &tcp_extension_vtable;
    v.destroy          = &tcp_destroy;
    return v;
}

const gn_transport_vtable_t kVtable = make_vtable();

const char* const kProvidesList[] = {
    "gn.transport.tcp",
    nullptr,
};

const gn_plugin_descriptor_t kDescriptor = {
    /* name              */ "goodnet_transport_tcp",
    /* version           */ "0.1.0",
    /* hot_reload_safe   */ 0,
    /* ext_requires      */ nullptr,
    /* ext_provides      */ kProvidesList,
    /* kind              */ GN_PLUGIN_KIND_TRANSPORT,
    /* _reserved         */ {nullptr, nullptr, nullptr, nullptr},
};

}  // namespace

extern "C" {

GN_PLUGIN_EXPORT void gn_plugin_sdk_version(std::uint32_t* major,
                                             std::uint32_t* minor,
                                             std::uint32_t* patch) {
    if (major) *major = GN_SDK_VERSION_MAJOR;
    if (minor) *minor = GN_SDK_VERSION_MINOR;
    if (patch) *patch = GN_SDK_VERSION_PATCH;
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_init(const host_api_t* api,
                                             void** out_self) {
    if (!api || !out_self) return GN_ERR_NULL_ARG;
    auto* p = new (std::nothrow) TcpPlugin{};
    if (!p) return GN_ERR_OUT_OF_MEMORY;
    p->api      = api;
    p->host_ctx = api->host_ctx;
    p->transport = std::make_shared<TcpTransport>();
    p->transport->set_host_api(api);
    *out_self = p;
    return GN_OK;
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_register(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<TcpPlugin*>(self);
    if (!p->api || !p->api->register_transport) return GN_ERR_NOT_IMPLEMENTED;
    return p->api->register_transport(
        p->host_ctx, kTcpScheme, &kVtable, p, &p->transport_id);
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_unregister(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<TcpPlugin*>(self);
    if (p->api && p->api->unregister_transport &&
        p->transport_id != GN_INVALID_ID) {
        (void)p->api->unregister_transport(p->host_ctx, p->transport_id);
        p->transport_id = GN_INVALID_ID;
    }
    if (p->transport) {
        p->transport->shutdown();
    }
    return GN_OK;
}

GN_PLUGIN_EXPORT void gn_plugin_shutdown(void* self) {
    delete static_cast<TcpPlugin*>(self);
}

GN_PLUGIN_EXPORT const gn_plugin_descriptor_t* gn_plugin_descriptor(void) {
    return &kDescriptor;
}

}  // extern "C"
