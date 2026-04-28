// SPDX-License-Identifier: MIT
/// @file   plugins/transports/udp/plugin_entry.cpp
/// @brief  `gn_plugin_*` + `gn_transport_vtable_t` glue around `UdpTransport`.

#include "udp.hpp"

#include <sdk/abi.h>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/transport.h>

#include <cstdint>
#include <new>
#include <span>
#include <vector>

namespace {

using gn::transport::udp::UdpTransport;

struct UdpPlugin {
    const host_api_t*                api          = nullptr;
    void*                            host_ctx     = nullptr;
    std::shared_ptr<UdpTransport>    transport;
    gn_transport_id_t                transport_id = GN_INVALID_ID;
};

UdpTransport& udp_of(void* self) {
    return *static_cast<UdpPlugin*>(self)->transport;
}

constexpr const char kUdpScheme[] = "udp";

const char* udp_scheme(void* /*self*/) { return kUdpScheme; }

gn_result_t udp_listen(void* self, const char* uri) {
    if (!self || !uri) return GN_ERR_NULL_ARG;
    return udp_of(self).listen(uri);
}

gn_result_t udp_connect(void* self, const char* uri) {
    if (!self || !uri) return GN_ERR_NULL_ARG;
    return udp_of(self).connect(uri);
}

gn_result_t udp_send(void* self, gn_conn_id_t conn,
                      const std::uint8_t* bytes, std::size_t size) {
    if (!self) return GN_ERR_NULL_ARG;
    if (!bytes && size > 0) return GN_ERR_NULL_ARG;
    return udp_of(self).send(conn,
        std::span<const std::uint8_t>(bytes, size));
}

gn_result_t udp_send_batch(void* self, gn_conn_id_t conn,
                            const gn_byte_span_t* batch, std::size_t count) {
    if (!self) return GN_ERR_NULL_ARG;
    if (count > 0 && !batch) return GN_ERR_NULL_ARG;
    std::vector<std::span<const std::uint8_t>> frames;
    frames.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        frames.emplace_back(batch[i].bytes, batch[i].size);
    }
    return udp_of(self).send_batch(conn,
        std::span<const std::span<const std::uint8_t>>(frames));
}

gn_result_t udp_disconnect(void* self, gn_conn_id_t conn) {
    if (!self) return GN_ERR_NULL_ARG;
    return udp_of(self).disconnect(conn);
}

const char* udp_extension_name(void* /*self*/) { return nullptr; }
const void* udp_extension_vtable(void* /*self*/) { return nullptr; }
void        udp_destroy(void* /*self*/) {}

gn_transport_vtable_t make_vtable() {
    gn_transport_vtable_t v{};
    v.api_size         = sizeof(gn_transport_vtable_t);
    v.scheme           = &udp_scheme;
    v.listen           = &udp_listen;
    v.connect          = &udp_connect;
    v.send             = &udp_send;
    v.send_batch       = &udp_send_batch;
    v.disconnect       = &udp_disconnect;
    v.extension_name   = &udp_extension_name;
    v.extension_vtable = &udp_extension_vtable;
    v.destroy          = &udp_destroy;
    return v;
}

const gn_transport_vtable_t kVtable = make_vtable();

const char* const kProvidesList[] = {
    "gn.transport.udp",
    nullptr,
};

const gn_plugin_descriptor_t kDescriptor = {
    /* name              */ "goodnet_transport_udp",
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
    auto* p = new (std::nothrow) UdpPlugin{};
    if (!p) return GN_ERR_OUT_OF_MEMORY;
    p->api      = api;
    p->host_ctx = api->host_ctx;
    p->transport = std::make_shared<UdpTransport>();
    p->transport->set_host_api(api);
    *out_self = p;
    return GN_OK;
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_register(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<UdpPlugin*>(self);
    if (!p->api || !p->api->register_transport) return GN_ERR_NOT_IMPLEMENTED;
    return p->api->register_transport(
        p->host_ctx, kUdpScheme, &kVtable, p, &p->transport_id);
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_unregister(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<UdpPlugin*>(self);
    if (p->api && p->api->unregister_transport &&
        p->transport_id != GN_INVALID_ID) {
        (void)p->api->unregister_transport(p->host_ctx, p->transport_id);
        p->transport_id = GN_INVALID_ID;
    }
    if (p->transport) p->transport->shutdown();
    return GN_OK;
}

GN_PLUGIN_EXPORT void gn_plugin_shutdown(void* self) {
    delete static_cast<UdpPlugin*>(self);
}

GN_PLUGIN_EXPORT const gn_plugin_descriptor_t* gn_plugin_descriptor(void) {
    return &kDescriptor;
}

}  // extern "C"
