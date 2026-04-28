// SPDX-License-Identifier: MIT
/// @file   plugins/transports/ipc/plugin_entry.cpp
/// @brief  `gn_plugin_*` + `gn_transport_vtable_t` glue around `IpcTransport`.

#include "ipc.hpp"

#include <sdk/abi.h>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/transport.h>

#include <cstdint>
#include <new>
#include <span>
#include <vector>

namespace {

using gn::transport::ipc::IpcTransport;

struct IpcPlugin {
    const host_api_t*                api          = nullptr;
    void*                            host_ctx     = nullptr;
    std::shared_ptr<IpcTransport>    transport;
    gn_transport_id_t                transport_id = GN_INVALID_ID;
};

IpcTransport& ipc_of(void* self) {
    return *static_cast<IpcPlugin*>(self)->transport;
}

constexpr const char kIpcScheme[] = "ipc";

const char* ipc_scheme(void* /*self*/) { return kIpcScheme; }

gn_result_t ipc_listen(void* self, const char* uri) {
    if (!self || !uri) return GN_ERR_NULL_ARG;
    return ipc_of(self).listen(uri);
}

gn_result_t ipc_connect(void* self, const char* uri) {
    if (!self || !uri) return GN_ERR_NULL_ARG;
    return ipc_of(self).connect(uri);
}

gn_result_t ipc_send(void* self, gn_conn_id_t conn,
                      const std::uint8_t* bytes, std::size_t size) {
    if (!self) return GN_ERR_NULL_ARG;
    if (!bytes && size > 0) return GN_ERR_NULL_ARG;
    return ipc_of(self).send(conn,
        std::span<const std::uint8_t>(bytes, size));
}

gn_result_t ipc_send_batch(void* self, gn_conn_id_t conn,
                            const gn_byte_span_t* batch, std::size_t count) {
    if (!self) return GN_ERR_NULL_ARG;
    if (count > 0 && !batch) return GN_ERR_NULL_ARG;
    std::vector<std::span<const std::uint8_t>> frames;
    frames.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        frames.emplace_back(batch[i].bytes, batch[i].size);
    }
    return ipc_of(self).send_batch(conn,
        std::span<const std::span<const std::uint8_t>>(frames));
}

gn_result_t ipc_disconnect(void* self, gn_conn_id_t conn) {
    if (!self) return GN_ERR_NULL_ARG;
    return ipc_of(self).disconnect(conn);
}

const char* ipc_extension_name(void* /*self*/) { return nullptr; }
const void* ipc_extension_vtable(void* /*self*/) { return nullptr; }
void        ipc_destroy(void* /*self*/) {}

gn_transport_vtable_t make_vtable() {
    gn_transport_vtable_t v{};
    v.api_size         = sizeof(gn_transport_vtable_t);
    v.scheme           = &ipc_scheme;
    v.listen           = &ipc_listen;
    v.connect          = &ipc_connect;
    v.send             = &ipc_send;
    v.send_batch       = &ipc_send_batch;
    v.disconnect       = &ipc_disconnect;
    v.extension_name   = &ipc_extension_name;
    v.extension_vtable = &ipc_extension_vtable;
    v.destroy          = &ipc_destroy;
    return v;
}

const gn_transport_vtable_t kVtable = make_vtable();

const char* const kProvidesList[] = {
    "gn.transport.ipc",
    nullptr,
};

const gn_plugin_descriptor_t kDescriptor = {
    /* name              */ "goodnet_transport_ipc",
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
    auto* p = new (std::nothrow) IpcPlugin{};
    if (!p) return GN_ERR_OUT_OF_MEMORY;
    p->api      = api;
    p->host_ctx = api->host_ctx;
    p->transport = std::make_shared<IpcTransport>();
    p->transport->set_host_api(api);
    *out_self = p;
    return GN_OK;
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_register(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<IpcPlugin*>(self);
    if (!p->api || !p->api->register_transport) return GN_ERR_NOT_IMPLEMENTED;
    return p->api->register_transport(
        p->host_ctx, kIpcScheme, &kVtable, p, &p->transport_id);
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_unregister(void* self) {
    if (!self) return GN_ERR_NULL_ARG;
    auto* p = static_cast<IpcPlugin*>(self);
    if (p->api && p->api->unregister_transport &&
        p->transport_id != GN_INVALID_ID) {
        (void)p->api->unregister_transport(p->host_ctx, p->transport_id);
        p->transport_id = GN_INVALID_ID;
    }
    if (p->transport) p->transport->shutdown();
    return GN_OK;
}

GN_PLUGIN_EXPORT void gn_plugin_shutdown(void* self) {
    delete static_cast<IpcPlugin*>(self);
}

GN_PLUGIN_EXPORT const gn_plugin_descriptor_t* gn_plugin_descriptor(void) {
    return &kDescriptor;
}

}  // extern "C"
