/// @file   plugins/workers/remote_echo/remote_echo.cpp
/// @brief  Proof-of-concept subprocess plugin worker.
///
/// Registers as a link plugin with scheme `remote_echo`. The
/// vtable's `send` slot routes payloads straight back to the
/// kernel through `host_api.notify_inbound_bytes`, demonstrating
/// the full kernel↔worker round trip without involving a real
/// transport. Conformance test in
/// `tests/integration/tests/test_remote_echo.cpp` (separate repo).

#include <cstdint>

#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/plugin.h>

#include <sdk/cpp/remote_plugin.hpp>

namespace {

struct EchoSelf {
    const host_api_t* api = nullptr;
    gn_conn_id_t      next_conn = 1;
};

EchoSelf g_self{};

const char* echo_scheme(void* /*self*/) noexcept {
    return "remote_echo";
}

gn_result_t echo_listen(void* /*self*/, const char* /*uri*/) noexcept {
    return GN_OK;
}

gn_result_t echo_connect(void* /*self*/, const char* /*uri*/) noexcept {
    return GN_OK;
}

gn_result_t echo_send(void* self,
                      gn_conn_id_t conn,
                      const uint8_t* bytes,
                      size_t size) noexcept {
    auto& s = *static_cast<EchoSelf*>(self);
    if (s.api == nullptr || s.api->notify_inbound_bytes == nullptr) {
        return GN_ERR_INVALID_STATE;
    }
    return s.api->notify_inbound_bytes(s.api->host_ctx, conn, bytes, size);
}

gn_result_t echo_disconnect(void* /*self*/,
                             gn_conn_id_t /*conn*/) noexcept {
    return GN_OK;
}

void echo_destroy(void* /*self*/) noexcept {}

constexpr gn_link_vtable_t kEchoVtable{
    .api_size          = sizeof(gn_link_vtable_t),
    .scheme            = &echo_scheme,
    .listen            = &echo_listen,
    .connect           = &echo_connect,
    .send              = &echo_send,
    .send_batch        = nullptr,
    .disconnect        = &echo_disconnect,
    .extension_name    = nullptr,
    .extension_vtable  = nullptr,
    .destroy           = &echo_destroy,
    ._reserved         = {nullptr, nullptr, nullptr, nullptr},
};

gn_result_t on_init(const host_api_t* api, void** out_self) noexcept {
    g_self = EchoSelf{};
    g_self.api = api;
    if (out_self != nullptr) {
        *out_self = &g_self;
    }
    return GN_OK;
}

}  // namespace

int main() {
    gn::sdk::remote::WorkerConfig cfg{};
    cfg.plugin_name = "remote_echo";
    cfg.kind        = GN_PLUGIN_KIND_LINK;
    cfg.link_vtable = &kEchoVtable;
    cfg.link_self   = &g_self;
    cfg.on_init     = &on_init;
    return gn::sdk::remote::run_worker(cfg);
}
