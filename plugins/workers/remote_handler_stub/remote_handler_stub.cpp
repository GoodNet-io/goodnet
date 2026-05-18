/// @file   plugins/workers/remote_handler_stub/remote_handler_stub.cpp
/// @brief  Subprocess worker exercising the HANDLER proxy slots.
///
/// Implements a `gn_handler_vtable_t` that subscribes to a single
/// stub message id (`kStubMsgId`). The kernel-side integration test
/// dispatches an envelope through `RemoteHost::handler_vtable_proxy`
/// and asserts the worker's `handle_message` saw the payload.

#include <cstdint>
#include <cstring>
#include <vector>

#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/types.h>

#include <sdk/cpp/remote_plugin.hpp>

namespace {

constexpr std::uint32_t kStubMsgId = 0xC0DE;

struct StubHandlerSelf {
    std::uint32_t supported_ids[1] = {kStubMsgId};
};

StubHandlerSelf g_self{};

const char* stub_protocol_id(void* /*self*/) {
    return "remote_handler_stub";
}

void stub_supported_msg_ids(void* self,
                            const std::uint32_t** out_ids,
                            size_t* out_count) {
    auto* s = static_cast<StubHandlerSelf*>(self);
    *out_ids = s->supported_ids;
    *out_count = 1;
}

gn_propagation_t stub_handle_message(void* /*self*/,
                                      const gn_message_t* envelope) {
    if (envelope == nullptr || envelope->msg_id != kStubMsgId) {
        return GN_PROPAGATION_CONTINUE;
    }
    // Stub: every CONSUMED envelope round-trips ack-style through
    // `host_api.notify_inbound_bytes` on the same conn so the test
    // observes the dispatch landed inside the worker. The synthetic
    // host_api is reachable through `synthetic_host_api()` while
    // we are inside a PLUGIN_CALL.
    const host_api_t* api = gn::sdk::remote::synthetic_host_api();
    if (api != nullptr && api->notify_inbound_bytes != nullptr &&
        envelope->payload != nullptr && envelope->payload_size != 0) {
        (void)api->notify_inbound_bytes(
            api->host_ctx, envelope->conn_id,
            envelope->payload, envelope->payload_size);
    }
    return GN_PROPAGATION_CONSUMED;
}

void stub_on_result(void* /*self*/,
                     const gn_message_t* /*envelope*/,
                     gn_propagation_t /*result*/) {}

void stub_on_init(void* /*self*/) {}
void stub_on_shutdown(void* /*self*/) {}

constexpr gn_handler_vtable_t kVtable{
    .api_size          = sizeof(gn_handler_vtable_t),
    .protocol_id       = &stub_protocol_id,
    .supported_msg_ids = &stub_supported_msg_ids,
    .handle_message    = &stub_handle_message,
    .on_result         = &stub_on_result,
    .on_init           = &stub_on_init,
    .on_shutdown       = &stub_on_shutdown,
    ._reserved         = {nullptr, nullptr, nullptr, nullptr},
};

}  // namespace

int main() {
    gn::sdk::remote::WorkerConfig cfg{};
    cfg.plugin_name    = "remote_handler_stub";
    cfg.kind           = GN_PLUGIN_KIND_HANDLER;
    cfg.handler_vtable = &kVtable;
    cfg.handler_self   = &g_self;
    return gn::sdk::remote::run_worker(cfg);
}
