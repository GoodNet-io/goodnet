/// @file   plugins/workers/remote_slow_stub/remote_slow_stub.cpp
/// @brief  Subprocess worker that sleeps on selected lifecycle slots
///         to exercise `RemoteHost::set_reply_timeout_for_slot`.
///
/// `GOODNET_SLOW_STUB_INIT_MS` and `GOODNET_SLOW_STUB_REGISTER_MS`
/// env vars drive the per-slot sleep in milliseconds; absent or
/// unparsable values resolve to zero. The link vtable is a minimal
/// stub — the worker exists for kernel-side timeout coverage only.

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <thread>

#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/plugin.h>
#include <sdk/trust.h>

#include <sdk/cpp/remote_plugin.hpp>

namespace {

struct SlowSelf {
    const host_api_t* api = nullptr;
};

SlowSelf g_self{};

std::chrono::milliseconds env_ms(const char* name) {
    const char* v = std::getenv(name);
    if (v == nullptr || *v == '\0') return std::chrono::milliseconds{0};
    char* end = nullptr;
    long ms = std::strtol(v, &end, 10);
    if (end == v || ms < 0) return std::chrono::milliseconds{0};
    return std::chrono::milliseconds{ms};
}

const char* slow_scheme(void* /*self*/) noexcept {
    return "remote_slow_stub";
}

gn_result_t slow_listen(void* /*self*/, const char* /*uri*/) noexcept {
    return GN_OK;
}

gn_result_t slow_connect(void* /*self*/, const char* /*uri*/) noexcept {
    return GN_OK;
}

gn_result_t slow_send(void* /*self*/,
                      gn_conn_id_t /*conn*/,
                      const uint8_t* /*bytes*/,
                      size_t /*size*/) noexcept {
    return GN_OK;
}

gn_result_t slow_disconnect(void* /*self*/,
                             gn_conn_id_t /*conn*/) noexcept {
    return GN_OK;
}

void slow_destroy(void* /*self*/) noexcept {}

constexpr gn_link_vtable_t kSlowVtable{
    .api_size          = sizeof(gn_link_vtable_t),
    .scheme            = &slow_scheme,
    .listen            = &slow_listen,
    .connect           = &slow_connect,
    .send              = &slow_send,
    .send_batch        = nullptr,
    .disconnect        = &slow_disconnect,
    .extension_name    = nullptr,
    .extension_vtable  = nullptr,
    .destroy           = &slow_destroy,
    .on_topology_sealed = nullptr,
    ._reserved         = {nullptr, nullptr, nullptr, nullptr},
};

gn_result_t on_init(const host_api_t* api, void** out_self) noexcept {
    g_self = SlowSelf{};
    g_self.api = api;
    if (out_self != nullptr) {
        *out_self = &g_self;
    }
    std::this_thread::sleep_for(env_ms("GOODNET_SLOW_STUB_INIT_MS"));
    return GN_OK;
}

gn_result_t on_register(void* /*self*/) noexcept {
    std::this_thread::sleep_for(env_ms("GOODNET_SLOW_STUB_REGISTER_MS"));
    return GN_OK;
}

}  // namespace

int main() {
    gn::sdk::remote::WorkerConfig cfg{};
    cfg.plugin_name = "remote_slow_stub";
    cfg.kind        = GN_PLUGIN_KIND_LINK;
    cfg.link_vtable = &kSlowVtable;
    cfg.link_self   = &g_self;
    cfg.on_init     = &on_init;
    cfg.on_register = &on_register;
    return gn::sdk::remote::run_worker(cfg);
}
