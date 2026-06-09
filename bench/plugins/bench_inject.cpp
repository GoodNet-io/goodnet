// SPDX-License-Identifier: Apache-2.0
/// @file   bench/plugins/bench_inject.cpp
/// @brief  inject_message throughput — measures the kernel's hot path from
///         host_api.inject(LAYER_MESSAGE) through the router to a single
///         registered handler. No sockets, no security provider: pure
///         routing cost.

#include "../bench_harness.hpp"

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <plugins/protocols/gnet/protocol.hpp>

#include <sdk/limits.h>

#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <benchmark/benchmark.h>

#include <array>
#include <atomic>
#include <cstring>

namespace {

using namespace gn::core;
using namespace gn::plugins::gnet;

constexpr std::uint32_t kMsgInject = 0xBE1A0001u;

struct SinkCtx {
    std::atomic<std::uint64_t> calls{0};
    static gn_propagation_t handle(void* self,
                                   const gn_message_t* /*env*/) noexcept {
        static_cast<SinkCtx*>(self)->calls.fetch_add(1, std::memory_order_relaxed);
        return GN_PROPAGATION_CONSUMED;
    }
};

struct InjectFixture {
    std::unique_ptr<Kernel>       kernel = std::make_unique<Kernel>();
    std::shared_ptr<GnetProtocol> proto  = std::make_shared<GnetProtocol>();
    PluginContext                  plugin_ctx;
    host_api_t                     api{};
    SinkCtx                        sink;
    gn_handler_id_t                hid = GN_INVALID_ID;
    gn_conn_id_t                   src = GN_INVALID_ID;

    InjectFixture() {
        gn::core::protocol_layer_id_t layer_id = gn::core::kInvalidProtocolLayerId;
        (void)kernel->protocol_layers().register_layer(proto, &layer_id);
        // Disable inject rate limiter so the bench measures dispatch cost.
        gn_limits_t lim{}; lim.inject_rate_per_source = 0;
        kernel->set_limits(lim);

        plugin_ctx.plugin_name = "bench-inject";
        plugin_ctx.kernel      = kernel.get();
        api = build_host_api(plugin_ctx);

        gn::PublicKey pk; pk.fill(0xAB);
        kernel->identities().add(pk);
        gn::PublicKey peer; peer.fill(0xCD);

        (void)api.notify_connect(api.host_ctx, peer.data(),
                                  "bench://inject", GN_TRUST_PEER,
                                  GN_ROLE_RESPONDER, &src);

        gn_handler_vtable_t vt{};
        vt.api_size       = sizeof(gn_handler_vtable_t);
        vt.handle_message = &SinkCtx::handle;
        static gn_register_meta_t mt{};
        mt.api_size  = sizeof(gn_register_meta_t);
        mt.name      = "gnet-v1";
        mt.msg_id    = kMsgInject;
        mt.priority  = 128;
        (void)api.register_vtable(api.host_ctx, GN_REGISTER_HANDLER,
                                   &mt, &vt, &sink, &hid);
    }
};

static InjectFixture* g_fix = nullptr;

void BM_InjectMessage(benchmark::State& state) {
    auto& fix = *g_fix;
    const std::array<std::uint8_t, 64> payload{};

    for (auto _ : state) {
        fix.api.inject(fix.api.host_ctx, GN_INJECT_LAYER_MESSAGE,
                       fix.src, "gnet-v1", kMsgInject,
                       payload.data(), payload.size());
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(
        static_cast<std::int64_t>(state.iterations()) *
        static_cast<std::int64_t>(payload.size()));
}
BENCHMARK(BM_InjectMessage)->Threads(1)->Threads(4);

void BM_InjectMessageNoHandler(benchmark::State& state) {
    auto& fix = *g_fix;
    const std::array<std::uint8_t, 64> payload{};
    constexpr std::uint32_t kNoHandlerMsg = 0xBE1A0002u;

    for (auto _ : state) {
        fix.api.inject(fix.api.host_ctx, GN_INJECT_LAYER_MESSAGE,
                       fix.src, "gnet-v1", kNoHandlerMsg,
                       payload.data(), payload.size());
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_InjectMessageNoHandler)->Threads(1);

}  // namespace

int main(int argc, char** argv) {
    InjectFixture fix;
    g_fix = &fix;
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
