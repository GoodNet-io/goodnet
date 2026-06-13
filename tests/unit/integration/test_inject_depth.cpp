// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/integration/test_inject_depth.cpp
/// @brief  Kernel-side recursive inject depth protection.
///
/// The kernel maintains a `thread_local` inject-depth counter.  A handler
/// that calls `inject_message` (or `inject_frame`) re-enters the kernel
/// synchronously; at depth > `gn_limits_t::max_inject_depth` the kernel
/// returns `GN_ERR_LIMIT_REACHED` without dispatching.
///
/// Guard: this file requires GCC ≥ 16.  The integration test suite may
/// be checked out by plugin repos whose CI still uses older toolchains;
/// excluding the file at compile time prevents spurious build failures
/// on non-C++26 toolchains.

#if defined(__GNUC__) && __GNUC__ < 16
#  error "test_inject_depth.cpp requires GCC ≥ 16 (C++26 toolchain)"
#endif

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <span>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/registry/connection.hpp>
#include <tests/util/protocol_setup.hpp>

#include <plugins/protocols/gnet/protocol.hpp>

#include <sdk/cpp/inject.hpp>
#include <sdk/handler.h>
#include <sdk/limits.h>
#include <sdk/types.h>

namespace {

using namespace gn;
using namespace gn::core;
using namespace gn::plugins::gnet;

// ── Harness ──────────────────────────────────────────────────────────────

struct DepthHarness {
    std::unique_ptr<Kernel>       kernel = std::make_unique<Kernel>();
    std::shared_ptr<GnetProtocol> proto  = std::make_shared<GnetProtocol>();
    PluginContext                 plugin_ctx;
    host_api_t                   api{};

    DepthHarness() {
        gn::test::util::register_default_protocol(*kernel, proto);
        plugin_ctx.plugin_name = "inject-depth-test";
        plugin_ctx.kind        = GN_PLUGIN_KIND_HANDLER;
        plugin_ctx.kernel      = kernel.get();
        api = build_host_api(plugin_ctx);
    }

    gn_conn_id_t install_source(std::uint8_t pk_byte) {
        PublicKey pk{};
        pk.fill(pk_byte);
        const gn_conn_id_t id = kernel->connections().alloc_id();
        ConnectionRecord rec;
        rec.id          = id;
        rec.remote_pk   = pk;
        rec.uri         = "test://inject-depth";
        rec.trust       = GN_TRUST_PEER;
        rec.role        = GN_ROLE_RESPONDER;
        rec.scheme      = "test";
        rec.allows_relay = true;
        EXPECT_EQ(kernel->connections().insert_with_index(std::move(rec)),
                  GN_OK);
        return id;
    }
};

// ── Recursive handler ────────────────────────────────────────────────────

/// Each time handle() fires it immediately calls inject_message again,
/// creating a synchronous inject → dispatch → inject chain.
/// call_count tracks the number of handler invocations.
/// limit_reached_count tracks how many times inject_message returned
/// GN_ERR_LIMIT_REACHED (must be exactly 1: the call that pushed depth
/// past the configured maximum).
struct RecursiveInjector {
    const host_api_t* api{nullptr};
    gn_conn_id_t      source{GN_INVALID_ID};
    std::uint32_t     msg_id{0};
    int               call_count{0};
    int               limit_reached_count{0};

    static gn_propagation_t handle(void* self,
                                    const gn_message_t* /*env*/) noexcept {
        auto* r = static_cast<RecursiveInjector*>(self);
        ++r->call_count;
        const std::uint8_t payload[1] = {0x01};
        const gn_result_t res = gn::sdk::inject_message(
            r->api, r->source, "gnet-v1", r->msg_id,
            std::span<const std::uint8_t>{payload, 1});
        if (res == GN_ERR_LIMIT_REACHED) ++r->limit_reached_count;
        return GN_PROPAGATION_CONSUMED;
    }
};

gn_handler_id_t register_recursive(DepthHarness& h,
                                    RecursiveInjector& inj,
                                    std::uint32_t msg_id) {
    static const gn_handler_vtable_t vt = [] {
        gn_handler_vtable_t v{};
        v.api_size       = sizeof(gn_handler_vtable_t);
        v.handle_message = &RecursiveInjector::handle;
        return v;
    }();

    static gn_register_meta_t mt{};
    mt.api_size = sizeof(gn_register_meta_t);
    mt.name     = "gnet-v1";
    mt.msg_id   = msg_id;
    mt.priority = 128;

    gn_handler_id_t hid = GN_INVALID_ID;
    EXPECT_EQ(h.api.register_vtable(h.api.host_ctx, GN_REGISTER_HANDLER,
                                     &mt, &vt, &inj, &hid),
              GN_OK);
    inj.api    = &h.api;
    inj.msg_id = msg_id;
    return hid;
}

}  // namespace

// ── Tests ────────────────────────────────────────────────────────────────

/// Default max depth is GN_INJECT_MAX_DEPTH (5).  The handler is invoked
/// exactly 5 times; the 6th inject attempt (depth 6 > 5) surfaces
/// GN_ERR_LIMIT_REACHED inside the deepest handler invocation.
TEST(InjectDepth, DefaultDepth_HandlerCalledExactlyMaxDepthTimes) {
    DepthHarness h;
    RecursiveInjector inj;
    inj.source = h.install_source(0xAA);
    register_recursive(h, inj, 0x42);

    const std::uint8_t seed[1] = {0x01};
    EXPECT_EQ(gn::sdk::inject_message(&h.api, inj.source, "gnet-v1",
                                       0x42, {seed, 1}),
              GN_OK);

    EXPECT_EQ(inj.call_count,         static_cast<int>(GN_INJECT_MAX_DEPTH));
    EXPECT_EQ(inj.limit_reached_count, 1);
}

/// Operator-configured depth overrides the compile-time default.
/// With max_inject_depth = 2 the handler fires twice; the third inject
/// is rejected.
TEST(InjectDepth, CustomDepth_LimitRespected) {
    DepthHarness h;

    gn_limits_t lim = h.kernel->limits();
    lim.max_inject_depth = 2;
    h.kernel->set_limits(lim);

    RecursiveInjector inj;
    inj.source = h.install_source(0xBB);
    register_recursive(h, inj, 0x43);

    const std::uint8_t seed[1] = {0x02};
    EXPECT_EQ(gn::sdk::inject_message(&h.api, inj.source, "gnet-v1",
                                       0x43, {seed, 1}),
              GN_OK);

    EXPECT_EQ(inj.call_count,          2);
    EXPECT_EQ(inj.limit_reached_count, 1);
}

/// After the recursive chain fully unwinds the thread_local depth
/// counter must return to zero.  A subsequent top-level inject must
/// succeed and trigger the handler once (not hit the limit immediately).
TEST(InjectDepth, DepthResetsAfterChainUnwinds) {
    DepthHarness h;
    RecursiveInjector inj;
    inj.source = h.install_source(0xCC);
    register_recursive(h, inj, 0x44);

    const std::uint8_t seed[1] = {0x03};

    // First chain — exhausts and resets depth.
    EXPECT_EQ(gn::sdk::inject_message(&h.api, inj.source, "gnet-v1",
                                       0x44, {seed, 1}),
              GN_OK);
    const int first_calls = inj.call_count;

    // Second top-level inject must succeed and add exactly max_depth
    // new calls, not zero (which would indicate the counter was stuck).
    EXPECT_EQ(gn::sdk::inject_message(&h.api, inj.source, "gnet-v1",
                                       0x44, {seed, 1}),
              GN_OK);
    EXPECT_EQ(inj.call_count, first_calls * 2);
    EXPECT_EQ(inj.limit_reached_count, 2);
}
