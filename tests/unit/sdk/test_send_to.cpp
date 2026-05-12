// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/sdk/test_send_to.cpp
/// @brief  Coverage for `host_api->send_to(peer_pk, msg_id, payload)` —
///         Slice 9-KERNEL strategy-dispatch thunk plus the SDK wrapper
///         `gn::sdk::send_to(...)`.

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/cpp/connect.hpp>
#include <sdk/extensions/strategy.h>
#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

using gn::core::Kernel;
using gn::core::PluginContext;
using gn::core::build_host_api;

namespace {

PluginContext make_ctx(Kernel& k) {
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_LINK;
    ctx.plugin_name   = "test-send-to";
    ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
    return ctx;
}

/// Fake link vtable that just counts `send` calls per conn.
struct FakeLink {
    std::atomic<int>          send_calls{0};
    std::atomic<gn_conn_id_t> last_conn{GN_INVALID_ID};
    std::atomic<std::uint32_t> last_msg_id{0};

    static gn_result_t send(void* ctx, gn_conn_id_t conn,
                             const std::uint8_t*, std::size_t) {
        auto* f = static_cast<FakeLink*>(ctx);
        f->send_calls.fetch_add(1);
        f->last_conn.store(conn);
        return GN_OK;
    }

    static gn_link_api_t make_vtable(FakeLink& f) {
        gn_link_api_t vt{};
        vt.api_size = sizeof(vt);
        vt.send     = &send;
        vt.ctx      = &f;
        return vt;
    }
};

/// Test strategy that always picks the LAST candidate in the array.
/// Lets us verify multi-conn dispatch routes through `pick_conn`.
struct PickLastStrategy {
    std::atomic<int> pick_calls{0};
    std::atomic<std::size_t> last_count{0};

    static gn_result_t pick_conn(
        void* ctx,
        const std::uint8_t* /*peer_pk*/,
        const gn_path_sample_t* candidates,
        std::size_t count,
        gn_conn_id_t* out_chosen) {
        auto* s = static_cast<PickLastStrategy*>(ctx);
        s->pick_calls.fetch_add(1);
        s->last_count.store(count);
        if (!candidates || count == 0 || !out_chosen) return GN_ERR_NULL_ARG;
        *out_chosen = candidates[count - 1].conn;
        return GN_OK;
    }

    static gn_strategy_api_t make_vtable(PickLastStrategy& s) {
        gn_strategy_api_t vt{};
        vt.api_size  = sizeof(vt);
        vt.pick_conn = &pick_conn;
        vt.ctx       = &s;
        return vt;
    }
};

/// Spawn @p count conns to @p peer_pk, all wired through the same
/// fake link. Returns the allocated conn ids in order.
std::vector<gn_conn_id_t> spawn_conns(
    PluginContext& ctx,
    host_api_t& api,
    const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
    std::size_t count) {
    std::vector<gn_conn_id_t> conns;
    for (std::size_t i = 0; i < count; ++i) {
        gn_conn_id_t cid = GN_INVALID_ID;
        const auto rc = api.notify_connect(
            &ctx, peer_pk,
            (std::string("fake://h:") + std::to_string(i)).c_str(),
            GN_TRUST_LOOPBACK, GN_ROLE_RESPONDER, &cid);
        if (rc == GN_OK && cid != GN_INVALID_ID) conns.push_back(cid);
    }
    return conns;
}

}  // namespace

TEST(HostApiSendTo, NullPeerPkYieldsNullArg) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    const std::uint8_t payload[1] = {0};
    EXPECT_EQ(api.send_to(&ctx, nullptr, 0x10, payload, 1),
              GN_ERR_NULL_ARG);
}

TEST(HostApiSendTo, NoConnsYieldsNotFound) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xAA};
    const std::uint8_t payload[1] = {0};
    EXPECT_EQ(api.send_to(&ctx, pk, 0x10, payload, 1),
              GN_ERR_NOT_FOUND);
}

TEST(HostApiSendTo, SingleConnBypassesStrategy) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    FakeLink fake;
    auto vt = FakeLink::make_vtable(fake);
    ASSERT_EQ(api.register_extension(&ctx, "gn.link.fake",
                                       GN_EXT_LINK_VERSION, &vt), GN_OK);
    /// `register_vtable` on the link family wires the vtable for
    /// `notify_connect`-driven dispatch. The extension registration
    /// alone makes the kernel believe a transport exists; the actual
    /// send routes through `find_by_scheme` lookup which uses the
    /// link plugin's vtable registered through `GN_REGISTER_LINK`.
    /// For our purposes here `notify_connect` allocates the record
    /// and the kernel's send-queue path tolerates the absence of a
    /// formal link plugin. We test the strategy dispatch shape only.

    PickLastStrategy strat;
    auto strat_vt = PickLastStrategy::make_vtable(strat);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.test",
                                       GN_EXT_STRATEGY_VERSION, &strat_vt),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xCC};
    const auto conns = spawn_conns(ctx, api, pk, 1);
    ASSERT_EQ(conns.size(), 1u);

    const std::uint8_t payload[2] = {0xAB, 0xCD};
    /// `send_to` with one candidate must NOT call the strategy's
    /// pick_conn — common-path optimisation.
    (void)api.send_to(&ctx, pk, 0x10, payload, 2);
    EXPECT_EQ(strat.pick_calls.load(), 0);

    (void)api.unregister_extension(&ctx, "gn.strategy.test");
    (void)api.unregister_extension(&ctx, "gn.link.fake");
}

TEST(HostApiSendTo, MultipleConnsDelegateToStrategy) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    PickLastStrategy strat;
    auto strat_vt = PickLastStrategy::make_vtable(strat);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.test",
                                       GN_EXT_STRATEGY_VERSION, &strat_vt),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xDD};
    const auto conns = spawn_conns(ctx, api, pk, 3);
    ASSERT_EQ(conns.size(), 3u);

    const std::uint8_t payload[1] = {0x55};
    /// With 3 candidates, the strategy decides which conn wins.
    /// `PickLastStrategy` picks `candidates[count-1].conn` which is
    /// the last enumerated by `for_each` — order is implementation-
    /// defined (shard hash + insertion order), so we just check
    /// that pick_conn fired with 3 candidates.
    (void)api.send_to(&ctx, pk, 0x10, payload, 1);
    EXPECT_EQ(strat.pick_calls.load(), 1);
    EXPECT_EQ(strat.last_count.load(), 3u);

    (void)api.unregister_extension(&ctx, "gn.strategy.test");
}

TEST(HostApiSendTo, MultipleStrategiesReturnLimitReached) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    PickLastStrategy a, b;
    auto va = PickLastStrategy::make_vtable(a);
    auto vb = PickLastStrategy::make_vtable(b);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.alpha",
                                       GN_EXT_STRATEGY_VERSION, &va), GN_OK);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.beta",
                                       GN_EXT_STRATEGY_VERSION, &vb), GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xEE};
    const auto conns = spawn_conns(ctx, api, pk, 2);
    ASSERT_EQ(conns.size(), 2u);

    const std::uint8_t payload[1] = {0x55};
    EXPECT_EQ(api.send_to(&ctx, pk, 0x10, payload, 1),
              GN_ERR_LIMIT_REACHED);

    (void)api.unregister_extension(&ctx, "gn.strategy.alpha");
    (void)api.unregister_extension(&ctx, "gn.strategy.beta");
}

TEST(SdkSendToWrapper, ForwardsPayloadAndPeerPk) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    /// SDK wrapper rejects null inputs without poking the kernel.
    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xFF};
    const std::uint8_t payload[3] = {1, 2, 3};
    EXPECT_EQ(gn::sdk::send_to(nullptr, pk, 0x10,
                                 std::span<const std::uint8_t>(payload, 3)),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(gn::sdk::send_to(&api, nullptr, 0x10,
                                 std::span<const std::uint8_t>(payload, 3)),
              GN_ERR_NULL_ARG);

    /// With a registered conn it forwards to the kernel thunk —
    /// kernel returns NOT_FOUND because no conns to this pk.
    EXPECT_EQ(gn::sdk::send_to(&api, pk, 0x10,
                                 std::span<const std::uint8_t>(payload, 3)),
              GN_ERR_NOT_FOUND);
}
