/// @file   tests/unit/sdk/test_dsl_helpers.cpp
/// @brief  Coverage for the C++ SDK helper headers added by Slice 1:
///           - `sdk/cpp/subscription.hpp`  (RAII subscribe handle)
///           - `sdk/cpp/per_conn_map.hpp`  (auto-cleanup state map)
///           - `sdk/cpp/link_carrier.hpp`  (gn.link.<scheme> wrapper)
///           - `sdk/cpp/handler_plugin.hpp` (GN_HANDLER_PLUGIN macro)
///
/// The macro test is compile-only — the macro expands at file scope
/// and its emitted `gn_plugin_*` symbols would clash with other test
/// translation units. The instance lifetime exercised here drives the
/// real kernel through `build_host_api`.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <thread>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/conn_events.h>
#include <sdk/cpp/link_carrier.hpp>
#include <sdk/cpp/per_conn_map.hpp>
#include <sdk/cpp/subscription.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

using gn::core::Kernel;
using gn::core::PluginContext;
using gn::core::build_host_api;

namespace {

PluginContext make_ctx(Kernel& k) {
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_LINK;
    ctx.plugin_name   = "test-dsl";
    ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
    return ctx;
}

}  // namespace

// ─── Subscription RAII ────────────────────────────────────────────

TEST(SdkSubscription, OnConnStateRunsLambdaAndAutoUnsubscribes) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    std::atomic<int> hits{0};
    {
        auto sub = gn::sdk::Subscription::on_conn_state(
            &api,
            [&](const gn_conn_event_t&) { hits.fetch_add(1); });
        ASSERT_TRUE(sub.valid());

        std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {1, 2, 3};
        gn_conn_id_t conn = GN_INVALID_ID;
        ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:1",
                                      GN_TRUST_LOOPBACK,
                                      GN_ROLE_RESPONDER, &conn), GN_OK);
        EXPECT_EQ(hits.load(), 1);

        ASSERT_EQ(api.notify_disconnect(&ctx, conn, GN_OK), GN_OK);
        EXPECT_EQ(hits.load(), 2);
    }
    // sub destructor unsubscribed; another connect must not fire.
    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {9, 9, 9};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:2",
                                  GN_TRUST_LOOPBACK,
                                  GN_ROLE_RESPONDER, &conn), GN_OK);
    EXPECT_EQ(hits.load(), 2);  // unchanged
}

TEST(SdkSubscription, NullApiYieldsInvalidHandle) {
    auto sub = gn::sdk::Subscription::on_conn_state(
        nullptr, [](const gn_conn_event_t&) {});
    EXPECT_FALSE(sub.valid());
    EXPECT_EQ(sub.id(), GN_INVALID_SUBSCRIPTION_ID);
}

TEST(SdkSubscription, MoveTransfersOwnership) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    std::atomic<int> hits{0};
    auto a = gn::sdk::Subscription::on_conn_state(
        &api, [&](const gn_conn_event_t&) { hits.fetch_add(1); });
    ASSERT_TRUE(a.valid());

    auto b = std::move(a);
    EXPECT_FALSE(a.valid());  // NOLINT(bugprone-use-after-move) — testing moved-from state
    EXPECT_TRUE(b.valid());

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0x55};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:3",
                                  GN_TRUST_LOOPBACK,
                                  GN_ROLE_RESPONDER, &conn), GN_OK);
    EXPECT_EQ(hits.load(), 1);  // moved-to handle still fires
}

// ─── PerConnMap auto-cleanup ──────────────────────────────────────

namespace {
struct PeerState {
    int counter = 0;
    explicit PeerState(int seed = 0) : counter(seed) {}
};
}

TEST(SdkPerConnMap, AutoErasesOnDisconnected) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    gn::sdk::PerConnMap<PeerState> peers(&api);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xAA};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:4",
                                  GN_TRUST_LOOPBACK,
                                  GN_ROLE_RESPONDER, &conn), GN_OK);

    auto state = peers.ensure(conn, 42);
    ASSERT_NE(state, nullptr);
    EXPECT_EQ(state->counter, 42);
    EXPECT_EQ(peers.size(), 1u);

    ASSERT_EQ(api.notify_disconnect(&ctx, conn, GN_OK), GN_OK);
    EXPECT_EQ(peers.size(), 0u);
    EXPECT_EQ(peers.find(conn), nullptr);
}

TEST(SdkPerConnMap, CustomDisconnectHookRunsAfterErase) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    std::atomic<gn_conn_id_t> seen{GN_INVALID_ID};
    std::atomic<std::size_t>  size_at_hook{999};
    gn::sdk::PerConnMap<PeerState> peers(
        &api,
        [&](gn_conn_id_t c) {
            seen.store(c);
            size_at_hook.store(peers.size());
        });

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xBB};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:5",
                                  GN_TRUST_LOOPBACK,
                                  GN_ROLE_RESPONDER, &conn), GN_OK);
    (void)peers.ensure(conn);
    ASSERT_EQ(api.notify_disconnect(&ctx, conn, GN_OK), GN_OK);

    EXPECT_EQ(seen.load(), conn);
    EXPECT_EQ(size_at_hook.load(), 0u);  // erase ran before hook
}

TEST(SdkPerConnMap, EnsureIsIdempotent) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    gn::sdk::PerConnMap<PeerState> peers(&api);

    const gn_conn_id_t conn = 12345;
    auto a = peers.ensure(conn, 7);
    auto b = peers.ensure(conn, 99);
    EXPECT_EQ(a.get(), b.get());        // same shared_ptr
    EXPECT_EQ(a->counter, 7);            // second call did NOT overwrite
}

// ─── LinkCarrier query paths ──────────────────────────────────────

TEST(SdkLinkCarrier, QueryMissingExtensionReturnsNullopt) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);
    auto c = gn::sdk::LinkCarrier::query(&api, "tcp");
    EXPECT_FALSE(c.has_value());
}

TEST(SdkLinkCarrier, QueryNullApiReturnsNullopt) {
    auto c = gn::sdk::LinkCarrier::query(nullptr, "tcp");
    EXPECT_FALSE(c.has_value());
}

TEST(SdkLinkCarrier, QueryEmptySchemeReturnsNullopt) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);
    auto c = gn::sdk::LinkCarrier::query(&api, "");
    EXPECT_FALSE(c.has_value());
}

namespace {

// Minimal fake link extension with just enough slots wired for the
// carrier to exercise its full RAII path. The fake counts subscribe /
// unsubscribe calls so the test can prove the carrier drives them.
struct FakeLinkProducer {
    std::atomic<int> data_subs{0};
    std::atomic<int> data_unsubs{0};
    std::atomic<int> accept_subs{0};
    std::atomic<int> accept_unsubs{0};
    std::atomic<gn_subscription_id_t> next_accept_token{1};
};

gn_result_t fake_stats(void*, gn_link_stats_t*) { return GN_OK; }
gn_result_t fake_caps(void*, gn_link_caps_t*)   { return GN_OK; }
gn_result_t fake_send(void*, gn_conn_id_t, const std::uint8_t*, std::size_t) {
    return GN_OK;
}
gn_result_t fake_send_batch(void*, gn_conn_id_t,
                             const gn_byte_span_t*, std::size_t) {
    return GN_OK;
}
gn_result_t fake_close(void*, gn_conn_id_t, int) { return GN_OK; }
gn_result_t fake_listen(void*, const char*)      { return GN_OK; }
gn_result_t fake_connect(void*, const char*, gn_conn_id_t* out) {
    if (out) *out = 0x42;
    return GN_OK;
}
gn_result_t fake_subscribe_data(void* ctx, gn_conn_id_t,
                                 gn_link_data_cb_t, void*) {
    static_cast<FakeLinkProducer*>(ctx)->data_subs.fetch_add(1);
    return GN_OK;
}
gn_result_t fake_unsubscribe_data(void* ctx, gn_conn_id_t) {
    static_cast<FakeLinkProducer*>(ctx)->data_unsubs.fetch_add(1);
    return GN_OK;
}
gn_result_t fake_subscribe_accept(void* ctx, gn_link_accept_cb_t,
                                   void*, gn_subscription_id_t* out) {
    auto* p = static_cast<FakeLinkProducer*>(ctx);
    p->accept_subs.fetch_add(1);
    if (out) *out = p->next_accept_token.fetch_add(1);
    return GN_OK;
}
gn_result_t fake_unsubscribe_accept(void* ctx, gn_subscription_id_t) {
    static_cast<FakeLinkProducer*>(ctx)->accept_unsubs.fetch_add(1);
    return GN_OK;
}

}  // namespace

TEST(SdkLinkCarrier, FullLifecycleRoundtripWithFakeExtension) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    FakeLinkProducer fake;
    gn_link_api_t vt{};
    vt.api_size           = sizeof(vt);
    vt.get_stats          = &fake_stats;
    vt.get_capabilities   = &fake_caps;
    vt.send               = &fake_send;
    vt.send_batch         = &fake_send_batch;
    vt.close              = &fake_close;
    vt.listen             = &fake_listen;
    vt.connect            = &fake_connect;
    vt.subscribe_data     = &fake_subscribe_data;
    vt.unsubscribe_data   = &fake_unsubscribe_data;
    vt.subscribe_accept   = &fake_subscribe_accept;
    vt.unsubscribe_accept = &fake_unsubscribe_accept;
    vt.ctx                = &fake;

    ASSERT_EQ(api.register_extension(&ctx, "gn.link.fakelink",
                                      GN_EXT_LINK_VERSION, &vt), GN_OK);

    {
        auto carrier_opt = gn::sdk::LinkCarrier::query(&api, "fakelink");
        ASSERT_TRUE(carrier_opt.has_value());
        if (!carrier_opt) return;
        auto& carrier = *carrier_opt;
        EXPECT_TRUE(carrier.valid());

        gn_conn_id_t out = GN_INVALID_ID;
        EXPECT_EQ(carrier.connect("fakelink://h:1", &out), GN_OK);
        EXPECT_EQ(out, 0x42u);

        EXPECT_EQ(carrier.on_data(0x42, [](gn_conn_id_t,
                                              std::span<const std::uint8_t>) {}),
                  GN_OK);
        EXPECT_EQ(fake.data_subs.load(), 1);

        EXPECT_EQ(carrier.on_accept([](gn_conn_id_t, std::string_view) {}),
                  GN_OK);
        EXPECT_EQ(fake.accept_subs.load(), 1);

        // Replacing the data cb unsubscribes the prior one first.
        EXPECT_EQ(carrier.on_data(0x42, [](gn_conn_id_t,
                                              std::span<const std::uint8_t>) {}),
                  GN_OK);
        EXPECT_EQ(fake.data_subs.load(), 2);
        EXPECT_EQ(fake.data_unsubs.load(), 1);
    }
    // Carrier dtor must have torn down the accept sub and the data sub.
    EXPECT_EQ(fake.accept_unsubs.load(), 1);
    EXPECT_EQ(fake.data_unsubs.load(), 2);

    (void)api.unregister_extension(&ctx, "gn.link.fakelink");
}
