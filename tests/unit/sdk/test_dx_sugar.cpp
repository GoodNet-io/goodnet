// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/sdk/test_dx_sugar.cpp
/// @brief  Coverage for SDK DX sugar added 2026-05-12:
///           - `Subscription::on_connected/on_disconnected/...` typed slots
///           - `gn::parse_uri_strict(uri, scheme)`
///           - `gn::sdk::test::wait_for(...)` polling helper
///
/// The hand-rolled `wait_for` copies in plugin test files are now
/// expected to migrate to the SDK helper; this test pins the contract.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/cpp/config.hpp>
#include <sdk/cpp/subscription.hpp>
#include <sdk/cpp/test/poll.hpp>
#include <sdk/cpp/uri.hpp>
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
    ctx.plugin_name   = "test-dx-sugar";
    ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
    return ctx;
}

}  // namespace

// ─── Subscription event-typed slots ───────────────────────────────

TEST(SubscriptionEvents, OnConnectedFiresOnlyOnConnected) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    std::atomic<int> hits{0};
    std::atomic<gn_conn_id_t> last_conn{GN_INVALID_ID};
    auto sub = gn::sdk::Subscription::on_connected(
        &api,
        [&](gn_conn_id_t c, const gn_conn_event_t&) {
            hits.fetch_add(1, std::memory_order_relaxed);
            last_conn.store(c, std::memory_order_relaxed);
        });
    ASSERT_TRUE(sub.valid());

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xAA};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:1",
                                   GN_TRUST_LOOPBACK,
                                   GN_ROLE_RESPONDER, &conn), GN_OK);
    EXPECT_EQ(hits.load(), 1);
    EXPECT_EQ(last_conn.load(), conn);

    /// Disconnect must NOT trip the connected filter.
    ASSERT_EQ(api.notify_disconnect(&ctx, conn, GN_OK), GN_OK);
    EXPECT_EQ(hits.load(), 1);
}

TEST(SubscriptionEvents, OnDisconnectedFiresOnlyOnDisconnected) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    std::atomic<int> hits{0};
    std::atomic<gn_conn_id_t> last{GN_INVALID_ID};
    auto sub = gn::sdk::Subscription::on_disconnected(
        &api,
        [&](gn_conn_id_t c) {
            hits.fetch_add(1, std::memory_order_relaxed);
            last.store(c, std::memory_order_relaxed);
        });
    ASSERT_TRUE(sub.valid());

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xBB};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:2",
                                   GN_TRUST_LOOPBACK,
                                   GN_ROLE_RESPONDER, &conn), GN_OK);
    EXPECT_EQ(hits.load(), 0);

    ASSERT_EQ(api.notify_disconnect(&ctx, conn, GN_OK), GN_OK);
    EXPECT_EQ(hits.load(), 1);
    EXPECT_EQ(last.load(), conn);
}

TEST(SubscriptionEvents, NullFnYieldsNullHandle) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    auto a = gn::sdk::Subscription::on_connected(&api, nullptr);
    EXPECT_FALSE(a.valid());

    auto b = gn::sdk::Subscription::on_disconnected(&api, nullptr);
    EXPECT_FALSE(b.valid());

    auto c = gn::sdk::Subscription::on_trust_upgraded(&api, nullptr);
    EXPECT_FALSE(c.valid());

    auto d = gn::sdk::Subscription::on_backpressure(&api, nullptr);
    EXPECT_FALSE(d.valid());
}

TEST(SubscriptionEvents, NullApiYieldsNullHandle) {
    auto a = gn::sdk::Subscription::on_connected(
        nullptr, [](gn_conn_id_t, const gn_conn_event_t&) {});
    EXPECT_FALSE(a.valid());

    auto b = gn::sdk::Subscription::on_disconnected(
        nullptr, [](gn_conn_id_t) {});
    EXPECT_FALSE(b.valid());
}

// ─── parse_uri_strict ─────────────────────────────────────────────

TEST(ParseUriStrict, AcceptsMatchingScheme) {
    auto p = gn::parse_uri_strict("tcp://127.0.0.1:8080", "tcp");
    ASSERT_TRUE(p.has_value());
    if (!p) return;
    EXPECT_EQ(p->scheme, "tcp");
    EXPECT_EQ(p->host,   "127.0.0.1");
    EXPECT_EQ(p->port,   8080);
}

TEST(ParseUriStrict, RejectsMismatchedScheme) {
    auto p = gn::parse_uri_strict("udp://127.0.0.1:8080", "tcp");
    EXPECT_FALSE(p.has_value());
}

TEST(ParseUriStrict, RejectsMalformedUri) {
    EXPECT_FALSE(gn::parse_uri_strict("not-a-uri", "tcp").has_value());
    EXPECT_FALSE(gn::parse_uri_strict("",          "tcp").has_value());
    EXPECT_FALSE(gn::parse_uri_strict("tcp://",    "tcp").has_value());
}

// ─── gn::sdk::test::wait_for ──────────────────────────────────────

TEST(SdkTestPoll, ReturnsTrueWhenPredicateBecomesTrue) {
    std::atomic<int> counter{0};
    /// Flip the predicate from a side thread after ~25 ms.
    std::thread flipper([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds{25});
        counter.store(1, std::memory_order_release);
    });
    const bool ok = gn::sdk::test::wait_for(
        [&] { return counter.load(std::memory_order_acquire) == 1; },
        std::chrono::milliseconds{500});
    EXPECT_TRUE(ok);
    flipper.join();
}

TEST(SdkTestPoll, ReturnsFalseOnTimeout) {
    const bool ok = gn::sdk::test::wait_for(
        [] { return false; },
        std::chrono::milliseconds{20});
    EXPECT_FALSE(ok);
}

// ─── typed config helpers ─────────────────────────────────────────

TEST(SdkConfig, NullApiYieldsNullopt) {
    EXPECT_FALSE(gn::sdk::config_int(nullptr, "k").has_value());
    EXPECT_FALSE(gn::sdk::config_bool(nullptr, "k").has_value());
    EXPECT_FALSE(gn::sdk::config_double(nullptr, "k").has_value());
    EXPECT_FALSE(gn::sdk::config_string(nullptr, "k").has_value());
}

TEST(SdkConfig, EmptyKeyYieldsNullopt) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);
    EXPECT_FALSE(gn::sdk::config_int(&api, "").has_value());
    EXPECT_FALSE(gn::sdk::config_bool(&api, "").has_value());
}

TEST(SdkConfig, MissingKeyReturnsNullopt) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);
    /// Kernel default config has no key "test.does.not.exist", so a
    /// typed read must return nullopt without crash / corruption.
    EXPECT_FALSE(gn::sdk::config_int(&api,
                                       "test.does.not.exist").has_value());
    EXPECT_FALSE(gn::sdk::config_bool(&api,
                                        "test.does.not.exist").has_value());
    EXPECT_FALSE(gn::sdk::config_double(&api,
                                          "test.does.not.exist").has_value());
    EXPECT_FALSE(gn::sdk::config_string(&api,
                                          "test.does.not.exist").has_value());
}

TEST(SdkTestPoll, EvaluatesPredicateAfterTimeoutOneFinalTime) {
    /// Final evaluation happens AFTER the deadline so a predicate
    /// that flips exactly at the deadline still passes — avoids
    /// flake on slow CI machines.
    int evaluations = 0;
    const bool ok = gn::sdk::test::wait_for(
        [&] {
            ++evaluations;
            return evaluations >= 3;
        },
        std::chrono::milliseconds{10});
    /// The final evaluation makes this true even if the timed-out
    /// loop never saw `>=3`.
    EXPECT_TRUE(ok);
}
