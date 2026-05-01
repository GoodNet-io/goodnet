/// @file   tests/integration/test_conn_events.cpp
/// @brief  subscribe_conn_state + for_each_connection through the
///         real host_api thunks: the kernel fires CONNECTED on
///         notify_connect, DISCONNECTED on notify_disconnect, and
///         iteration walks every live record under the per-shard
///         read locks.

#include <gtest/gtest.h>

#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <vector>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/conn_events.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

using gn::core::Kernel;
using gn::core::PluginContext;
using gn::core::build_host_api;

namespace {

struct EventBag {
    std::mutex                              mu;
    std::vector<gn_conn_event_t>            events;
};

void record_event(void* ud, const gn_conn_event_t* ev) {
    auto* bag = static_cast<EventBag*>(ud);
    std::lock_guard lk(bag->mu);
    bag->events.push_back(*ev);
}

PluginContext make_transport_ctx(Kernel& k) {
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_LINK;
    ctx.plugin_name   = "test-link";
    ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
    return ctx;
}

}  // namespace

TEST(ConnEvents, ConnectFiresEvent) {
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    EventBag bag;
    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe_conn_state(&ctx, &record_event, &bag, &sub),
              GN_OK);
    EXPECT_NE(sub, GN_INVALID_SUBSCRIPTION_ID);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xAA, 0xBB, 0xCC};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:9000",
                                  "tcp", GN_TRUST_LOOPBACK,
                                  GN_ROLE_RESPONDER, &conn), GN_OK);

    {
        std::lock_guard lk(bag.mu);
        ASSERT_EQ(bag.events.size(), 1u);
        EXPECT_EQ(bag.events[0].kind, GN_CONN_EVENT_CONNECTED);
        EXPECT_EQ(bag.events[0].conn, conn);
        EXPECT_EQ(bag.events[0].trust, GN_TRUST_LOOPBACK);
        EXPECT_EQ(bag.events[0].remote_pk[0], 0xAA);
        EXPECT_EQ(bag.events[0].remote_pk[1], 0xBB);
        EXPECT_EQ(bag.events[0].remote_pk[2], 0xCC);
    }
}

TEST(ConnEvents, DisconnectFiresEventAndUnsubscribeStops) {
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    EventBag bag;
    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe_conn_state(&ctx, &record_event, &bag, &sub),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {1, 2, 3};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:9001",
                                  "tcp", GN_TRUST_LOOPBACK,
                                  GN_ROLE_RESPONDER, &conn), GN_OK);
    ASSERT_EQ(api.notify_disconnect(&ctx, conn, GN_OK), GN_OK);

    {
        std::lock_guard lk(bag.mu);
        ASSERT_EQ(bag.events.size(), 2u);
        EXPECT_EQ(bag.events[0].kind, GN_CONN_EVENT_CONNECTED);
        EXPECT_EQ(bag.events[1].kind, GN_CONN_EVENT_DISCONNECTED);
        EXPECT_EQ(bag.events[1].conn, conn);
    }

    /// After unsubscribe, no further events land in the bag.
    ASSERT_EQ(api.unsubscribe_conn_state(&ctx, sub), GN_OK);
    gn_conn_id_t conn2 = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:9002",
                                  "tcp", GN_TRUST_LOOPBACK,
                                  GN_ROLE_RESPONDER, &conn2), GN_OK);
    {
        std::lock_guard lk(bag.mu);
        EXPECT_EQ(bag.events.size(), 2u)
            << "unsubscribed channel must not fire";
    }
}

TEST(ConnEvents, UnsubscribeIdempotent) {
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    EventBag bag;
    ASSERT_EQ(api.subscribe_conn_state(&ctx, &record_event, &bag, &sub),
              GN_OK);

    EXPECT_EQ(api.unsubscribe_conn_state(&ctx, sub), GN_OK);
    EXPECT_EQ(api.unsubscribe_conn_state(&ctx, sub), GN_OK)
        << "second unsubscribe of same id must report success";
    EXPECT_EQ(api.unsubscribe_conn_state(&ctx, GN_INVALID_SUBSCRIPTION_ID),
              GN_ERR_NULL_ARG);
}

TEST(ConnEvents, AnchorExpiredDropsCallback) {
    Kernel k;
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_LINK;
    ctx.plugin_name   = "expiring";
    ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
    auto api = build_host_api(ctx);

    EventBag bag;
    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe_conn_state(&ctx, &record_event, &bag, &sub),
              GN_OK);

    /// Drop the anchor; subscription is still alive on the channel,
    /// but the dispatcher must observe the expiry and skip the cb.
    ctx.plugin_anchor.reset();

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:9003",
                                  "tcp", GN_TRUST_LOOPBACK,
                                  GN_ROLE_RESPONDER, &conn), GN_OK);

    std::lock_guard lk(bag.mu);
    EXPECT_TRUE(bag.events.empty())
        << "anchor expired before fire; callback must be dropped";
}

namespace {

struct VisitCounter {
    std::atomic<int> count{0};
};

int count_visitor(void* ud, gn_conn_id_t /*conn*/, gn_trust_class_t,
                   const std::uint8_t* /*pk*/, const char* /*uri*/) {
    static_cast<VisitCounter*>(ud)->count.fetch_add(1);
    return 0;
}

}  // namespace

TEST(ConnEvents, ForEachConnectionWalksRegistry) {
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    /// Three connections under different URIs / pks so the registry
    /// records are distinct.
    for (int i = 1; i <= 3; ++i) {
        std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0};
        pk[0] = static_cast<std::uint8_t>(i);
        gn_conn_id_t conn = GN_INVALID_ID;
        const std::string uri =
            "tcp://127.0.0.1:" + std::to_string(9100 + i);
        ASSERT_EQ(api.notify_connect(&ctx, pk, uri.c_str(),
                                      "tcp", GN_TRUST_LOOPBACK,
                                      GN_ROLE_RESPONDER, &conn), GN_OK);
    }

    VisitCounter vc;
    EXPECT_EQ(api.for_each_connection(&ctx, &count_visitor, &vc),
              GN_OK);
    EXPECT_EQ(vc.count.load(), 3);
}

TEST(ConnEvents, ForEachVisitorStopOnNonZero) {
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    for (int i = 1; i <= 5; ++i) {
        std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0};
        pk[0] = static_cast<std::uint8_t>(i);
        gn_conn_id_t conn = GN_INVALID_ID;
        const std::string uri =
            "tcp://127.0.0.1:" + std::to_string(9200 + i);
        ASSERT_EQ(api.notify_connect(&ctx, pk, uri.c_str(),
                                      "tcp", GN_TRUST_LOOPBACK,
                                      GN_ROLE_RESPONDER, &conn), GN_OK);
    }

    auto stop_at_two = +[](void* ud, gn_conn_id_t, gn_trust_class_t,
                            const std::uint8_t*, const char*) -> int {
        auto* counter = static_cast<std::atomic<int>*>(ud);
        return counter->fetch_add(1) >= 1 ? 1 : 0;
    };
    std::atomic<int> seen{0};
    EXPECT_EQ(api.for_each_connection(&ctx, stop_at_two, &seen), GN_OK);
    EXPECT_EQ(seen.load(), 2)
        << "visitor should have seen exactly two records before stop";
}

TEST(ConnEvents, RejectsNullArgs) {
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    EventBag bag;
    EXPECT_EQ(api.subscribe_conn_state(&ctx, nullptr, &bag, &sub),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(api.subscribe_conn_state(&ctx, &record_event, &bag, nullptr),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(api.for_each_connection(&ctx, nullptr, nullptr),
              GN_ERR_NULL_ARG);
}
