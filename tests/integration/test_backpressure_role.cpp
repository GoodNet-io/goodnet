/// @file   tests/integration/test_backpressure_role.cpp
/// @brief  Role gate on `host_api->notify_backpressure`.
///
/// Per `docs/contracts/host-api.md` §2 and `backpressure.md` §3, only
/// transport-kind plugins own write queues, so only they may publish
/// `BACKPRESSURE_SOFT` / `BACKPRESSURE_CLEAR`. Other plugin kinds are
/// rejected with `GN_ERR_NOT_IMPLEMENTED`. The `kind` field is
/// constrained to the two backpressure variants; any other event kind
/// is `GN_ERR_INVALID_ENVELOPE`.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/registry/connection.hpp>

#include <sdk/conn_events.h>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/trust.h>
#include <sdk/types.h>

using gn::core::ConnectionRecord;
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

PluginContext make_ctx(Kernel& k, gn_plugin_kind_t kind, const char* name) {
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = kind;
    ctx.plugin_name   = name;
    ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
    return ctx;
}

/// Insert a record directly through the registry so the test does not
/// have to thread `notify_connect` (which would also fire a
/// CONNECTED event into the bag and obscure the backpressure-only
/// assertions). The id is allocator-issued, matching the kernel path.
gn_conn_id_t insert_record(Kernel& k,
                            const std::array<std::uint8_t,
                                             GN_PUBLIC_KEY_BYTES>& pk,
                            const char* uri) {
    const gn_conn_id_t id = k.connections().alloc_id();
    ConnectionRecord rec;
    rec.id               = id;
    rec.uri              = uri;
    rec.transport_scheme = "tcp";
    rec.trust            = GN_TRUST_LOOPBACK;
    rec.role             = GN_ROLE_RESPONDER;
    rec.remote_pk        = pk;
    EXPECT_EQ(k.connections().insert_with_index(std::move(rec)), GN_OK);
    return id;
}

}  // namespace

TEST(BackpressureRole, RejectsHandlerKindPublisher) {
    Kernel k;
    auto ctx = make_ctx(k, GN_PLUGIN_KIND_HANDLER, "test-handler");
    auto api = build_host_api(ctx);

    const std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES> pk{0x11, 0x22, 0x33};
    const gn_conn_id_t conn = insert_record(k, pk, "tcp://127.0.0.1:9300");

    EXPECT_EQ(api.notify_backpressure(api.host_ctx, conn,
                                       GN_CONN_EVENT_BACKPRESSURE_SOFT,
                                       /*bytes=*/4096),
              GN_ERR_NOT_IMPLEMENTED);
}

TEST(BackpressureRole, AcceptsTransportKindPublisher) {
    Kernel k;
    auto ctx = make_ctx(k, GN_PLUGIN_KIND_LINK, "test-transport");
    auto api = build_host_api(ctx);

    EventBag bag;
    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe_conn_state(api.host_ctx,
                                        &record_event, &bag, &sub),
              GN_OK);

    const std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES> pk{0xAA, 0xBB, 0xCC};
    const gn_conn_id_t conn = insert_record(k, pk, "tcp://127.0.0.1:9301");

    /// Rising edge: SOFT with the queue depth that crossed the high
    /// watermark.
    EXPECT_EQ(api.notify_backpressure(api.host_ctx, conn,
                                       GN_CONN_EVENT_BACKPRESSURE_SOFT,
                                       /*bytes=*/8192),
              GN_OK);
    /// Falling edge: CLEAR back to zero pending.
    EXPECT_EQ(api.notify_backpressure(api.host_ctx, conn,
                                       GN_CONN_EVENT_BACKPRESSURE_CLEAR,
                                       /*bytes=*/0),
              GN_OK);

    std::lock_guard lk(bag.mu);
    ASSERT_EQ(bag.events.size(), 2u);

    const auto& soft = bag.events[0];
    EXPECT_EQ(soft.kind,          GN_CONN_EVENT_BACKPRESSURE_SOFT);
    EXPECT_EQ(soft.conn,          conn);
    EXPECT_EQ(soft.pending_bytes, 8192u);
    /// Trust and pk are snapshotted from the registry record.
    EXPECT_EQ(soft.trust,         GN_TRUST_LOOPBACK);
    EXPECT_EQ(soft.remote_pk[0],  0xAA);
    EXPECT_EQ(soft.remote_pk[1],  0xBB);
    EXPECT_EQ(soft.remote_pk[2],  0xCC);

    const auto& clear = bag.events[1];
    EXPECT_EQ(clear.kind,          GN_CONN_EVENT_BACKPRESSURE_CLEAR);
    EXPECT_EQ(clear.conn,          conn);
    EXPECT_EQ(clear.pending_bytes, 0u);
    EXPECT_EQ(clear.trust,         GN_TRUST_LOOPBACK);
}

TEST(BackpressureRole, RejectsInvalidEventKind) {
    Kernel k;
    auto ctx = make_ctx(k, GN_PLUGIN_KIND_LINK, "test-transport");
    auto api = build_host_api(ctx);

    const std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES> pk{0x42};
    const gn_conn_id_t conn = insert_record(k, pk, "tcp://127.0.0.1:9302");

    /// CONNECTED is a lifecycle event, not a backpressure transition;
    /// the thunk must reject it even from a transport caller.
    EXPECT_EQ(api.notify_backpressure(api.host_ctx, conn,
                                       GN_CONN_EVENT_CONNECTED,
                                       /*bytes=*/0),
              GN_ERR_INVALID_ENVELOPE);
}
