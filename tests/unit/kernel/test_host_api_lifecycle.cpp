/// @file   tests/unit/kernel/test_host_api_lifecycle.cpp
/// @brief  Unit tests for the connection-lifecycle host_api thunks.
///
/// Exercises two contracts on `host_api->notify_connect` /
/// `notify_disconnect` per `docs/contracts/host-api.md` and
/// `security-trust.md` §4:
///
///   * `notify_connect` consults `IProtocolLayer::allowed_trust_mask()`
///     and refuses connections whose declared trust class is not in
///     the mask (`GN_ERR_INVALID_ENVELOPE`). Refused calls leak
///     neither a registry record nor a `CONNECTED` event.
///
///   * `notify_disconnect` snapshots and erases the connection
///     record atomically, so the published `DISCONNECTED` event
///     payload carries the snapshotted trust class and remote_pk
///     per `conn-events.md` §2a.

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/conn_events.h>
#include <sdk/cpp/protocol_layer.hpp>
#include <sdk/cpp/types.hpp>
#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

using gn::core::Kernel;
using gn::core::PluginContext;
using gn::core::build_host_api;

namespace {

/// Minimal subscriber sink for `gn_conn_event_t` deliveries.
struct EventBag {
    std::mutex                   mu;
    std::vector<gn_conn_event_t> events;
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

PluginContext make_handler_ctx(Kernel& k) {
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_HANDLER;
    ctx.plugin_name   = "test-handler";
    ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
    return ctx;
}

/// Stub protocol layer that admits only Loopback and IntraNode trust
/// classes. `deframe` / `frame` return `GN_ERR_NOT_IMPLEMENTED`; the
/// trust gate in `thunk_notify_connect` rejects unsupported trust
/// classes before any wire bytes flow.
class LoopbackOnlyProtocol final : public ::gn::IProtocolLayer {
public:
    [[nodiscard]] std::string_view protocol_id() const noexcept override {
        return "test-loopback-only";
    }

    [[nodiscard]] ::gn::Result<::gn::DeframeResult> deframe(
        ::gn::ConnectionContext& /*ctx*/,
        std::span<const std::uint8_t> /*bytes*/) override {
        return std::unexpected(::gn::Error{
            GN_ERR_NOT_IMPLEMENTED, "LoopbackOnlyProtocol::deframe"});
    }

    [[nodiscard]] ::gn::Result<std::vector<std::uint8_t>> frame(
        ::gn::ConnectionContext& /*ctx*/,
        const gn_message_t& /*msg*/) override {
        return std::unexpected(::gn::Error{
            GN_ERR_NOT_IMPLEMENTED, "LoopbackOnlyProtocol::frame"});
    }

    [[nodiscard]] std::size_t max_payload_size() const noexcept override {
        return 0;
    }

    [[nodiscard]] std::uint32_t allowed_trust_mask() const noexcept override {
        return (1u << GN_TRUST_LOOPBACK) | (1u << GN_TRUST_INTRA_NODE);
    }
};

}  // namespace

// ─── notify_connect: protocol-layer trust gate ───────────────────────

TEST(HostApiNotifyConnect, RejectsConnectionOutsideProtocolMask) {
    Kernel k;
    k.set_protocol_layer(std::make_shared<LoopbackOnlyProtocol>());
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    EventBag bag;
    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe_conn_state(&ctx, &record_event, &bag, &sub),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0x11, 0x22, 0x33};
    gn_conn_id_t conn = GN_INVALID_ID;
    EXPECT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:9500",
                                  "tcp", GN_TRUST_UNTRUSTED,
                                  GN_ROLE_RESPONDER, &conn),
              GN_ERR_INVALID_ENVELOPE);

    EXPECT_EQ(conn, GN_INVALID_ID);
    EXPECT_EQ(k.connections().size(), 0u);

    std::lock_guard lk(bag.mu);
    EXPECT_TRUE(bag.events.empty())
        << "rejected connect must not publish CONNECTED";
}

TEST(HostApiNotifyConnect, AcceptsConnectionInsideProtocolMask) {
    Kernel k;
    k.set_protocol_layer(std::make_shared<LoopbackOnlyProtocol>());
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    EventBag bag;
    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe_conn_state(&ctx, &record_event, &bag, &sub),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xAA, 0xBB, 0xCC};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:9501",
                                  "tcp", GN_TRUST_LOOPBACK,
                                  GN_ROLE_RESPONDER, &conn),
              GN_OK);

    EXPECT_NE(conn, GN_INVALID_ID);
    EXPECT_EQ(k.connections().size(), 1u);
    auto fetched = k.connections().find_by_id(conn);
    ASSERT_TRUE(fetched.has_value());
    if (fetched.has_value()) {
        const auto& got = *fetched;
        EXPECT_EQ(got.trust, GN_TRUST_LOOPBACK);
        EXPECT_EQ(got.remote_pk[0], 0xAA);
    }

    std::lock_guard lk(bag.mu);
    ASSERT_EQ(bag.events.size(), 1u);
    EXPECT_EQ(bag.events[0].kind, GN_CONN_EVENT_CONNECTED);
    EXPECT_EQ(bag.events[0].conn, conn);
    EXPECT_EQ(bag.events[0].trust, GN_TRUST_LOOPBACK);
}

// ─── notify_disconnect: snapshot-before-erase ────────────────────────

TEST(HostApiNotifyDisconnect, SnapshotsTrustAndPkBeforeErase) {
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    EventBag bag;
    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe_conn_state(&ctx, &record_event, &bag, &sub),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xDE, 0xAD, 0xBE, 0xEF};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:9600",
                                  "tcp", GN_TRUST_LOOPBACK,
                                  GN_ROLE_RESPONDER, &conn),
              GN_OK);

    ASSERT_EQ(api.notify_disconnect(&ctx, conn, GN_OK), GN_OK);

    EXPECT_FALSE(k.connections().find_by_id(conn).has_value());

    std::lock_guard lk(bag.mu);
    ASSERT_EQ(bag.events.size(), 2u);
    EXPECT_EQ(bag.events[0].kind, GN_CONN_EVENT_CONNECTED);
    EXPECT_EQ(bag.events[1].kind, GN_CONN_EVENT_DISCONNECTED);
    EXPECT_EQ(bag.events[1].conn, conn);
    EXPECT_EQ(bag.events[1].trust, GN_TRUST_LOOPBACK)
        << "DISCONNECTED must carry the snapshotted trust class";
    EXPECT_EQ(bag.events[1].remote_pk[0], 0xDE);
    EXPECT_EQ(bag.events[1].remote_pk[1], 0xAD);
    EXPECT_EQ(bag.events[1].remote_pk[2], 0xBE);
    EXPECT_EQ(bag.events[1].remote_pk[3], 0xEF);
}

TEST(HostApiNotifyDisconnect, MissingConnReturnsNotFound) {
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    EventBag bag;
    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe_conn_state(&ctx, &record_event, &bag, &sub),
              GN_OK);

    /// Disconnect of a never-inserted id reports
    /// `GN_ERR_NOT_FOUND` and fires no event — per
    /// `conn-events.md` §2 each event must correspond to a real
    /// lifecycle transition; an id that was never registered has
    /// none.
    constexpr gn_conn_id_t kUnknownConn = 99999;
    EXPECT_EQ(api.notify_disconnect(&ctx, kUnknownConn, GN_OK),
              GN_ERR_NOT_FOUND);

    std::lock_guard lk(bag.mu);
    EXPECT_TRUE(bag.events.empty())
        << "unknown id ⇒ no DISCONNECTED event; channel publishes one "
           "event per real transition";
}

TEST(HostApiNotifyDisconnect, IdempotentSecondCallFiresOnceAndReportsUnknown) {
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    EventBag bag;
    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe_conn_state(&ctx, &record_event, &bag, &sub),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xAA, 0xBB};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:9100",
                                  "tcp", GN_TRUST_LOOPBACK,
                                  GN_ROLE_RESPONDER, &conn), GN_OK);

    /// First disconnect: removes the record, fires DISCONNECTED.
    EXPECT_EQ(api.notify_disconnect(&ctx, conn, GN_OK), GN_OK);

    /// Second disconnect on the same id: record is gone, registry
    /// reports `GN_ERR_NOT_FOUND`, channel stays silent.
    EXPECT_EQ(api.notify_disconnect(&ctx, conn, GN_OK),
              GN_ERR_NOT_FOUND);

    std::lock_guard lk(bag.mu);
    ASSERT_EQ(bag.events.size(), 2u)
        << "exactly one CONNECTED + one DISCONNECTED";
    EXPECT_EQ(bag.events[0].kind, GN_CONN_EVENT_CONNECTED);
    EXPECT_EQ(bag.events[1].kind, GN_CONN_EVENT_DISCONNECTED);
}

/// Two threads race the same `notify_disconnect(conn)` through the C
/// ABI. Per `conn-events.md` §2a the channel publishes exactly one
/// DISCONNECTED for the single underlying lifecycle transition; the
/// losing thread reports `GN_ERR_NOT_FOUND`.
TEST(HostApiNotifyDisconnect, ConcurrentSameConnFiresOnceAndOneLoses) {
    constexpr int kRounds = 64;
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    EventBag bag;
    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe_conn_state(&ctx, &record_event, &bag, &sub),
              GN_OK);

    for (int round = 0; round < kRounds; ++round) {
        std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {};
        pk[0] = static_cast<std::uint8_t>(round);
        gn_conn_id_t conn = GN_INVALID_ID;
        const std::string uri = "tcp://127.0.0.1:" + std::to_string(20000 + round);
        ASSERT_EQ(api.notify_connect(&ctx, pk, uri.c_str(), "tcp",
                                      GN_TRUST_LOOPBACK,
                                      GN_ROLE_RESPONDER, &conn), GN_OK);

        std::atomic<int>  ready{0};
        std::atomic<bool> go{false};
        std::atomic<int>  ok_count{0};
        std::atomic<int>  unknown_count{0};

        auto worker = [&] {
            ready.fetch_add(1, std::memory_order_release);
            while (!go.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            const auto rc = api.notify_disconnect(&ctx, conn, GN_OK);
            if (rc == GN_OK) {
                ok_count.fetch_add(1, std::memory_order_relaxed);
            } else if (rc == GN_ERR_NOT_FOUND) {
                unknown_count.fetch_add(1, std::memory_order_relaxed);
            } else {
                ADD_FAILURE() << "unexpected rc " << rc;
            }
        };

        std::thread t1(worker);
        std::thread t2(worker);
        while (ready.load(std::memory_order_acquire) < 2) {
            std::this_thread::yield();
        }
        go.store(true, std::memory_order_release);
        t1.join();
        t2.join();

        ASSERT_EQ(ok_count.load(),      1) << "round " << round;
        ASSERT_EQ(unknown_count.load(), 1) << "round " << round;
    }

    std::lock_guard lk(bag.mu);
    int connected = 0, disconnected = 0;
    for (const auto& ev : bag.events) {
        if (ev.kind == GN_CONN_EVENT_CONNECTED)    ++connected;
        if (ev.kind == GN_CONN_EVENT_DISCONNECTED) ++disconnected;
    }
    EXPECT_EQ(connected,    kRounds)
        << "one CONNECTED per insert";
    EXPECT_EQ(disconnected, kRounds)
        << "one DISCONNECTED per real removal, regardless of contention";
}

/// `conn-events.md` §2a Returns row: `conn == GN_INVALID_ID`
/// collapses to `GN_ERR_NOT_FOUND` (no record matches the
/// sentinel id).
TEST(HostApiNotifyDisconnect, InvalidConnIdReturnsNotFound) {
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);
    EXPECT_EQ(api.notify_disconnect(&ctx, GN_INVALID_ID, GN_OK),
              GN_ERR_NOT_FOUND);
}

/// `conn-events.md` §2a Returns row: NULL host_ctx returns
/// `GN_ERR_NULL_ARG` and changes no state.
TEST(HostApiNotifyDisconnect, NullHostCtxReturnsNullArg) {
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);
    EXPECT_EQ(api.notify_disconnect(nullptr, 1, GN_OK), GN_ERR_NULL_ARG);
}

/// `conn-events.md` §2a Returns row: a non-transport plugin
/// receives `GN_ERR_NOT_IMPLEMENTED` from `notify_disconnect`
/// (host-api.md kind gate).
TEST(HostApiNotifyDisconnect, NonTransportPluginReturnsNotImplemented) {
    Kernel k;
    auto handler_ctx = make_handler_ctx(k);
    auto api = build_host_api(handler_ctx);
    EXPECT_EQ(api.notify_disconnect(&handler_ctx, 1, GN_OK),
              GN_ERR_NOT_IMPLEMENTED);
}

/// `conn-events.md` §2a Concurrency clause: a subscriber callback
/// may invoke `notify_disconnect` against the same `conn`
/// re-entrantly. The re-entrant call observes the record already
/// removed and reports `GN_ERR_NOT_FOUND` without
/// publishing a second DISCONNECTED.
TEST(HostApiNotifyDisconnect, ReentrantFromCallbackReportsUnknown) {
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    EventBag bag;
    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe_conn_state(&ctx, &record_event, &bag, &sub),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xCC};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "tcp://127.0.0.1:9200",
                                  "tcp", GN_TRUST_LOOPBACK,
                                  GN_ROLE_RESPONDER, &conn), GN_OK);

    /// Replace the subscriber sink with a re-entrant variant that
    /// fires `notify_disconnect(conn)` from inside the DISCONNECTED
    /// callback. The same EventBag still records.
    struct Reenter {
        host_api_t*              api;
        PluginContext*           ctx;
        gn_conn_id_t             conn;
        EventBag*                bag;
        std::atomic<gn_result_t> reentrant_rc{GN_ERR_NOT_IMPLEMENTED};
    };
    Reenter re{&api, &ctx, conn, &bag};

    auto reentrant_cb = +[](void* ud, const gn_conn_event_t* ev) {
        auto* r = static_cast<Reenter*>(ud);
        {
            std::lock_guard lk(r->bag->mu);
            r->bag->events.push_back(*ev);
        }
        if (ev->kind == GN_CONN_EVENT_DISCONNECTED) {
            r->reentrant_rc.store(
                r->api->notify_disconnect(r->ctx, r->conn, GN_OK),
                std::memory_order_release);
        }
    };

    ASSERT_EQ(api.unsubscribe_conn_state(&ctx, sub), GN_OK);
    sub = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe_conn_state(&ctx, reentrant_cb, &re, &sub),
              GN_OK);

    EXPECT_EQ(api.notify_disconnect(&ctx, conn, GN_OK), GN_OK);

    EXPECT_EQ(re.reentrant_rc.load(), GN_ERR_NOT_FOUND);

    std::lock_guard lk(bag.mu);
    int disconnected = 0;
    for (const auto& ev : bag.events) {
        if (ev.kind == GN_CONN_EVENT_DISCONNECTED) ++disconnected;
    }
    EXPECT_EQ(disconnected, 1)
        << "re-entrant call publishes nothing; one DISCONNECTED total";
}

/// PluginContext liveness canary covers every `host_api_t` thunk
/// uniformly per `plugin_context.hpp`. A plugin that retained
/// the host_api past its own teardown lands here with a context
/// whose `magic` field reads as `kMagicDead`; every thunk drops
/// the call before dereferencing other fields. Hand-poison the
/// canary on a still-live context and exercise three thunk
/// families — register, send, query — to assert uniform
/// rejection. Restore before harness destruct.
TEST(HostApiCanary, PoisonedContextRejectsThunksAcrossFamilies) {
    Kernel k;
    auto ctx = make_handler_ctx(k);
    auto api = build_host_api(ctx);

    ctx.magic = PluginContext::kMagicDead;

    /// register family — register_handler
    gn_handler_id_t hid = GN_INVALID_ID;
    gn_handler_vtable_t vt{};
    vt.api_size       = sizeof(gn_handler_vtable_t);
    EXPECT_EQ(api.register_handler(&ctx, "gnet-v1", 1, 128, &vt, nullptr, &hid),
              GN_ERR_INVALID_STATE);
    EXPECT_EQ(hid, GN_INVALID_ID);

    /// send family — disconnect. Without the canary this would
    /// reach `connections().find_by_id(1)` and return
    /// `GN_ERR_NOT_FOUND`; the canary fast-fails first.
    EXPECT_EQ(api.disconnect(&ctx, 1), GN_ERR_INVALID_STATE);

    /// query family — get_endpoint
    gn_endpoint_t endpoint{};
    EXPECT_EQ(api.get_endpoint(&ctx, 1, &endpoint), GN_ERR_INVALID_STATE);

    /// timer family — set_timer
    gn_timer_id_t tid = GN_INVALID_TIMER_ID;
    EXPECT_EQ(api.set_timer(&ctx, 1000, [](void*) {}, nullptr, &tid),
              GN_ERR_INVALID_STATE);

    /// extension family — register_extension
    EXPECT_EQ(api.register_extension(&ctx, "gn.test", 0x00010000u, &vt),
              GN_ERR_INVALID_STATE);

    /// shutdown query — poisoned ctx surfaces as
    /// `shutdown_requested = 1` per `host-api.md` §10 so a
    /// stale long-running loop bails instead of running with
    /// freed state.
    EXPECT_EQ(api.is_shutdown_requested(&ctx), 1);

    ctx.magic = PluginContext::kMagicLive;
}
