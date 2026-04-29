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
///   * `notify_disconnect` snapshots the connection record (trust +
///     remote_pk) before erasing it, so the published
///     `DISCONNECTED` event payload reflects the just-departed conn
///     and not a default-zero record.

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

/// Minimal subscriber sink. Mirrors the EventBag pattern from
/// `tests/integration/test_conn_events.cpp`.
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
    ctx.kind          = GN_PLUGIN_KIND_TRANSPORT;
    ctx.plugin_name   = "test-transport";
    ctx.plugin_anchor = std::make_shared<int>(0);
    return ctx;
}

/// Stub protocol layer that admits only Loopback and IntraNode trust
/// classes. Deframe / frame are unreachable in these tests — the trust
/// gate fires inside `thunk_notify_connect` before any wire bytes
/// move — so the stubs return a no-op error if ever invoked.
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

TEST(HostApiNotifyDisconnect, MissingConnReturnsUnknownReceiver) {
    Kernel k;
    auto ctx = make_transport_ctx(k);
    auto api = build_host_api(ctx);

    EventBag bag;
    gn_subscription_id_t sub = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe_conn_state(&ctx, &record_event, &bag, &sub),
              GN_OK);

    /// Disconnect of a never-inserted id propagates the registry's
    /// `GN_ERR_UNKNOWN_RECEIVER`. The thunk still publishes a
    /// `DISCONNECTED` event so subscribers see one terminal signal
    /// per `notify_disconnect` call regardless of whether the
    /// transport's view of the conn matched the registry's.
    constexpr gn_conn_id_t kUnknownConn = 99999;
    EXPECT_EQ(api.notify_disconnect(&ctx, kUnknownConn, GN_OK),
              GN_ERR_UNKNOWN_RECEIVER);

    std::lock_guard lk(bag.mu);
    ASSERT_EQ(bag.events.size(), 1u);
    EXPECT_EQ(bag.events[0].kind, GN_CONN_EVENT_DISCONNECTED);
    EXPECT_EQ(bag.events[0].conn, kUnknownConn);
    EXPECT_EQ(bag.events[0].trust, GN_TRUST_UNTRUSTED)
        << "no record snapshot ⇒ default-zero trust class";
}
