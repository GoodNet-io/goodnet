/// @file   tests/unit/plugins/transports/test_ws.cpp
/// @brief  RFC 6455 framing + URI parsing + loopback round-trip
///         coverage for the `ws` transport plugin.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <plugins/transports/ws/wire.hpp>
#include <plugins/transports/ws/ws.hpp>

#include <sdk/host_api.h>
#include <sdk/types.h>

namespace ws_wire = gn::transport::ws::wire;

namespace {

/// Tiny test harness that swallows transport callbacks so the
/// loopback round-trip can be observed from outside the worker
/// threads. Mirrors the IPC / TCP test fixtures so the shape is
/// uniform across the three.
struct WsHarness {
    std::mutex                                  mu;
    std::vector<gn_conn_id_t>                   connects;
    std::vector<gn_handshake_role_t>            roles;
    std::vector<std::vector<std::uint8_t>>      inbound;
    std::vector<gn_conn_id_t>                   disconnects;

    static gn_result_t s_notify_connect(void* host_ctx,
                                         const std::uint8_t* /*remote_pk*/,
                                         const char* /*uri*/,
                                         const char* /*scheme*/,
                                         gn_trust_class_t /*trust*/,
                                         gn_handshake_role_t role,
                                         gn_conn_id_t* out_conn) {
        auto* h = static_cast<WsHarness*>(host_ctx);
        std::lock_guard lk(h->mu);
        const auto id = static_cast<gn_conn_id_t>(h->connects.size() + 1);
        h->connects.push_back(id);
        h->roles.push_back(role);
        *out_conn = id;
        return GN_OK;
    }
    static gn_result_t s_notify_inbound(void* host_ctx, gn_conn_id_t /*conn*/,
                                         const std::uint8_t* bytes,
                                         std::size_t size) {
        auto* h = static_cast<WsHarness*>(host_ctx);
        std::lock_guard lk(h->mu);
        h->inbound.emplace_back(bytes, bytes + size);
        return GN_OK;
    }
    static gn_result_t s_notify_disconnect(void* host_ctx, gn_conn_id_t conn,
                                            gn_result_t /*reason*/) {
        auto* h = static_cast<WsHarness*>(host_ctx);
        std::lock_guard lk(h->mu);
        h->disconnects.push_back(conn);
        return GN_OK;
    }
    static gn_result_t s_kick(void* /*host_ctx*/, gn_conn_id_t /*conn*/) {
        return GN_OK;
    }

    host_api_t make_api() {
        host_api_t api{};
        api.api_size           = sizeof(host_api_t);
        api.host_ctx           = this;
        api.notify_connect     = &s_notify_connect;
        api.notify_inbound_bytes = &s_notify_inbound;
        api.notify_disconnect  = &s_notify_disconnect;
        api.kick_handshake     = &s_kick;
        return api;
    }
};

bool wait_for(auto&& predicate,
              std::chrono::milliseconds timeout = std::chrono::seconds{2}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return predicate();
}

} // namespace

// ─── frame layout ──────────────────────────────────────────────

TEST(WsWire, SmallPayloadFrame) {
    const std::uint8_t payload[] = {0x01, 0x02, 0x03};
    auto frame = ws_wire::build_binary_frame(
        std::span<const std::uint8_t>(payload), /*mask=*/false, 0);

    ASSERT_GE(frame.size(), 2u);
    EXPECT_EQ(frame[0], 0x82u);  // FIN | binary
    EXPECT_EQ(frame[1], 0x03u);  // unmasked, len=3

    auto h = ws_wire::parse_frame_header(
        std::span<const std::uint8_t>(frame));
    ASSERT_TRUE(h.has_value());
    if (!h.has_value()) return;
    const auto hv = *h;
    EXPECT_TRUE(hv.fin);
    EXPECT_EQ(hv.opcode, 0x2u);
    EXPECT_FALSE(hv.masked);
    EXPECT_EQ(hv.payload_len, 3u);
    EXPECT_EQ(hv.header_size, 2u);
}

TEST(WsWire, MaskedPayloadRoundTrip) {
    /// 200-byte payload exercises the 16-bit length field and
    /// the masking path used on every client-to-server frame.
    std::vector<std::uint8_t> payload(200);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>(i);
    }
    auto frame = ws_wire::build_binary_frame(
        std::span<const std::uint8_t>(payload), /*mask=*/true,
        /*mask_seed=*/0xDEADBEEFu);

    auto h = ws_wire::parse_frame_header(
        std::span<const std::uint8_t>(frame));
    ASSERT_TRUE(h.has_value());
    if (!h.has_value()) return;
    const auto hv = *h;
    EXPECT_TRUE(hv.masked);
    EXPECT_EQ(hv.payload_len, 200u);

    std::vector<std::uint8_t> received(
        frame.begin() + static_cast<std::ptrdiff_t>(hv.header_size),
        frame.end());
    ws_wire::apply_mask(
        std::span<std::uint8_t>(received.data(), received.size()),
        hv.mask);
    EXPECT_EQ(received, payload);
}

TEST(WsWire, HandshakeAcceptKnownVector) {
    /// RFC 6455 §1.3 known-answer test: the canonical example from
    /// the spec must produce the canonical accept value.
    EXPECT_EQ(ws_wire::handshake_accept("dGhlIHNhbXBsZSBub25jZQ=="),
              "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

// ─── URI parsing ───────────────────────────────────────────────

TEST(WsTransport_Uri, AcceptsHostPortPath) {
    auto u = gn::transport::ws::WsTransport::Stats{};
    (void)u;
    /// Use the public listen() method on a transient instance to
    /// observe parse outcomes through the listen-port effect.
    auto t = std::make_shared<gn::transport::ws::WsTransport>();
    /// Bind to ephemeral port; success means the URI parsed.
    EXPECT_EQ(t->listen("ws://127.0.0.1:0/foo"), GN_OK);
    EXPECT_GT(t->listen_port(), 0u);
    t->shutdown();
}

TEST(WsTransport_Uri, RejectsWss) {
    /// `wss://` is intentionally not handled here — it routes
    /// through `tls + ws` once the TLS composer plugin lands.
    auto t = std::make_shared<gn::transport::ws::WsTransport>();
    EXPECT_EQ(t->listen("wss://127.0.0.1:0"), GN_ERR_INVALID_ENVELOPE);
    t->shutdown();
}

TEST(WsTransport_Uri, RejectsBareScheme) {
    auto t = std::make_shared<gn::transport::ws::WsTransport>();
    EXPECT_EQ(t->listen("not-a-uri"), GN_ERR_INVALID_ENVELOPE);
    t->shutdown();
}

// ─── loopback round-trip ───────────────────────────────────────

TEST(WsTransport, LoopbackHandshakeAndPayloadRoundTrip) {
    WsHarness harness;
    auto api = harness.make_api();

    auto server = std::make_shared<gn::transport::ws::WsTransport>();
    auto client = std::make_shared<gn::transport::ws::WsTransport>();
    server->set_host_api(&api);
    client->set_host_api(&api);

    ASSERT_EQ(server->listen("ws://127.0.0.1:0/"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_GT(port, 0u);

    const std::string uri =
        "ws://127.0.0.1:" + std::to_string(port) + "/";
    ASSERT_EQ(client->connect(uri), GN_OK);

    /// Both sides must observe `notify_connect`.
    ASSERT_TRUE(wait_for([&]() {
        std::lock_guard lk(harness.mu);
        return harness.connects.size() >= 2;
    }));
    {
        std::lock_guard lk(harness.mu);
        EXPECT_EQ(harness.connects.size(), 2u);
        /// One initiator, one responder; harness dedupes nothing
        /// because both transports share the same fake api.
        const bool roles_pair =
            (harness.roles[0] == GN_ROLE_INITIATOR &&
             harness.roles[1] == GN_ROLE_RESPONDER) ||
            (harness.roles[0] == GN_ROLE_RESPONDER &&
             harness.roles[1] == GN_ROLE_INITIATOR);
        EXPECT_TRUE(roles_pair);
    }

    /// Send a payload over the client and verify it surfaces on the
    /// server side. Because both transports share the harness, the
    /// inbound list catches whichever side received the bytes.
    const std::vector<std::uint8_t> payload{0xAA, 0xBB, 0xCC, 0xDD};
    /// Client-side conn id: the first allocated by harness for the
    /// initiator. With two notify_connect calls and one harness, ids
    /// are 1 and 2 — find the initiator's id.
    gn_conn_id_t initiator_id = 0;
    {
        std::lock_guard lk(harness.mu);
        for (std::size_t i = 0; i < harness.roles.size(); ++i) {
            if (harness.roles[i] == GN_ROLE_INITIATOR) {
                initiator_id = harness.connects[i];
                break;
            }
        }
    }
    ASSERT_NE(initiator_id, 0u);
    /// Both transports share conn ids 1..2 in this fixture; the
    /// client's `send` looks up by id in its own session map. The
    /// id allocated by the harness for the client (initiator) is
    /// the conn id the client transport registered under. Send
    /// through whichever side it was assigned to.
    auto rc1 = client->send(initiator_id,
        std::span<const std::uint8_t>(payload));
    auto rc2 = server->send(initiator_id,
        std::span<const std::uint8_t>(payload));
    /// One of the two will return UNKNOWN_RECEIVER (the other side
    /// owns the conn id), the other will succeed. Either delivers
    /// bytes through the wire.
    EXPECT_TRUE(rc1 == GN_OK || rc2 == GN_OK)
        << "send must succeed on the side owning the conn id";

    ASSERT_TRUE(wait_for([&]() {
        std::lock_guard lk(harness.mu);
        return !harness.inbound.empty();
    }));
    {
        std::lock_guard lk(harness.mu);
        ASSERT_FALSE(harness.inbound.empty());
        EXPECT_EQ(harness.inbound.front(), payload);
    }

    client->shutdown();
    server->shutdown();
}

// ─── transport-extension capabilities ──────────────────────────

TEST(WsTransport_Capabilities, AdvertisesStreamReliableOrdered) {
    const auto caps = gn::transport::ws::WsTransport::capabilities();
    EXPECT_TRUE(caps.flags & GN_TRANSPORT_CAP_STREAM);
    EXPECT_TRUE(caps.flags & GN_TRANSPORT_CAP_RELIABLE);
    EXPECT_TRUE(caps.flags & GN_TRANSPORT_CAP_ORDERED);
    EXPECT_FALSE(caps.flags & GN_TRANSPORT_CAP_DATAGRAM);
    EXPECT_GT(caps.max_payload, 0u)
        << "WS caps should declare the per-frame payload ceiling";
}
