// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/sdk/test_test_harness.cpp
/// @brief  Coverage for `gn::sdk::test` namespace — shared stub host
///         + fake link extracted in DX Tier 2 (2026-05-12).
///
/// The full migration of per-plugin StubHost copies happens in a
/// separate sweep; this file pins the shared contract so future
/// regressions in the helper surface fail fast.

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>

#include <sdk/cpp/connect.hpp>
#include <sdk/cpp/connection.hpp>
#include <sdk/cpp/link_carrier.hpp>
#include <sdk/cpp/test/fake_link.hpp>
#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

using gn::core::Kernel;
using gn::core::PluginContext;
using gn::core::build_host_api;

namespace {

PluginContext make_ctx(Kernel& k) {
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_LINK;
    ctx.plugin_name   = "test-test-harness";
    ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
    return ctx;
}

}  // namespace

// ─── LinkStub ─────────────────────────────────────────────────────

TEST(SdkTestStubHost, LinkStubRoundtrip) {
    gn::sdk::test::LinkStub h;
    auto api = gn::sdk::test::make_link_host_api(h);
    ASSERT_EQ(api.host_ctx, &h);
    ASSERT_NE(api.notify_connect, nullptr);

    /// Drive each slot once and verify the counters move.
    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xAA};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(api.host_ctx, pk, "uri",
                                   GN_TRUST_LOOPBACK,
                                   GN_ROLE_RESPONDER, &conn), GN_OK);
    EXPECT_EQ(h.connects.load(), 1);
    EXPECT_NE(conn, GN_INVALID_ID);

    const std::uint8_t bytes[3] = {1, 2, 3};
    ASSERT_EQ(api.notify_inbound_bytes(api.host_ctx, conn,
                                         bytes, 3), GN_OK);
    EXPECT_EQ(h.inbound_calls.load(), 1);
    {
        std::lock_guard lk(h.mu);
        ASSERT_EQ(h.inbound.size(), 1u);
        EXPECT_EQ(h.inbound[0].size(), 3u);
        EXPECT_EQ(h.inbound_owners[0], conn);
    }

    ASSERT_EQ(api.kick_handshake(api.host_ctx, conn), GN_OK);
    EXPECT_EQ(h.kicks.load(), 1);

    ASSERT_EQ(api.notify_disconnect(api.host_ctx, conn, GN_OK), GN_OK);
    EXPECT_EQ(h.disconnects.load(), 1);
}

// ─── HandlerStub ──────────────────────────────────────────────────

TEST(SdkTestStubHost, HandlerStubRoundtrip) {
    gn::sdk::test::HandlerStub h;
    h.add_peer(0xAB, /*conn*/ 0x100, "tcp://1.2.3.4:5");
    auto api = gn::sdk::test::make_handler_host_api(h);
    ASSERT_NE(api.send, nullptr);
    ASSERT_NE(api.find_conn_by_pk, nullptr);

    /// find_conn_by_pk for a known peer.
    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xAB};
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.find_conn_by_pk(api.host_ctx, pk, &conn), GN_OK);
    EXPECT_EQ(conn, 0x100u);

    /// unknown peer.
    std::uint8_t unknown[GN_PUBLIC_KEY_BYTES] = {0xFF};
    EXPECT_EQ(api.find_conn_by_pk(api.host_ctx, unknown, &conn),
              GN_ERR_NOT_FOUND);

    /// send recorded.
    const std::uint8_t payload[2] = {0xCA, 0xFE};
    ASSERT_EQ(api.send(api.host_ctx, 0x100, /*msg_id*/ 0x10,
                        payload, 2), GN_OK);
    EXPECT_EQ(h.send_calls.load(), 1);
    {
        std::lock_guard lk(h.mu);
        ASSERT_EQ(h.sent_payloads.size(), 1u);
        EXPECT_EQ(h.sent_msg_ids.front(), 0x10u);
    }

    /// get_endpoint reverse lookup.
    gn_endpoint_t ep{};
    ASSERT_EQ(api.get_endpoint(api.host_ctx, 0x100, &ep), GN_OK);
    EXPECT_EQ(ep.conn_id, 0x100u);
    EXPECT_STREQ(ep.uri, "tcp://1.2.3.4:5");
}

// ─── FakeLink ─────────────────────────────────────────────────────

TEST(SdkTestFakeLink, FullVtableDispatchesAllSlots) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    gn::sdk::test::FakeLink fake;
    auto vt = gn::sdk::test::make_fake_link_vtable(fake);
    ASSERT_EQ(api.register_extension(&ctx, "gn.link.fake-test",
                                       GN_EXT_LINK_VERSION, &vt), GN_OK);

    {
        auto carrier_opt = gn::sdk::LinkCarrier::query(&api, "fake-test");
        ASSERT_TRUE(carrier_opt.has_value());
        if (!carrier_opt) return;
        auto& carrier = *carrier_opt;

        ASSERT_EQ(carrier.listen("fake-test://h:0"), GN_OK);
        EXPECT_EQ(fake.listens.load(), 1);

        gn_conn_id_t id = GN_INVALID_ID;
        ASSERT_EQ(carrier.connect("fake-test://h:1", &id), GN_OK);
        EXPECT_EQ(fake.connects.load(), 1);
        EXPECT_EQ(id, gn::sdk::test::FakeLink::kSynthId);

        const std::uint8_t payload[4] = {1, 2, 3, 4};
        ASSERT_EQ(carrier.send(id,
            std::span<const std::uint8_t>(payload, 4)), GN_OK);
        EXPECT_EQ(fake.sends.load(), 1);
        EXPECT_EQ(fake.last_send_bytes.load(), 4u);

        ASSERT_EQ(carrier.on_data(id,
            [](gn_conn_id_t, std::span<const std::uint8_t>) {}), GN_OK);
        EXPECT_EQ(fake.data_subs.load(), 1);

        ASSERT_EQ(carrier.on_accept(
            [](gn_conn_id_t, std::string_view) {}), GN_OK);
        EXPECT_EQ(fake.accept_subs.load(), 1);
    }
    /// LinkCarrier dtor must have unsubscribed.
    EXPECT_EQ(fake.data_unsubs.load(), 1);
    EXPECT_EQ(fake.accept_unsubs.load(), 1);

    (void)api.unregister_extension(&ctx, "gn.link.fake-test");
}

TEST(SdkTestFakeLink, ConnectToWiresThroughCleanly) {
    /// Confirms the new `gn::sdk::connect_to` scheme dispatcher
    /// works against the shared FakeLink helper — no per-test fake
    /// glue needed.
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    gn::sdk::test::FakeLink fake;
    auto vt = gn::sdk::test::make_fake_link_vtable(fake);
    ASSERT_EQ(api.register_extension(&ctx, "gn.link.fl",
                                       GN_EXT_LINK_VERSION, &vt), GN_OK);

    {
        auto session = gn::sdk::connect_to(&api, "fl://h:1");
        ASSERT_TRUE(session.has_value());
        if (!session) return;  // narrows for clang-tidy optional-access
        EXPECT_TRUE(session->valid());
        EXPECT_EQ(session->id(), gn::sdk::test::FakeLink::kSynthId);
        EXPECT_EQ(fake.connects.load(), 1);
    }
    /// session out of scope → carrier + conn unwind.
    EXPECT_EQ(fake.disconnects.load(), 1);
    (void)api.unregister_extension(&ctx, "gn.link.fl");
}
