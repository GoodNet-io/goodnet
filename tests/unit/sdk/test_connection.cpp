// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/sdk/test_connection.cpp
/// @brief  Coverage for `sdk/cpp/connection.hpp` (RAII conn handle)
///         and `sdk/cpp/connect.hpp` (scheme-dispatch sugar) — DX
///         Tier 1 sugar landed 2026-05-12.

#include <gtest/gtest.h>

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
#include <sdk/cpp/connection.hpp>
#include <sdk/cpp/link_carrier.hpp>
#include <sdk/extensions/link.h>
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
    ctx.plugin_name   = "test-connection";
    ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
    return ctx;
}

/// Same fake link producer pattern as `test_dsl_helpers.cpp`. Tracks
/// subscribe / unsubscribe / disconnect counters so the test can
/// assert RAII cleanup actually fired.
struct FakeLink {
    std::atomic<int> data_subs{0};
    std::atomic<int> data_unsubs{0};
    std::atomic<int> connects{0};
    std::atomic<int> disconnects{0};
    std::atomic<int> sends{0};
    std::atomic<gn_conn_id_t> last_conn{GN_INVALID_ID};
    std::atomic<std::size_t> last_send_bytes{0};
    /// The fake's only "live" conn id — synthesized in `connect`.
    static constexpr gn_conn_id_t kSynthId = 0xAB;
};

gn_result_t fake_get_stats(void*, gn_link_stats_t*) { return GN_OK; }
gn_result_t fake_get_caps(void*, gn_link_caps_t*)   { return GN_OK; }
gn_result_t fake_send(void* ctx, gn_conn_id_t c,
                      const std::uint8_t*, std::size_t n) {
    auto* f = static_cast<FakeLink*>(ctx);
    f->sends.fetch_add(1);
    f->last_conn.store(c);
    f->last_send_bytes.store(n);
    return GN_OK;
}
gn_result_t fake_send_batch(void*, gn_conn_id_t,
                             const gn_byte_span_t*, std::size_t) {
    return GN_OK;
}
gn_result_t fake_close(void* ctx, gn_conn_id_t, int) {
    static_cast<FakeLink*>(ctx)->disconnects.fetch_add(1);
    return GN_OK;
}
gn_result_t fake_listen(void*, const char*) { return GN_OK; }
gn_result_t fake_connect(void* ctx, const char*, gn_conn_id_t* out) {
    static_cast<FakeLink*>(ctx)->connects.fetch_add(1);
    if (out) *out = FakeLink::kSynthId;
    return GN_OK;
}
gn_result_t fake_subscribe_data(void* ctx, gn_conn_id_t,
                                 gn_link_data_cb_t, void*) {
    static_cast<FakeLink*>(ctx)->data_subs.fetch_add(1);
    return GN_OK;
}
gn_result_t fake_unsubscribe_data(void* ctx, gn_conn_id_t) {
    static_cast<FakeLink*>(ctx)->data_unsubs.fetch_add(1);
    return GN_OK;
}
gn_result_t fake_subscribe_accept(void*, gn_link_accept_cb_t, void*,
                                    gn_subscription_id_t* out) {
    if (out) *out = 1;
    return GN_OK;
}
gn_result_t fake_unsubscribe_accept(void*, gn_subscription_id_t) {
    return GN_OK;
}

gn_link_api_t make_vt(FakeLink& f) {
    gn_link_api_t vt{};
    vt.api_size           = sizeof(vt);
    vt.get_stats          = &fake_get_stats;
    vt.get_capabilities   = &fake_get_caps;
    vt.send               = &fake_send;
    vt.send_batch         = &fake_send_batch;
    vt.close              = &fake_close;
    vt.listen             = &fake_listen;
    vt.connect            = &fake_connect;
    vt.subscribe_data     = &fake_subscribe_data;
    vt.unsubscribe_data   = &fake_unsubscribe_data;
    vt.subscribe_accept   = &fake_subscribe_accept;
    vt.unsubscribe_accept = &fake_unsubscribe_accept;
    vt.ctx                = &f;
    return vt;
}

}  // namespace

// ─── gn::sdk::Connection RAII handle ──────────────────────────────

TEST(SdkConnection, DtorDisconnectsAndUnsubscribes) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    FakeLink fake;
    auto vt = make_vt(fake);
    ASSERT_EQ(api.register_extension(&ctx, "gn.link.fake",
                                       GN_EXT_LINK_VERSION, &vt), GN_OK);

    auto carrier_opt = gn::sdk::LinkCarrier::query(&api, "fake");
    ASSERT_TRUE(carrier_opt.has_value());
    if (!carrier_opt) return;
    auto& carrier = *carrier_opt;

    {
        gn_conn_id_t id = GN_INVALID_ID;
        ASSERT_EQ(carrier.connect("fake://h:1", &id), GN_OK);
        ASSERT_NE(id, GN_INVALID_ID);

        gn::sdk::Connection conn(carrier, id);
        EXPECT_TRUE(conn.valid());
        EXPECT_EQ(conn.id(), FakeLink::kSynthId);

        std::atomic<int> hits{0};
        ASSERT_EQ(conn.on_data(
            [&](std::span<const std::uint8_t>) { hits.fetch_add(1); }),
            GN_OK);
        EXPECT_EQ(fake.data_subs.load(), 1);

        const std::uint8_t payload[3] = {1, 2, 3};
        ASSERT_EQ(conn.send(std::span<const std::uint8_t>(payload, 3)),
                  GN_OK);
        EXPECT_EQ(fake.sends.load(), 1);
        EXPECT_EQ(fake.last_conn.load(), FakeLink::kSynthId);
        EXPECT_EQ(fake.last_send_bytes.load(), 3u);
        EXPECT_EQ(hits.load(), 0);  // no inbound fed
    }

    /// Dtor must have unsubscribed data + closed the conn.
    EXPECT_EQ(fake.data_unsubs.load(), 1);
    EXPECT_EQ(fake.disconnects.load(), 1);

    (void)api.unregister_extension(&ctx, "gn.link.fake");
}

TEST(SdkConnection, MoveTransfersOwnership) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    FakeLink fake;
    auto vt = make_vt(fake);
    ASSERT_EQ(api.register_extension(&ctx, "gn.link.fake",
                                       GN_EXT_LINK_VERSION, &vt), GN_OK);

    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    auto carrier = gn::sdk::LinkCarrier::query(&api, "fake").value();

    gn_conn_id_t id = GN_INVALID_ID;
    ASSERT_EQ(carrier.connect("fake://h:1", &id), GN_OK);

    gn::sdk::Connection a(carrier, id);
    EXPECT_TRUE(a.valid());

    gn::sdk::Connection b(std::move(a));
    EXPECT_FALSE(a.valid());  // NOLINT(bugprone-use-after-move)
    EXPECT_TRUE(b.valid());
    EXPECT_EQ(b.id(), FakeLink::kSynthId);

    /// a's dtor must NOT disconnect (it was moved-from). b's dtor
    /// disconnects once.
    {
        gn::sdk::Connection consumed = std::move(b);
        EXPECT_TRUE(consumed.valid());
    }
    EXPECT_EQ(fake.disconnects.load(), 1);

    (void)api.unregister_extension(&ctx, "gn.link.fake");
}

TEST(SdkConnection, ExplicitCloseIsIdempotent) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    FakeLink fake;
    auto vt = make_vt(fake);
    ASSERT_EQ(api.register_extension(&ctx, "gn.link.fake",
                                       GN_EXT_LINK_VERSION, &vt), GN_OK);

    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    auto carrier = gn::sdk::LinkCarrier::query(&api, "fake").value();
    gn_conn_id_t id = GN_INVALID_ID;
    ASSERT_EQ(carrier.connect("fake://h:1", &id), GN_OK);

    gn::sdk::Connection conn(carrier, id);
    EXPECT_TRUE(conn.valid());

    EXPECT_EQ(conn.close(), GN_OK);
    EXPECT_FALSE(conn.valid());
    EXPECT_EQ(fake.disconnects.load(), 1);

    /// Second close: no-op, no extra disconnect.
    EXPECT_EQ(conn.close(), GN_OK);
    EXPECT_EQ(fake.disconnects.load(), 1);

    /// Send on closed conn: INVALID_STATE.
    EXPECT_EQ(conn.send({}), GN_ERR_INVALID_STATE);

    (void)api.unregister_extension(&ctx, "gn.link.fake");
}

TEST(SdkConnection, ReleaseHandsOffRawId) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    FakeLink fake;
    auto vt = make_vt(fake);
    ASSERT_EQ(api.register_extension(&ctx, "gn.link.fake",
                                       GN_EXT_LINK_VERSION, &vt), GN_OK);

    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    auto carrier = gn::sdk::LinkCarrier::query(&api, "fake").value();
    gn_conn_id_t id = GN_INVALID_ID;
    ASSERT_EQ(carrier.connect("fake://h:1", &id), GN_OK);

    gn::sdk::Connection conn(carrier, id);
    const gn_conn_id_t taken = conn.release();
    EXPECT_EQ(taken, FakeLink::kSynthId);
    EXPECT_FALSE(conn.valid());

    /// release() does NOT disconnect — count stays zero until caller
    /// drives an explicit close on the raw id.
    EXPECT_EQ(fake.disconnects.load(), 0);

    (void)api.unregister_extension(&ctx, "gn.link.fake");
}

// ─── gn::sdk::connect_to / listen_to scheme dispatchers ───────────

TEST(SdkConnectTo, ParsesSchemeAndDispatches) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    FakeLink fake;
    auto vt = make_vt(fake);
    ASSERT_EQ(api.register_extension(&ctx, "gn.link.fake",
                                       GN_EXT_LINK_VERSION, &vt), GN_OK);

    {
        auto session = gn::sdk::connect_to(&api, "fake://host:1");
        ASSERT_TRUE(session.has_value());
        if (!session) return;
        EXPECT_TRUE(session->valid());
        EXPECT_EQ(session->id(), FakeLink::kSynthId);
        EXPECT_EQ(fake.connects.load(), 1);

        const std::uint8_t b[2] = {0xDE, 0xAD};
        ASSERT_EQ(session->send(std::span<const std::uint8_t>(b, 2)), GN_OK);
        EXPECT_EQ(fake.sends.load(), 1);
    }
    /// session out of scope → carrier moves out → conn disconnects.
    EXPECT_EQ(fake.disconnects.load(), 1);

    (void)api.unregister_extension(&ctx, "gn.link.fake");
}

TEST(SdkConnectTo, MissingPluginReturnsNullopt) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    /// `gn.link.fake` not registered — dispatcher must fall through
    /// to nullopt rather than crash on missing extension.
    EXPECT_FALSE(gn::sdk::connect_to(&api, "fake://h:1").has_value());
}

TEST(SdkConnectTo, MalformedUriReturnsNullopt) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);
    EXPECT_FALSE(gn::sdk::connect_to(&api, "no-scheme-here").has_value());
    EXPECT_FALSE(gn::sdk::connect_to(&api, "").has_value());
}

TEST(SdkConnectTo, NullApiReturnsNullopt) {
    EXPECT_FALSE(gn::sdk::connect_to(nullptr, "tcp://h:1").has_value());
}

TEST(SdkConnectTo, ErrVariantSurfacesFailureCodes) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    gn_result_t err = GN_OK;

    /// No plugin → NOT_FOUND.
    EXPECT_FALSE(gn::sdk::connect_to_err(&api, "missing://h:1", &err).has_value());
    EXPECT_EQ(err, GN_ERR_NOT_FOUND);

    /// Malformed → INVALID_ENVELOPE.
    err = GN_OK;
    EXPECT_FALSE(gn::sdk::connect_to_err(&api, "no-scheme", &err).has_value());
    EXPECT_EQ(err, GN_ERR_INVALID_ENVELOPE);

    /// Null api → NULL_ARG.
    err = GN_OK;
    EXPECT_FALSE(gn::sdk::connect_to_err(nullptr, "tcp://h:1", &err).has_value());
    EXPECT_EQ(err, GN_ERR_NULL_ARG);
}

TEST(SdkListenTo, RegistersAndBinds) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    FakeLink fake;
    auto vt = make_vt(fake);
    ASSERT_EQ(api.register_extension(&ctx, "gn.link.fake",
                                       GN_EXT_LINK_VERSION, &vt), GN_OK);

    auto carrier = gn::sdk::listen_to(&api, "fake://0.0.0.0:0");
    ASSERT_TRUE(carrier.has_value());
    if (!carrier) return;
    EXPECT_TRUE(carrier->valid());

    (void)api.unregister_extension(&ctx, "gn.link.fake");
}
