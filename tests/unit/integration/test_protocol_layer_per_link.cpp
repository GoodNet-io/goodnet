/// @file   tests/unit/integration/test_protocol_layer_per_link.cpp
/// @brief  notify_connect stamps each ConnectionRecord with the
///         protocol_id its link declared at registration.
///
/// Pins the per-link protocol-layer selection contract from
/// `protocol-layer.md` §4: when a link plugin registers under a
/// scheme with a `protocol_id` other than the kernel default, every
/// connection on that scheme records the declared id. The dispatch
/// path (`thunk_send`, `thunk_notify_inbound_bytes`, `thunk_inject`)
/// uses the per-conn id to look up the matching layer.

#include <gtest/gtest.h>

#include <cstring>
#include <memory>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/registry/protocol_layer.hpp>
#include <tests/util/protocol_setup.hpp>

#include <plugins/protocols/gnet/protocol.hpp>

#include <sdk/cpp/protocol_layer.hpp>
#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace {

using namespace gn;
using namespace gn::core;
using namespace gn::plugins::gnet;

/// Stub protocol layer used to verify cross-protocol coexistence.
/// Permits all trust classes so notify_connect's mask gate accepts
/// the test's Untrusted connections.
class StubProtocolB final : public ::gn::IProtocolLayer {
public:
    [[nodiscard]] std::string_view protocol_id() const noexcept override {
        return "test-stub-b";
    }

    ::gn::Result<::gn::DeframeResult> deframe(
        ::gn::ConnectionContext&,
        std::span<const std::uint8_t>) override {
        return ::gn::DeframeResult{};
    }

    ::gn::Result<std::vector<std::uint8_t>> frame(
        ::gn::ConnectionContext&,
        const gn_message_t&) override {
        return std::vector<std::uint8_t>{};
    }

    [[nodiscard]] std::size_t max_payload_size() const noexcept override {
        return std::size_t{4} * 1024;
    }
};

}  // namespace

TEST(ProtocolLayerPerLink, NotifyConnectStampsDeclaredProtocolId) {
    Kernel kernel;

    /// Two coexisting protocol layers: kernel default and a stub
    /// alternative. Cross-protocol coexistence is the relax's whole
    /// point.
    gn::test::util::register_default_protocol(
        kernel, std::make_shared<GnetProtocol>());
    gn::test::util::register_default_protocol(
        kernel, std::make_shared<StubProtocolB>());

    /// Two stub link plugins, each declaring its own protocol_id at
    /// register time. notify_connect on each scheme must stamp the
    /// matching id on the new ConnectionRecord.
    gn_link_vtable_t link_vt{};
    link_vt.api_size = sizeof(gn_link_vtable_t);

    gn_link_id_t a_id = GN_INVALID_LINK_ID;
    gn_link_id_t b_id = GN_INVALID_LINK_ID;
    ASSERT_EQ(kernel.links().register_link(
                  "scheme-a", "gnet-v1",
                  &link_vt, nullptr, &a_id),
              GN_OK);
    ASSERT_EQ(kernel.links().register_link(
                  "scheme-b", "test-stub-b",
                  &link_vt, nullptr, &b_id),
              GN_OK);

    PluginContext ctx;
    ctx.plugin_name = "per-link-test";
    ctx.kernel      = &kernel;
    auto api = build_host_api(ctx);

    PublicKey pk_a;
    pk_a.fill(0x11);
    PublicKey pk_b;
    pk_b.fill(0x22);

    gn_conn_id_t conn_a = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(api.host_ctx, pk_a.data(),
                                  "scheme-a://1.2.3.4:1",
                                  GN_TRUST_PEER, GN_ROLE_INITIATOR,
                                  &conn_a),
              GN_OK);
    gn_conn_id_t conn_b = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(api.host_ctx, pk_b.data(),
                                  "scheme-b://5.6.7.8:1",
                                  GN_TRUST_PEER, GN_ROLE_INITIATOR,
                                  &conn_b),
              GN_OK);

    /// Each connection records the layer its link declared.
    auto rec_a = kernel.connections().find_by_id(conn_a);
    auto rec_b = kernel.connections().find_by_id(conn_b);
    ASSERT_NE(rec_a, nullptr);
    ASSERT_NE(rec_b, nullptr);
    if (rec_a && rec_b) {
        EXPECT_EQ(rec_a->protocol_id, "gnet-v1");
        EXPECT_EQ(rec_b->protocol_id, "test-stub-b");
    }
}

TEST(ProtocolLayerPerLink, NotifyConnectFallsBackToKernelDefault) {
    /// Pre-relax test fixtures inserted ConnectionRecord directly with
    /// no protocol_id; the field defaults to `kDefaultProtocolId`. A
    /// link that registers without declaring a protocol_id picks up
    /// the same default at notify_connect time.
    Kernel kernel;
    gn::test::util::register_default_protocol(
        kernel, std::make_shared<GnetProtocol>());

    gn_link_vtable_t link_vt{};
    link_vt.api_size = sizeof(gn_link_vtable_t);
    gn_link_id_t link_id = GN_INVALID_LINK_ID;
    ASSERT_EQ(kernel.links().register_link(
                  "scheme-default", /*protocol_id*/"",
                  &link_vt, nullptr, &link_id),
              GN_OK);

    PluginContext ctx;
    ctx.plugin_name = "default-test";
    ctx.kernel      = &kernel;
    auto api = build_host_api(ctx);

    PublicKey pk;
    pk.fill(0x33);
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(api.host_ctx, pk.data(),
                                  "scheme-default://9.9.9.9:9",
                                  GN_TRUST_PEER, GN_ROLE_INITIATOR,
                                  &conn),
              GN_OK);

    auto rec = kernel.connections().find_by_id(conn);
    ASSERT_NE(rec, nullptr);
    if (rec) {
        EXPECT_EQ(rec->protocol_id, kDefaultProtocolId);
    }
}
