/// @file   tests/integration/test_trust_class_metric.cpp
/// @brief  Pin `metrics.drop.trust_class_mismatch` symmetry across
///         the two trust-class gates per `security-trust.md` §4 +
///         §9. The protocol-side gate at `host_api_builder.cpp:1067`
///         already bumped the counter; this test pins the matching
///         security-side bump after `SessionRegistry::create`
///         rejects on the provider's `allowed_trust_mask` —
///         operators watching the counter would otherwise see only
///         half of the trust-mask breaches.

#include <cstring>
#include <memory>

#include <gtest/gtest.h>

#include <core/identity/node_identity.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <plugins/protocols/gnet/protocol.hpp>

#include <sdk/security.h>
#include <sdk/types.h>

namespace {

using gn::core::Kernel;
using gn::core::PluginContext;
using gn::core::build_host_api;
using gn::PublicKey;
using gn::plugins::gnet::GnetProtocol;

/// Loopback / IntraNode-only mask, mirroring null security: an
/// inbound `Untrusted` connection cannot legitimately reach this
/// provider's handshake state.
struct LoopbackOnlyProvider {
    static const char* provider_id(void*) { return "loopback-only-test"; }
    static std::uint32_t mask(void*) {
        return (1u << GN_TRUST_LOOPBACK) | (1u << GN_TRUST_INTRA_NODE);
    }
    static gn_result_t open(void*, gn_conn_id_t, gn_trust_class_t,
                             gn_handshake_role_t,
                             const std::uint8_t*, const std::uint8_t*,
                             const std::uint8_t*, void**) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    static gn_result_t step(void*, void*, const std::uint8_t*, std::size_t,
                             gn_secure_buffer_t*) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    static int complete(void*, void*) { return 0; }
    static gn_result_t export_keys(void*, void*, gn_handshake_keys_t*) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    static gn_result_t encrypt(void*, void*, const std::uint8_t*, std::size_t,
                                gn_secure_buffer_t*) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    static gn_result_t decrypt(void*, void*, const std::uint8_t*, std::size_t,
                                gn_secure_buffer_t*) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    static gn_result_t rekey(void*, void*) { return GN_ERR_NOT_IMPLEMENTED; }
    static void close(void*, void*) {}
    static void destroy(void*) {}
};

gn_security_provider_vtable_t make_loopback_only_vtable() {
    gn_security_provider_vtable_t v{};
    v.api_size              = sizeof(gn_security_provider_vtable_t);
    v.provider_id           = &LoopbackOnlyProvider::provider_id;
    v.handshake_open        = &LoopbackOnlyProvider::open;
    v.handshake_step        = &LoopbackOnlyProvider::step;
    v.handshake_complete    = &LoopbackOnlyProvider::complete;
    v.export_transport_keys = &LoopbackOnlyProvider::export_keys;
    v.encrypt               = &LoopbackOnlyProvider::encrypt;
    v.decrypt               = &LoopbackOnlyProvider::decrypt;
    v.rekey                 = &LoopbackOnlyProvider::rekey;
    v.handshake_close       = &LoopbackOnlyProvider::close;
    v.destroy               = &LoopbackOnlyProvider::destroy;
    v.allowed_trust_mask    = &LoopbackOnlyProvider::mask;
    return v;
}

/// Protocol layer that admits only Loopback / IntraNode, so an
/// inbound `Untrusted` connect hits the protocol-side gate at
/// `notify_connect` before reaching the security stack.
class StrictProtocolLayer : public gn::IProtocolLayer {
public:
    std::string_view protocol_id() const noexcept override { return "strict-v1"; }

    gn::Result<gn::DeframeResult> deframe(
        gn::ConnectionContext&, std::span<const std::uint8_t>) override {
        return gn::DeframeResult{};
    }

    gn::Result<std::vector<std::uint8_t>> frame(
        gn::ConnectionContext&, const gn_message_t&) override {
        return std::vector<std::uint8_t>{};
    }

    std::size_t max_payload_size() const noexcept override { return 0; }

    std::uint32_t allowed_trust_mask() const noexcept override {
        return (1u << GN_TRUST_LOOPBACK) | (1u << GN_TRUST_INTRA_NODE);
    }
};

}  // namespace

TEST(TrustClassMetric, ProtocolGateBumpsCounterOnUntrustedConnect) {
    /// The protocol-side gate at `host_api_builder.cpp:1067` has bumped
    /// `drop.trust_class_mismatch` since Wave 6.1 but never had a
    /// regression — coverage only by diagonal of the security-side
    /// test below. This pins the protocol-side bump directly.
    Kernel kernel;
    kernel.set_protocol_layer(std::make_shared<StrictProtocolLayer>());

    PluginContext ctx;
    ctx.plugin_name = "trust-test";
    ctx.kernel      = &kernel;
    auto api = build_host_api(ctx);

    PublicKey peer_pk; peer_pk.fill(0x01);
    gn_conn_id_t conn = GN_INVALID_ID;
    EXPECT_EQ(api.notify_connect(api.host_ctx,
                                 peer_pk.data(),
                                 "tcp://1.2.3.4:9000",
                                 GN_TRUST_UNTRUSTED,
                                 GN_ROLE_RESPONDER,
                                 &conn),
              GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(conn, GN_INVALID_ID);
    EXPECT_EQ(kernel.metrics().value("drop.trust_class_mismatch"), 1u);
}

TEST(TrustClassMetric, SecurityGateBumpsCounterOnUntrustedConnect) {
    Kernel kernel;
    kernel.set_protocol_layer(std::make_shared<GnetProtocol>());
    /// `notify_connect` skips the security path when no NodeIdentity
    /// is installed (`host_api_builder.cpp:1103`), and the gate then
    /// never fires. Generate a real identity; the provider's
    /// `handshake_open` never runs because the trust-mask gate
    /// rejects first.
    auto ident = gn::core::identity::NodeIdentity::generate(0);
    ASSERT_TRUE(ident.has_value());
    kernel.identities().add(ident->device().public_key());
    kernel.set_node_identity(std::move(*ident));

    PluginContext ctx;
    ctx.plugin_name = "trust-test";
    ctx.kernel      = &kernel;
    auto api = build_host_api(ctx);

    auto vt = make_loopback_only_vtable();
    int self_token = 0;
    ASSERT_EQ(api.register_security(api.host_ctx, "loopback-only-test",
                                     &vt, &self_token),
              GN_OK);

    PublicKey peer_pk; peer_pk.fill(0x02);
    gn_conn_id_t conn = GN_INVALID_ID;
    EXPECT_EQ(api.notify_connect(api.host_ctx,
                                 peer_pk.data(),
                                 "tcp://5.6.7.8:9000",
                                 GN_TRUST_UNTRUSTED,
                                 GN_ROLE_RESPONDER,
                                 &conn),
              GN_ERR_INVALID_ENVELOPE);
    /// Pre-fix this read 0 — the security-side rejection at
    /// `SessionRegistry::create` returned `INVALID_ENVELOPE` without
    /// bumping the operator's drop counter. Post-fix the caller in
    /// `thunk_notify_connect` increments the same counter the
    /// protocol-side gate uses.
    EXPECT_EQ(kernel.metrics().value("drop.trust_class_mismatch"), 1u);
}
