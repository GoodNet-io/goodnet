/// @file   tests/unit/topology/test_topology_build.cpp
/// @brief  Topology fingerprint determinism and named contour array (#33).

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include <core/kernel/kernel.hpp>
#include <core/topology/topology_builder.hpp>
#include <sdk/cpp/protocol_layer.hpp>
#include <sdk/security.h>
#include <sdk/trust.h>

namespace gn::core::topology {
namespace {

struct MockProtocolLayer final : ::gn::IProtocolLayer {
    explicit MockProtocolLayer(std::string_view id) : id_(id) {}
    std::string_view protocol_id()   const noexcept override { return id_; }
    std::size_t      max_payload_size() const noexcept override { return 65536; }
    ::gn::Result<::gn::DeframeResult> deframe(::gn::ConnectionContext&,
        std::span<const std::uint8_t>) override { return ::gn::DeframeResult{}; }
    ::gn::Result<std::vector<std::uint8_t>> frame(::gn::ConnectionContext&,
        const gn_message_t&) override { return std::vector<std::uint8_t>{}; }
private:
    std::string id_;
};

struct MockSecProvider {
    gn_security_provider_vtable_t vtable{};
    std::uint32_t mask  = 0;
    std::uint32_t flags = 0;

    MockSecProvider(std::uint32_t m, std::uint32_t f) : mask(m), flags(f) {
        vtable.api_size = sizeof(gn_security_provider_vtable_t);
        vtable.allowed_trust_mask = [](void* self) -> std::uint32_t {
            return static_cast<MockSecProvider*>(self)->mask;
        };
        vtable.provides_flags = [](void* self) -> std::uint32_t {
            return static_cast<MockSecProvider*>(self)->flags;
        };
    }
};

std::array<std::uint8_t, 32> fingerprint_for(bool noise_first) {
    gn::core::Kernel k;

    const std::uint32_t noise_mask =
        (1u << GN_TRUST_UNTRUSTED) | (1u << GN_TRUST_PEER);
    const std::uint32_t null_mask =
        (1u << GN_TRUST_LOOPBACK) | (1u << GN_TRUST_INTRA_NODE);

    auto noise = std::make_unique<MockSecProvider>(noise_mask,
                     GN_SEC_PROVIDES_E2E_ENCRYPTION);
    auto null_p = std::make_unique<MockSecProvider>(null_mask, 0);

    if (noise_first) {
        k.security().register_provider("noise", &noise->vtable, noise.get());
        k.security().register_provider("null",  &null_p->vtable, null_p.get());
    } else {
        k.security().register_provider("null",  &null_p->vtable, null_p.get());
        k.security().register_provider("noise", &noise->vtable, noise.get());
    }

    auto snap = build_topology(k);
    std::array<std::uint8_t, 32> fp{};
    std::memcpy(fp.data(), snap->topo.fingerprint, 32);
    return fp;
}

TEST(TopologyFingerprint, Deterministic_SameProviders_SameOrder) {
    auto a = fingerprint_for(true);
    auto b = fingerprint_for(true);
    EXPECT_EQ(a, b);
}

TEST(TopologyFingerprint, Deterministic_SwapRegistrationOrder) {
    auto a = fingerprint_for(true);
    auto b = fingerprint_for(false);
    EXPECT_EQ(a, b);
}

TEST(TopologyFingerprint, ChangesWhenProviderAdded) {
    gn::core::Kernel k1, k2;

    const std::uint32_t noise_mask =
        (1u << GN_TRUST_UNTRUSTED) | (1u << GN_TRUST_PEER);

    auto noise1 = std::make_unique<MockSecProvider>(noise_mask,
                      GN_SEC_PROVIDES_E2E_ENCRYPTION);
    auto noise2 = std::make_unique<MockSecProvider>(noise_mask,
                      GN_SEC_PROVIDES_E2E_ENCRYPTION);
    auto extra  = std::make_unique<MockSecProvider>(
                      1u << GN_TRUST_LOOPBACK, 0);

    k1.security().register_provider("noise", &noise1->vtable, noise1.get());

    k2.security().register_provider("noise", &noise2->vtable, noise2.get());
    k2.security().register_provider("extra", &extra->vtable,  extra.get());

    auto snap1 = build_topology(k1);
    auto snap2 = build_topology(k2);

    EXPECT_NE(std::memcmp(snap1->topo.fingerprint,
                           snap2->topo.fingerprint, 32), 0);
}

// ── Named contour array (#33) ─────────────────────────────────────────────

TEST(TopologyContour, EmptyWhenNoProtocols) {
    gn::core::Kernel k;
    const std::uint32_t noise_mask = (1u << GN_TRUST_UNTRUSTED) | (1u << GN_TRUST_PEER);
    auto noise = std::make_unique<MockSecProvider>(noise_mask, GN_SEC_PROVIDES_E2E_ENCRYPTION);
    k.security().register_provider("noise", &noise->vtable, noise.get());

    auto snap = build_topology(k);
    // No protocols registered → inner loop runs 0 times → no contours.
    EXPECT_EQ(snap->topo.contour_count, 0u);
    EXPECT_EQ(snap->topo.contours, nullptr);
}

TEST(TopologyContour, PopulatedForEachTrustClassWithProvider) {
    gn::core::Kernel k;

    const std::uint32_t noise_mask =
        (1u << GN_TRUST_UNTRUSTED) | (1u << GN_TRUST_PEER);
    const std::uint32_t null_mask =
        (1u << GN_TRUST_LOOPBACK) | (1u << GN_TRUST_INTRA_NODE);

    auto noise  = std::make_unique<MockSecProvider>(noise_mask,
        GN_SEC_PROVIDES_E2E_ENCRYPTION | GN_SEC_PROVIDES_AUTHENTICATION |
        GN_SEC_PROVIDES_FORWARD_SECRECY);
    auto null_p = std::make_unique<MockSecProvider>(null_mask, 0u);

    k.security().register_provider("noise", &noise->vtable, noise.get());
    k.security().register_provider("null",  &null_p->vtable, null_p.get());

    protocol_layer_id_t pid{};
    auto proto = std::make_shared<MockProtocolLayer>("test-v1");
    k.protocol_layers().register_layer(proto, &pid);

    auto snap = build_topology(k);
    const auto& topo = snap->topo;

    // Trust classes 0,1 → noise; 2,3 → null; 4,5 → no provider → 4 contours.
    ASSERT_EQ(topo.contour_count, 4u);
    ASSERT_NE(topo.contours, nullptr);

    // Verify per-contour fields.
    const std::uint32_t full_flags =
        GN_SEC_PROVIDES_E2E_ENCRYPTION | GN_SEC_PROVIDES_AUTHENTICATION |
        GN_SEC_PROVIDES_FORWARD_SECRECY;

    for (std::uint32_t i = 0; i < topo.contour_count; ++i) {
        const auto& c = topo.contours[i];
        EXPECT_EQ(std::string_view(c.protocol_id), "test-v1");
        EXPECT_EQ(c.link_scheme, nullptr);   // v1: all links
        EXPECT_EQ(c.handler_count, 0u);
        EXPECT_EQ(c.handler_msg_ids, nullptr);
        EXPECT_EQ(c._pad, 0u);

        if (c.trust == GN_TRUST_UNTRUSTED || c.trust == GN_TRUST_PEER) {
            EXPECT_EQ(std::string_view(c.security_provider_id), "noise");
            EXPECT_EQ(c.security_provides_flags, full_flags);
        } else {
            EXPECT_EQ(std::string_view(c.security_provider_id), "null");
            EXPECT_EQ(c.security_provides_flags, 0u);
        }
    }

    // Trust classes covered: UNTRUSTED, PEER, LOOPBACK, INTRA_NODE.
    bool saw[4] = {};
    for (std::uint32_t i = 0; i < topo.contour_count; ++i) {
        const unsigned t = static_cast<unsigned>(topo.contours[i].trust);
        ASSERT_LT(t, 4u);
        saw[t] = true;
    }
    EXPECT_TRUE(saw[0] && saw[1] && saw[2] && saw[3]);
}

TEST(TopologyContour, HandlerMsgIdsPopulated) {
    gn::core::Kernel k;

    const std::uint32_t mask = (1u << GN_TRUST_PEER);
    auto sec = std::make_unique<MockSecProvider>(mask, GN_SEC_PROVIDES_E2E_ENCRYPTION);
    k.security().register_provider("sec", &sec->vtable, sec.get());

    protocol_layer_id_t pid{};
    auto proto = std::make_shared<MockProtocolLayer>("p1");
    k.protocol_layers().register_layer(proto, &pid);

    // Register a handler for msg_id=0x20 under protocol "p1".
    gn_handler_vtable_t hvt{};
    hvt.api_size = sizeof(gn_handler_vtable_t);
    gn_handler_id_t hid{};
    k.handlers().register_handler("p1", 0x20u, 0u, &hvt, nullptr, &hid);

    auto snap = build_topology(k);
    const auto& topo = snap->topo;

    ASSERT_EQ(topo.contour_count, 1u); // 1 trust class (PEER) × 1 protocol
    ASSERT_NE(topo.contours, nullptr);

    const auto& c = topo.contours[0];
    EXPECT_EQ(c.trust, GN_TRUST_PEER);
    EXPECT_EQ(c.handler_count, 1u);
    ASSERT_NE(c.handler_msg_ids, nullptr);
    EXPECT_EQ(c.handler_msg_ids[0], 0x20u);
}

} // namespace
} // namespace gn::core::topology
