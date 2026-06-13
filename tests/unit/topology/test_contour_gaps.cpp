/// @file   tests/unit/topology/test_contour_gaps.cpp
/// @brief  Contour-gap computation in `build_topology` — pins the invariant
///         that every external trust class is covered by a provider with
///         E2E encryption (or by a link-layer encrypted path for LINK_ENCRYPTED).

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>

#include <core/kernel/kernel.hpp>
#include <core/topology/topology_builder.hpp>
#include <sdk/extensions/link.h>
#include <sdk/security.h>
#include <sdk/trust.h>

namespace gn::core::topology {
namespace {

// ── vtable helpers ──────────────────────────────────────────────────────────

/// Heap-allocated security provider stub. Returns the stored mask/flags
/// via the vtable's `self` pointer (which IS the struct itself).
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

/// Link vtable + extension state for an encrypted-path link.
struct MockEncLink {
    gn_link_vtable_t v{};
    gn_link_api_t    lapi{};

    MockEncLink() {
        v.api_size = sizeof(gn_link_vtable_t);
        lapi.api_size = sizeof(gn_link_api_t);
        lapi.ctx = this;
        lapi.get_capabilities = [](void* /*ctx*/,
                                    gn_link_caps_t* out) -> gn_result_t {
            out->flags = GN_LINK_CAP_ENCRYPTED_PATH;
            return GN_OK;
        };
        v.extension_vtable = [](void* self) -> const void* {
            return &static_cast<MockEncLink*>(self)->lapi;
        };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

/// Noise covers only external classes (UNTRUSTED, PEER) with E2E.
/// Null covers local classes (LOOPBACK, INTRA_NODE) without E2E.
/// Expected: bits 0,1 = 0 (Noise has E2E); bits 2,3 = set (null, no E2E);
/// bit 4 (ANONYMOUS_LOOPBACK) = set (no provider); bit 5 (LINK_ENCRYPTED) = set.
TEST(ContourGaps, NoiseAndNull) {
    gn::core::Kernel k;

    auto noise = std::make_unique<MockSecProvider>(
        (1u << GN_TRUST_UNTRUSTED) | (1u << GN_TRUST_PEER),
        GN_SEC_PROVIDES_E2E_ENCRYPTION | GN_SEC_PROVIDES_AUTHENTICATION |
        GN_SEC_PROVIDES_FORWARD_SECRECY);

    auto null_p = std::make_unique<MockSecProvider>(
        (1u << GN_TRUST_LOOPBACK) | (1u << GN_TRUST_INTRA_NODE), 0);

    ASSERT_EQ(k.security().register_provider(
        "noise", &noise->vtable, noise.get()), GN_OK);
    ASSERT_EQ(k.security().register_provider(
        "null", &null_p->vtable, null_p.get()), GN_OK);

    auto snap = build_topology(k);
    ASSERT_NE(snap, nullptr);

    // Noise covers external classes with E2E — no gap.
    EXPECT_EQ(snap->topo.contour_gaps & (1u << GN_TRUST_UNTRUSTED), 0u);
    EXPECT_EQ(snap->topo.contour_gaps & (1u << GN_TRUST_PEER),      0u);
    // Null covers local classes without E2E — gap expected.
    EXPECT_NE(snap->topo.contour_gaps & (1u << GN_TRUST_LOOPBACK),    0u);
    EXPECT_NE(snap->topo.contour_gaps & (1u << GN_TRUST_INTRA_NODE),  0u);
    // No provider for LINK_ENCRYPTED → gap.
    EXPECT_NE(snap->topo.contour_gaps & (1u << GN_TRUST_LINK_ENCRYPTED), 0u);
}

/// LINK_ENCRYPTED trust class is covered when both an encrypted link
/// AND a link-only security provider are registered.
TEST(ContourGaps, LinkEncryptedCovered) {
    gn::core::Kernel k;

    auto noise = std::make_unique<MockSecProvider>(
        (1u << GN_TRUST_UNTRUSTED) | (1u << GN_TRUST_PEER),
        GN_SEC_PROVIDES_E2E_ENCRYPTION | GN_SEC_PROVIDES_AUTHENTICATION);

    auto link_only = std::make_unique<MockSecProvider>(
        1u << GN_TRUST_LINK_ENCRYPTED, 0);

    ASSERT_EQ(k.security().register_provider(
        "noise", &noise->vtable, noise.get()), GN_OK);
    ASSERT_EQ(k.security().register_provider(
        "link-only", &link_only->vtable, link_only.get()), GN_OK);

    auto enc_link = std::make_unique<MockEncLink>();
    gn_link_id_t lid{};
    ASSERT_EQ(k.links().register_link(
        "tls", "gnet-v1", &enc_link->v, enc_link.get(), &lid), GN_OK);

    auto snap = build_topology(k);
    ASSERT_NE(snap, nullptr);

    EXPECT_EQ(snap->topo.contour_gaps & (1u << GN_TRUST_LINK_ENCRYPTED), 0u);
}

/// Without an encrypted link, LINK_ENCRYPTED stays a gap even with the provider.
TEST(ContourGaps, LinkEncryptedOpenWithoutEncryptedLink) {
    gn::core::Kernel k;

    auto link_only = std::make_unique<MockSecProvider>(
        1u << GN_TRUST_LINK_ENCRYPTED, 0);

    ASSERT_EQ(k.security().register_provider(
        "link-only", &link_only->vtable, link_only.get()), GN_OK);

    static const gn_link_vtable_t plain_v = []() {
        gn_link_vtable_t x{};
        x.api_size = sizeof(gn_link_vtable_t);
        return x;
    }();
    gn_link_id_t lid{};
    ASSERT_EQ(k.links().register_link(
        "tcp", "gnet-v1", &plain_v, nullptr, &lid), GN_OK);

    auto snap = build_topology(k);
    ASSERT_NE(snap, nullptr);
    EXPECT_NE(snap->topo.contour_gaps & (1u << GN_TRUST_LINK_ENCRYPTED), 0u);
}

} // namespace
} // namespace gn::core::topology
