/// @file   tests/unit/topology/test_contour_gaps.cpp
/// @brief  Contour-gap computation in `build_topology` — pins the invariant
///         that every external trust class is covered by a provider with
///         E2E encryption (or by a link-layer encrypted path for LINK_ENCRYPTED).

#include <gtest/gtest.h>

#include <cstdint>

#include <core/kernel/kernel.hpp>
#include <core/topology/topology_builder.hpp>
#include <sdk/extensions/link.h>
#include <sdk/security.h>
#include <sdk/trust.h>

namespace gn::core::topology {
namespace {

// ── vtable helpers ──────────────────────────────────────────────────────────

const gn_security_provider_vtable_t* make_sec_vtable(
        std::uint32_t trust_mask,
        std::uint32_t provides) {
    struct V {
        gn_security_provider_vtable_t v;
        std::uint32_t mask;
        std::uint32_t flags;
    };
    // Leak is intentional for test lifetime — tests are short-lived.
    auto* s = new V{};
    s->v.api_size = sizeof(gn_security_provider_vtable_t);
    s->mask  = trust_mask;
    s->flags = provides;
    s->v.allowed_trust_mask = [](void* self) -> std::uint32_t {
        return static_cast<V*>(self)->mask;
    };
    s->v.provides_flags = [](void* self) -> std::uint32_t {
        return static_cast<V*>(self)->flags;
    };
    return &s->v;
}

// Link vtable with ENCRYPTED_PATH caps.
const gn_link_vtable_t* make_link_vtable_encrypted() {
    struct V {
        gn_link_vtable_t v;
        gn_link_api_t    lapi;
    };
    auto* s = new V{};
    s->v.api_size = sizeof(gn_link_vtable_t);
    s->lapi.api_size = sizeof(gn_link_api_t);
    s->lapi.ctx = s;
    s->lapi.get_capabilities = [](void* /*ctx*/,
                                   gn_link_caps_t* out) -> gn_result_t {
        out->flags = GN_LINK_CAP_ENCRYPTED_PATH;
        return GN_OK;
    };
    s->v.extension_vtable = [](void* self) -> const void* {
        return &static_cast<V*>(self)->lapi;
    };
    s->v.ctx = s;
    return &s->v;
}

const gn_link_vtable_t* make_link_vtable_plain() {
    static const gn_link_vtable_t v = []() {
        gn_link_vtable_t x{};
        x.api_size = sizeof(gn_link_vtable_t);
        return x;
    }();
    return &v;
}

// ── tests ───────────────────────────────────────────────────────────────────

/// A Noise-only stack (UNTRUSTED + PEER with E2E) + null (LOOPBACK +
/// INTRA_NODE, no E2E). Expected: bits 0,1 = 0; bits 2,3,4 = set; bit 5 = set.
TEST(ContourGaps, NoiseAndNull) {
    gn::core::Kernel k;

    const std::uint32_t noise_mask =
        (1u << GN_TRUST_UNTRUSTED) | (1u << GN_TRUST_PEER) |
        (1u << GN_TRUST_LOOPBACK) | (1u << GN_TRUST_INTRA_NODE);
    const std::uint32_t noise_provides =
        GN_SEC_PROVIDES_E2E_ENCRYPTION |
        GN_SEC_PROVIDES_AUTHENTICATION |
        GN_SEC_PROVIDES_FORWARD_SECRECY;

    ASSERT_EQ(k.security().register_provider(
        "noise", make_sec_vtable(noise_mask, noise_provides), nullptr), GN_OK);

    const std::uint32_t null_mask =
        (1u << GN_TRUST_LOOPBACK) | (1u << GN_TRUST_INTRA_NODE);
    ASSERT_EQ(k.security().register_provider(
        "null", make_sec_vtable(null_mask, 0), nullptr), GN_OK);

    auto snap = build_topology(k);
    ASSERT_NE(snap, nullptr);

    // Noise covers UNTRUSTED and PEER with E2E — no gap.
    EXPECT_EQ(snap->topo.contour_gaps & (1u << GN_TRUST_UNTRUSTED), 0u);
    EXPECT_EQ(snap->topo.contour_gaps & (1u << GN_TRUST_PEER),      0u);
    // Null covers LOOPBACK and INTRA_NODE but without E2E — gap is expected.
    EXPECT_NE(snap->topo.contour_gaps & (1u << GN_TRUST_LOOPBACK),    0u);
    EXPECT_NE(snap->topo.contour_gaps & (1u << GN_TRUST_INTRA_NODE),  0u);
    // LINK_ENCRYPTED: no encrypted link + no link-only provider → gap.
    EXPECT_NE(snap->topo.contour_gaps & (1u << GN_TRUST_LINK_ENCRYPTED), 0u);
}

/// LINK_ENCRYPTED trust class is covered when both an encrypted link
/// AND a link-only security provider are registered.
TEST(ContourGaps, LinkEncryptedCovered) {
    gn::core::Kernel k;

    // Noise covers external classes.
    const std::uint32_t noise_mask =
        (1u << GN_TRUST_UNTRUSTED) | (1u << GN_TRUST_PEER);
    ASSERT_EQ(k.security().register_provider(
        "noise",
        make_sec_vtable(noise_mask,
                        GN_SEC_PROVIDES_E2E_ENCRYPTION |
                        GN_SEC_PROVIDES_AUTHENTICATION),
        nullptr), GN_OK);

    // link-only provider covers LINK_ENCRYPTED with provides_flags=0.
    ASSERT_EQ(k.security().register_provider(
        "link-only",
        make_sec_vtable(1u << GN_TRUST_LINK_ENCRYPTED, 0),
        nullptr), GN_OK);

    // Register an encrypted-path link.
    gn_link_id_t lid{};
    ASSERT_EQ(k.links().register_link(
        "tls", "gnet-v1", make_link_vtable_encrypted(), nullptr, &lid), GN_OK);

    auto snap = build_topology(k);
    ASSERT_NE(snap, nullptr);

    // LINK_ENCRYPTED should now be covered (link has ENCRYPTED_PATH + provider).
    EXPECT_EQ(snap->topo.contour_gaps & (1u << GN_TRUST_LINK_ENCRYPTED), 0u);
}

/// Without an encrypted link, the LINK_ENCRYPTED class is still a gap
/// even if the link-only provider is registered.
TEST(ContourGaps, LinkEncryptedOpenWithoutEncryptedLink) {
    gn::core::Kernel k;

    ASSERT_EQ(k.security().register_provider(
        "link-only",
        make_sec_vtable(1u << GN_TRUST_LINK_ENCRYPTED, 0),
        nullptr), GN_OK);

    // Plain (non-encrypted) link.
    gn_link_id_t lid{};
    ASSERT_EQ(k.links().register_link(
        "tcp", "gnet-v1", make_link_vtable_plain(), nullptr, &lid), GN_OK);

    auto snap = build_topology(k);
    ASSERT_NE(snap, nullptr);
    EXPECT_NE(snap->topo.contour_gaps & (1u << GN_TRUST_LINK_ENCRYPTED), 0u);
}

} // namespace
} // namespace gn::core::topology
