/// @file   tests/unit/topology/test_topology_build.cpp
/// @brief  Topology fingerprint determinism — same plugin set produces
///         identical fingerprint regardless of registration order.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>

#include <core/kernel/kernel.hpp>
#include <core/topology/topology_builder.hpp>
#include <sdk/security.h>
#include <sdk/trust.h>

namespace gn::core::topology {
namespace {

const gn_security_provider_vtable_t* make_minimal_vtable(
        const char* /*id*/, std::uint32_t mask, std::uint32_t flags) {
    struct V {
        gn_security_provider_vtable_t v;
        std::uint32_t mask;
        std::uint32_t flags;
    };
    auto* s = new V{};
    s->v.api_size = sizeof(gn_security_provider_vtable_t);
    s->mask  = mask;
    s->flags = flags;
    s->v.allowed_trust_mask = [](void* self) -> std::uint32_t {
        return static_cast<V*>(self)->mask;
    };
    s->v.provides_flags = [](void* self) -> std::uint32_t {
        return static_cast<V*>(self)->flags;
    };
    return &s->v;
}

// Register noise + null in one order, get fingerprint.
std::array<std::uint8_t, 32> fingerprint_with(bool noise_first) {
    gn::core::Kernel k;

    const std::uint32_t noise_mask =
        (1u << GN_TRUST_UNTRUSTED) | (1u << GN_TRUST_PEER);
    const std::uint32_t null_mask =
        (1u << GN_TRUST_LOOPBACK) | (1u << GN_TRUST_INTRA_NODE);

    auto* noise_vt = make_minimal_vtable("noise", noise_mask,
                         GN_SEC_PROVIDES_E2E_ENCRYPTION);
    auto* null_vt  = make_minimal_vtable("null",  null_mask, 0);

    if (noise_first) {
        k.security().register_provider("noise", noise_vt, nullptr);
        k.security().register_provider("null",  null_vt,  nullptr);
    } else {
        k.security().register_provider("null",  null_vt,  nullptr);
        k.security().register_provider("noise", noise_vt, nullptr);
    }

    auto snap = build_topology(k);
    std::array<std::uint8_t, 32> fp{};
    std::memcpy(fp.data(), snap->topo.fingerprint, 32);
    return fp;
}

TEST(TopologyFingerprint, Deterministic_SameProviders_SameOrder) {
    auto a = fingerprint_with(true);
    auto b = fingerprint_with(true);
    EXPECT_EQ(a, b);
}

TEST(TopologyFingerprint, Deterministic_SwapRegistrationOrder) {
    // Entries are sorted before hashing — registration order must not matter.
    auto a = fingerprint_with(true);
    auto b = fingerprint_with(false);
    EXPECT_EQ(a, b);
}

TEST(TopologyFingerprint, ChangesWhenProviderAdded) {
    gn::core::Kernel k1, k2;

    const std::uint32_t noise_mask =
        (1u << GN_TRUST_UNTRUSTED) | (1u << GN_TRUST_PEER);
    auto* noise_vt = make_minimal_vtable("noise", noise_mask,
                         GN_SEC_PROVIDES_E2E_ENCRYPTION);
    auto* extra_vt = make_minimal_vtable("extra",
        (1u << GN_TRUST_LOOPBACK), 0);

    k1.security().register_provider("noise", noise_vt, nullptr);

    k2.security().register_provider("noise", noise_vt, nullptr);
    k2.security().register_provider("extra", extra_vt, nullptr);

    auto fp1 = build_topology(k1)->topo.fingerprint;
    auto fp2 = build_topology(k2)->topo.fingerprint;

    EXPECT_NE(std::memcmp(fp1, fp2, 32), 0);
}

} // namespace
} // namespace gn::core::topology
