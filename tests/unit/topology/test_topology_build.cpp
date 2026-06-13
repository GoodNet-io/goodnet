/// @file   tests/unit/topology/test_topology_build.cpp
/// @brief  Topology fingerprint determinism — same plugin set produces
///         identical fingerprint regardless of registration order.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>

#include <core/kernel/kernel.hpp>
#include <core/topology/topology_builder.hpp>
#include <sdk/security.h>
#include <sdk/trust.h>

namespace gn::core::topology {
namespace {

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

} // namespace
} // namespace gn::core::topology
