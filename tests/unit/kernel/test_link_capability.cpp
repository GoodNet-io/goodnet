/// @file   tests/unit/kernel/test_link_capability.cpp
/// @brief  Host-side link capability probe + the gn.link.capability
///         extension surface registered by the kernel constructor.

#include <gtest/gtest.h>

#include <core/kernel/kernel.hpp>
#include <core/kernel/link_capability.hpp>

#include <sdk/extensions/link_capability.h>

namespace gn {
namespace {

/// Synthetic probe seam state: the test installs a callable that
/// flips its result on the second call, verifies the cache reflects
/// the first read, and confirms `refresh_host_link_capability`
/// triggers the re-probe path on the next access.
struct ProbeCounter {
    static int  calls;
    static bool first_round_value;
};
int  ProbeCounter::calls            = 0;
bool ProbeCounter::first_round_value = true;

void counting_probe(LinkCapability& out) noexcept {
    /// First call sets every field to true; subsequent calls flip to
    /// false. The test relies on the seam being invoked exactly once
    /// per cache miss so it can pin both states.
    const bool v = (ProbeCounter::calls == 0)
                       ? ProbeCounter::first_round_value
                       : !ProbeCounter::first_round_value;
    ProbeCounter::calls++;
    out.can_bind_udp_v4 = v;
    out.can_bind_udp_v6 = v;
    out.can_bind_tcp_v4 = v;
    out.can_bind_tcp_v6 = v;
}

class LinkCapabilitySeamFixture : public ::testing::Test {
protected:
    void SetUp() override {
        ProbeCounter::calls            = 0;
        ProbeCounter::first_round_value = true;
        set_link_capability_probe_for_testing(&counting_probe);
    }
    void TearDown() override {
        set_link_capability_probe_for_testing(nullptr);
    }
};

TEST_F(LinkCapabilitySeamFixture, LinkCapabilityProbeReturnsConsistentResult) {
    const auto a = host_link_capability();
    const auto b = host_link_capability();

    EXPECT_EQ(a.can_bind_udp_v4, b.can_bind_udp_v4);
    EXPECT_EQ(a.can_bind_udp_v6, b.can_bind_udp_v6);
    EXPECT_EQ(a.can_bind_tcp_v4, b.can_bind_tcp_v4);
    EXPECT_EQ(a.can_bind_tcp_v6, b.can_bind_tcp_v6);
    /// Probe must have run exactly once across the two reads.
    EXPECT_EQ(ProbeCounter::calls, 1);
}

TEST_F(LinkCapabilitySeamFixture, LinkCapabilityRefreshTriggersReprobe) {
    /// First round: seam reports yes/yes/yes/yes.
    const auto first = host_link_capability();
    EXPECT_TRUE(first.can_bind_udp_v4);
    EXPECT_TRUE(first.can_bind_tcp_v4);
    EXPECT_EQ(ProbeCounter::calls, 1);

    /// Force re-probe; the next read should see the flipped values.
    refresh_host_link_capability();
    const auto second = host_link_capability();
    EXPECT_FALSE(second.can_bind_udp_v4);
    EXPECT_FALSE(second.can_bind_tcp_v4);
    EXPECT_EQ(ProbeCounter::calls, 2);
}

TEST(LinkCapabilityRealProbe, RealProbeBindsAtLeastOneFamily) {
    /// No seam: the real probe runs against the test host. CI
    /// environments typically allow at least TCP-v4; assert the
    /// weakest non-trivial invariant so the test stays portable.
    set_link_capability_probe_for_testing(nullptr);
    refresh_host_link_capability();

    const auto& cap = host_link_capability();
    const bool any_bind = cap.can_bind_udp_v4 || cap.can_bind_udp_v6 ||
                          cap.can_bind_tcp_v4 || cap.can_bind_tcp_v6;
    EXPECT_TRUE(any_bind)
        << "the real probe must succeed on at least one of UDP/TCP × v4/v6 "
           "on a sane test host";
}

TEST(LinkCapabilityExtensionSurface,
     ExtensionQueryReturnsCurrentCapability) {
    /// Install a synthetic seam that pins every field to true so the
    /// extension thunk's output is deterministic, then query the
    /// kernel-side extension and verify it returns the same struct.
    set_link_capability_probe_for_testing(&counting_probe);
    ProbeCounter::calls             = 0;
    ProbeCounter::first_round_value = true;
    refresh_host_link_capability();

    core::Kernel k;  // constructor registers gn.link.capability
    const void* raw_vtable = nullptr;
    const auto rc = k.extensions().query_extension_checked(
        GN_EXT_LINK_CAPABILITY, GN_EXT_LINK_CAPABILITY_VERSION,
        &raw_vtable);
    ASSERT_EQ(rc, GN_OK);
    ASSERT_NE(raw_vtable, nullptr);

    const auto* api =
        static_cast<const gn_link_capability_api_t*>(raw_vtable);
    ASSERT_EQ(api->api_size, sizeof(gn_link_capability_api_t));
    ASSERT_NE(api->get, nullptr);

    gn_link_capability_t through_ext{};
    EXPECT_EQ(api->get(api->ctx, &through_ext), 0);

    const auto& direct = host_link_capability();
    EXPECT_EQ(through_ext.can_bind_udp_v4, direct.can_bind_udp_v4);
    EXPECT_EQ(through_ext.can_bind_udp_v6, direct.can_bind_udp_v6);
    EXPECT_EQ(through_ext.can_bind_tcp_v4, direct.can_bind_tcp_v4);
    EXPECT_EQ(through_ext.can_bind_tcp_v6, direct.can_bind_tcp_v6);

    set_link_capability_probe_for_testing(nullptr);
    refresh_host_link_capability();
}

TEST(LinkCapabilityExtensionSurface, NullOutPointerReturnsError) {
    core::Kernel k;
    const void* raw_vtable = nullptr;
    ASSERT_EQ(k.extensions().query_extension_checked(
                  GN_EXT_LINK_CAPABILITY, GN_EXT_LINK_CAPABILITY_VERSION,
                  &raw_vtable),
              GN_OK);
    const auto* api =
        static_cast<const gn_link_capability_api_t*>(raw_vtable);
    EXPECT_EQ(api->get(api->ctx, nullptr), -1);
}

}  // namespace
}  // namespace gn
